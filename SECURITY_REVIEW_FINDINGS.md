# Application security review — HashiCorp Vault 1.18.0-beta1 (`0513545dd`)

Scope: novel medium+ candidates with end-to-end attack paths, excluding the
caller-listed known CVEs (CVE-2025-6000/5999/6037/6004/11621, CVE-2024-7594/8185,
CVE-2025-6013, ACME SSRF, Redshift/HANA SQLi). Thoroughness: medium.

---

## 1. Identity-templated ACL path injection (`/`, `*`, `+`)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Attacker** | Authenticated client who can influence an identity value referenced by a templated policy (alias name, entity/alias metadata, custom_metadata) |
| **Controlled input** | Identity string interpolated into a policy `path` key |
| **Validation** | Validated (code path); later tracked as CVE-2026-5006 for `/` (fixed long after 1.18); `*`/`+` also unrestricted in this tree |

### Reachability

1. Admin publishes a templated ACL, e.g.  
   `path "kv/data/{{identity.entity.aliases.<accessor>.name}}/*" { capabilities = ["read","list"] }`  
   or uses `{{identity.entity.metadata.*}}` / alias `custom_metadata`.
2. Attacker controls the rendered value:
   - **cert auth**: alias name is `clientCert.Subject.CommonName` (`builtin/credential/cert/path_login.go`) — CNs may contain `/` and `*`.
   - **metadata**: values are length-checked only (`metaValueMaxLength`), not charset-restricted (`vault/identity_store_structs.go`, `vault/identity_store_util.go`).
3. At evaluation time, `parsePaths` substitutes the value verbatim (`vault/policy.go`) via `identitytpl.aclTemplateHandler`, which returns strings unchanged (`sdk/helper/identitytpl/templating.go`). There is **no** `deny_slash_in_templated_paths` and no rejection of `*`/`+` in this commit.
4. Rendered path is then interpreted with normal ACL wildcard rules (`*` suffix → prefix match; `+` → segment wildcard) in `vault/acl.go` / `vault/policy.go`.

### Impact

Privilege escalation within Vault: broaden path grants (e.g. name=`*` → `kv/data/*/*`), inject extra path segments via `/`, or match unintended mounts via `+`.

### Notes

Sibling class of OpenBao GHSA-59w7-v8rr-pr4p / HashiCorp HCSEC-2026-32. Present and exploitable on 1.18.0-beta1 whenever templated policies use attacker-influenced identity fields.

---

## 2. SSH secrets engine: comma injection via identity templates

| Field | Value |
| --- | --- |
| **Severity** | High (when templates reference attacker-influenced identity data) |
| **Attacker** | Principal who can request SSH certs on a role with `allowed_users_template` / `allowed_domains_template` / `default_user_template` |
| **Controlled input** | Rendered identity template string (metadata, alias name, etc.) |
| **Validation** | Validated |

### Reachability

1. Role configured with e.g.  
   `allowed_users = "{{identity.entity.metadata.ssh_user}}"`, `allowed_users_template=true`  
   (and typically matching `default_user_template`).
2. `calculateValidPrincipals` in `builtin/logical/ssh/path_issue_sign.go` calls `renderPrincipal` **then** `ParseStringSlice(..., ",")`.
3. If the rendered value is `alice,root` (comma from metadata/alias/claim), both `alice` and `root` become allowed principals.
4. Attacker requests `valid_principals=root`, or omits principals so `default_user` expands to the same multi-principal list.

Same pattern applies to host certs via `allowed_domains_template`.

### Impact

SSH certificate principal privilege escalation (e.g. obtain `root` / additional hostnames) beyond the intended single templated identity.

### Notes

Distinct from CVE-2024-7594 (empty principals). Expand-before-split was intentional (PR #16622) but lacks sanitization of `,` in rendered values. OpenBao later treated this as part of GHSA-59w7.

---

## 3. PKI: identity-templated `allowed_domains` / URI SANs → glob / domain expansion

| Field | Value |
| --- | --- |
| **Severity** | Medium–High (depends on role flags) |
| **Attacker** | Client allowed to issue/sign against a PKI role with domain/URI templating |
| **Controlled input** | Identity template fields used in `allowed_domains` or `allowed_uri_sans` |
| **Validation** | Validated |

### Reachability

1. Role has `allowed_domains_template=true` (and often `allow_glob_domains` and/or `allow_subdomains`) with a template such as `{{identity.entity.metadata.domain}}`.
2. `validateNames` / `ValidateURISAN` in `builtin/logical/pki/issuing/issue_common.go` populate the template, then:
   - with `AllowGlobDomains`, treat `*` in the rendered domain as a glob;
   - with `AllowSubdomains`, a rendered value of `example.com` vs attacker-chosen parent domain changes the effective issuance scope;
   - URI SANs use `glob.Glob(allowed, uri)` after templating.
3. Attacker who can set the templated identity value to `*` (or a broader domain / URI pattern) expands issuance beyond the role author’s intent.

### Impact

Unauthorized certificate issuance for unintended names/URIs (impersonation of other services/hosts).

---

## 4. Vault Agent / Proxy: `cache-clear` (and metrics) ignore `require_request_header`

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Network peer who can reach the Agent/Proxy listener |
| **Controlled input** | HTTP POST to `/agent/v1/cache-clear` or `/proxy/v1/cache-clear` |
| **Validation** | Validated |

### Reachability

1. Agent/Proxy configured with a TCP listener; operator may enable `require_request_header = true` as SSRF/CSRF mitigation for the API proxy.
2. In `command/agent.go` / `command/proxy.go`, `verifyRequestHeader` wraps **only** the `/` proxy handler. Registration of:
   - `consts.AgentPathCacheClear` / `ProxyPathCacheClear`
   - `AgentPathMetrics` / `ProxyPathMetrics`
   - quit (if enabled)  
   is **outside** that wrapper.
3. `LeaseCache.HandleCacheClear` (`command/agentproxyshared/cache/lease_cache.go`) performs no authentication of its own.
4. Attacker POSTs JSON `{ "type": "request_path"|"token"|"lease"|..., ... }` and clears cached leases/static secrets / tokens.

### Impact

Unauthenticated cache wipe (forced re-fetch / DoS against Agent caching; can disrupt clients relying on cached leases). Metrics similarly exposed without the request-header gate. Not direct secret exfiltration by itself; severity rises when combined with `use_auto_auth_token` on an exposed listener (by-design proxying of the auto-auth token on `/`).

---

## 5. Cert auth OCSP: server-side fetch of AIA OCSP URLs (SSRF beyond ACME)

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Client presenting a TLS client certificate during cert-auth login when OCSP is enabled without `ocsp_servers_override` |
| **Controlled input** | OCSP URL in the leaf certificate AIA (`subject.OCSPServer`) |
| **Validation** | Partially validated (fetch path confirmed); AIA control is environment-dependent → treat as **speculative** for many CA deployments |

### Reachability

1. Cert role has `ocsp_enabled=true` and empty `ocsp_servers_override` (`builtin/credential/cert/path_certs.go`, `path_login.go` → `checkForCertInOCSP`).
2. `sdk/helper/ocsp/client.go` `GetRevocationStatus` uses `subject.OCSPServer` and issues HTTP(S) requests via `retryablehttp` with `newInsecureOcspTransport` (no IP/URL allowlist; honors `ProxyFromEnvironment`).
3. Separately, admin-configured CRL URLs use raw `http.Get` in `builtin/credential/cert/backend.go` `fetchCRL` (admin-only SSRF; lower interest).

### Impact

Blind SSRF from the Vault server to attacker-chosen URLs during login (internal HTTP services, link-local metadata, etc.). With `ocsp_fail_open=true`, login can still succeed after the fetch.

### Notes

Practical only if the attacker can obtain a chain-trusted client cert whose AIA OCSP URL they influence (uncommon with public CAs; more plausible with permissive private CAs or unusual issuance pipelines). Distinct from ACME challenge SSRF.

---

## Related (not scored as novel)

| Item | Why omitted from top findings |
| --- | --- |
| Identity **group** policy `"ROOT"` case bypass | Same root-cause class as CVE-2025-5999 (entity). Groups use `RemoveDuplicatesStable(..., true)` which **preserves** original case, then check only exact `"root"` (`vault/identity_store_groups.go`) — material API-surface sibling, same fix pattern. |
| Known listed CVEs | Explicitly out of scope. |
| Cassandra/Influx `QueryHelper` username interpolation | Real sink if custom `username_template` embeds raw `DisplayName`; default templates truncate/sanitize enough that a clean E2E path needs non-default config → weaker than items 1–3. |

---

## Suggested prioritization

1. Templated ACL path injection (finding 1)  
2. SSH template comma principal injection (finding 2)  
3. PKI templated domain/URI expansion (finding 3)  
4. Agent/Proxy unauthenticated cache-clear header bypass (finding 4)  
5. Cert OCSP AIA SSRF (finding 5), where private-CA AIA control exists  
