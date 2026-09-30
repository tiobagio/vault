# Vault OSS Application Security Review — Deep Dive

**Target:** HashiCorp Vault OSS @ `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-dae7`  
**Scope:** Higher-yield areas requested after prior broad scan (no medium+ remote vulns found).

## Verdict

**No medium+ remote vulnerability validated.**

Strongest candidate is **ACME http-01 blind SSRF with connection-error leakage**. It is real behavior, code-traced and unit-validated, but fails the medium+ bar for a remote finding (see below).

Evidence test: `builtin/logical/pki/acme_ssrf_validation_test.go` (`TestAcmeHTTP01_SSRF_Characteristics`) — PASS.

---

## 1. ACME http-01 SSRF (strongest candidate — fails medium+ bar)

### Attack path (code-traced)

1. **Enable gate (authenticated):** `config/acme` write (`pathAcmeWrite` in `builtin/logical/pki/path_config_acme.go`). ACME defaults to `Enabled: false`.
2. **EAB footgun:** `defaultAcmeConfig.EabPolicyName = "not-required"`, while the field schema Default claims `"always-required"`. Writes use `GetOk("eab_policy")`, so enabling with only `enabled=true` persists **EAB not required**.
3. **Unauthenticated ACME API** (when enabled): `new-account`, `new-order`, `challenge/...` are unauthenticated paths (`backend_test.go` marks them `shouldBeUnauthedWriteOnly`).
4. **Identifier control:** With default `default_directory_policy=sign-verbatim`, role is `SignVerbatimRole()` → `AllowAnyName=true`, `AllowIPSANs=true` (`issuing/roles.go`). Orders may use DNS or IP identifiers (`parseOrderIdentifiers`).
5. **Fetch:** `ValidateHTTP01Challenge` builds `http://{identifier}/.well-known/acme-challenge/{token}` and `client.Get`s it (`acme_challenges.go:125-202`):
   - Follows up to **10 redirects** with **no private/link-local IP blocking**
   - `TLSClientConfig: InsecureSkipVerify: true` (redirects may upgrade to HTTPS)
   - Does **not** check HTTP status before reading body
6. **Error to client:** Failures wrap into `ErrIncorrectResponse`; `TranslateErrorToErrorResponse` sets `Detail = given.Error()`; stored via `challenge.Error` and returned by `NetworkMarshal` (`acme_errors.go:180-211`, `acme_authorizations.go:127-128`).

### Validated (unit tests)

| Property | Result |
|---|---|
| Redirect to different host followed | Yes (hits internal httptest) |
| IP literal (`127.0.0.1:port`) dialed | Yes |
| Connection errors include addr + dial detail in error string | Yes |
| Those details survive `TranslateErrorToErrorResponse` / `MarshalForStorage` | Yes |
| Response **body** reflected in errors | **No** |
| HTTP **status** reflected in errors | **No** (non-2xx with correct body still validates) |

### Why this fails the medium+ bar

- ACME is **off by default**; enable requires an authenticated policy write to `pki/config/acme`.
- Outbound fetches to client-chosen identifiers are **inherent to ACME http-01**.
- No response-body or status reflection → impact is blind SSRF / reachability & coarse connection-error recon, not secret exfiltration (e.g. IMDS body).
- Residual risk after deliberate enable + missing EAB is a **hardening gap** (block RFC1918/link-local/metadata; redact fetch errors; apply schema EAB default on write), not a validated Medium+ remote vuln against a default/hardened install.

TLS-ALPN and DNS-01: same identifier trust model; ALPN dials `{domain}:443` with custom dialer; DNS-01 does TXT lookups only — no HTTP body SSRF channel.

---

## 2. AWS auth (`builtin/credential/aws`)

- Login STS call uses **admin-configured** `sts_endpoint` (default `https://sts.amazonaws.com`), not client URL as dial target (`path_login.go:297-341`, `submitCallerIdentityRequest` comment at 1770-1773).
- Client `iam_request_url` supplies path/query/Host for SigV4; TCP target remains configured endpoint (`buildHttpRequest`).
- Redirects disabled (`ErrUseLastResponse`); response must be `text/xml`.
- `validateLoginIamRequestBody` restricts body to `Action=GetCallerIdentity` (+ Version).
- **No low-priv SSRF validated.** Admin-misconfigured `sts_endpoint` is an operator concern, not remote attacker SSRF.

---

## 3. JWT/OIDC auth

- **Not present in OSS builtins** (`builtin/credential/` has approle, aws, cert, github, ldap, okta, radius, token, userpass only).
- OSS identity OIDC (`vault/identity_store_oidc*.go`) is Vault-as-IdP (issues JWKS), not login that fetches remote issuer/JWKS.
- **N/A for OSS remote JWT issuer/JWKS SSRF / alg confusion on login.**

---

## 4. Cert auth (`path_login.go`)

- Login uses **TLS peer certificates** only (`ConnState.PeerCertificates`), not attacker-supplied PEM in the login body.
- Non-CA trusted leaves require serial + AKID + **public key** match (rejects forged leaf with same serial).
- Chain path: `validateConnState` → intersect trusted entries → `matchesConstraints`; first successful match wins (documented backwards-compat).
- **No forged-PEM / partial-chain role confusion validated** without admin trust misconfiguration.

---

## 5. Identity merge / alias

- Explicit `entity/merge` is an identity API requiring appropriate ACL (not unauthenticated).
- Upsert auto-merge when alias factors collide (`identity_store_util.go:593-606`) merges into the entity being upserted; alias name+mountAccessor come from auth backends, not free attacker choice across victims.
- **No alias-takeover privilege escalation validated.**

---

## 6. Policy ACL glob / namespace escape

- ACL matching is radix / segment-wildcard based (`vault/acl.go`); OSS has no namespaces beyond root.
- No `../` path-escape bypass validated in this pass; request paths are mount-routed rather than `filepath.Clean`-confused into other mounts in the reviewed paths.

---

## 7. UI custom messages XSS

- Enterprise UI feature; messages rendered with Ember `{{msg}}` / `{{bannerMessage.title}}` (**auto-escaped**), not triple-stash / unsanitized HTML (`ui/app/templates/vault/cluster.hbs`).
- Links use `@href={{href}}` from admin-configured message links (admin-planted `javascript:` would be admin XSS / social engineering, requires privileged message write).
- **No stored XSS for non-admin attackers validated.**

---

## 8. Plugin catalog

- `plugins/catalog/*` is in **RootOnly / sudo** special paths (`logical_system.go`).
- `handlePluginCatalogUpdate` **requires** SHA-256 (`missing SHA-256 value` if absent) and verifies plugin stays under configured plugin directory / symlink constraints (`plugincatalog.Set`).
- **Non-root register without checksum: not possible** via this API as coded.

---

## 9. sys/raw, pprof, monitor, metrics

| Endpoint | Gate |
|---|---|
| `sys/raw` | Only registered if `core.rawEnabled` (listener/config); then normal ACL |
| `sys/pprof` | Auth via logical handler **unless** `UnauthenticatedPProfAccess` |
| `sys/metrics` | Auth unless `UnauthenticatedMetricsAccess` |
| `sys/monitor` | Logical path (authenticated); streams logs at requested level |

Default installs keep pprof/metrics authenticated. **No auth-bypass validated.**

---

## 10. SSH secrets engine

- OTP: UUID stored/verified; no shell execution in Vault.
- CA signing: principals/extensions filtered by role `allowed_users` / `allowed_extensions` / critical options (`path_issue_sign.go`). Empty `allowed_extensions` fails closed (tested).
- **No command/principal injection validated** beyond role misconfiguration (`allowed_users=*` / `allowed_extensions=*`).

---

## Hardening notes (not scored as medium+)

1. ACME: on enable, default `eab_policy` to `always-required` (match schema); refuse IP identifiers or block private/link-local/metadata destinations; stop following redirects to non-public IPs; redact dial errors in `challenge.error.detail`.
2. Prefer `VAULT_DISABLE_PUBLIC_ACME=true` in private networks.
