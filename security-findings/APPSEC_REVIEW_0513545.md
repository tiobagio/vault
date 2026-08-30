# Application Security Review — Vault @ 0513545dd

**Tree:** HashiCorp Vault OSS (`version/VERSION` = `1.18.0-beta1`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-56b2`

Scope: validated medium/high/critical findings with real end-to-end attack paths on surfaces often missed by prior scanners (command injection, path traversal, non-ACME SSRF, authz bypass, template injection, deserialization, plugin/raft/sys auth skips, audit leakage, lease/token races, namespaces).

Excluded (already covered / rejected by prior runs — not re-reported): ACME SSRF; MSSQL/Redshift/HANA/Snowflake/MySQL SQLi; GitHub Name/Slug; Duo MFA IP; UI OIDC redirect; cert/LDAP/AWS/Azure auth issues; ACL/KVv2/LIST bugs; generate-root DoS; recovery-mode timing; OpenLDAP DisplayName LDIF injection; Elasticsearch `path.Join` username traversal; Postgres/InfluxDB static-role quote breakout; known CVEs (e.g. CVE-2026-39946, CVE-2024-7594); SSH CA `allowed_users_template` comma-split principal expansion (validated on this tree by a prior run).

---

## Verdict

**0 validated medium+ findings** with a defendable, non-excluded end-to-end attack path.

---

## Areas scanned

| Focus | Primary locations | Outcome |
|-------|-------------------|---------|
| 1. Command injection (`os/exec`) | Plugin catalog / `sdk/helper/pluginutil`, agent exec, SSH CLI helper, external token helper | No remote API field → argv/shell sink; operator-local or admin-only |
| 2. Path traversal | `sdk/physical/file` (`validatePath` rejects `..`), raft snapshot HTTP streaming, audit `file_path`, plugin directory containment | No untrusted path segment → arbitrary host file R/W |
| 3. SSRF beyond ACME | Cert CRL/OCSP, JWT/OIDC discovery & JWKS, Azure/GCP/Okta/GitHub base URLs, PingID, Keybase PGP fetch, Consul/Nomad/RabbitMQ clients | Outbound URLs are admin mount/config or CA AIA; no low-priv open SSRF |
| 4. Auth bypass / priv-esc | AppRole login/CIDR/num_uses, Okta/RADIUS/userpass, MFA validate queue, identity merge/upsert, unauth `sys/` + DR raft wrappers | No new non-admin authz bypass; DR raft unauth paths CE-gated / DR-token wrapped on Ent |
| 5. Template injection | `sdk/helper/template` FuncMap, LDAP filters, ACL identity templating (`parsePaths` templates path key only after HCL parse), SSH extensions | No RCE FuncMap; ACL path templating cannot inject new HCL blocks; wildcard/path-broadening requires dangerous admin policy design |
| 6. Deserialization | JSON/mapstructure into typed structs; plugin gRPC | No gadget / type-confusion chain |
| 7. Plugin / raft / sys auth skips | `PathsSpecial.Unauthenticated`, raft remove-peer/bootstrap, wrapping lookup, UI mounts/messages | Intentional unauth surfaces; mutating raft ops ACL- or DR-token gated; UI authenticated-messages still requires a valid token in-handler |
| 8. Secrets leakage (audit/logging) | Audit HMAC pipeline, `log_raw` lineage, credential engines | No new raw-secret leak to untrusted readers on this tree beyond known fixed classes |
| 9. Token/lease races | AppRole secret_id use-count vs CIDR order, MFA cache pop/push, lease quotas on MFA token mint | Wrong-IP CIDR-after-consume burns uses (availability), not privilege gain |
| 10. Cross-tenant / namespaces | CE namespace stubs, identity namespace checks on MFA validate | No CE multi-namespace tenancy surface for cross-tenant escalation |
| External DB/secrets plugins | Redis ACL argv, Snowflake QueryHelper, OpenLDAP LDIF templates, ES client paths, AD | Redis uses separate protocol args; other issues match excluded SQLi/traversal/LDIF classes |

---

## Near-misses (below reporting bar)

1. **`.well-known` redirect `url.ResolveReference` path join** (`vault/well_known_redirect.go` `Destination`) — `../` in remaining path can escape the registered mount prefix when resolving. No OSS builtin registers redirects via `RequestWellKnownRedirect`; rewritten request remains ACL-enforced. No standalone medium+ path without a registering plugin.

2. **AppRole CIDR check after consuming `secret_id` use** (`builtin/credential/approle/path_login.go`) — for finite `SecretIDNumUses`, storage decrement/delete happens before CIDR validation. Wrong-source IP can burn uses (DoS of a secret ID), not login as that role from an unauthorized network.

3. **ACL identity path templating + attacker-influenced JWT/AppRole metadata** — values substituted into path strings without escaping; can broaden access only if operators already grant templated paths over untrusted claim/metadata fields (documented footgun, not a novel code sink).

4. **Admin-configured egress / connection strings** (CRL URLs, OIDC discovery, DB `connection_url`, plugin `Env`/`Args`) — privileged configuration trust model; does not escalate a lower-priv caller.

---

## Methodology

Static end-to-end tracing with Grep/Read across `builtin/`, `vault/`, `http/`, `plugins/database/`, `sdk/`, and downloaded modules for JWT, K8s, Azure, Redis, Elasticsearch, OpenLDAP, Snowflake, AD, GCP. Cross-checked sinks against the exclusion list and prior review artifacts on sibling branches for this commit.

---

## Conclusion

No new medium+ vulnerability with attacker identity → controlled input → reachable sink → concrete impact was validated beyond issues already covered or rejected by prior runs on this tree.
