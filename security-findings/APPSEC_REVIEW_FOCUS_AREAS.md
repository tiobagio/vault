# Application Security Review — Focus Areas

**Tree:** `0513545dd` / `version/VERSION` = `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-f63c`  
**Method:** Static code tracing (auth plugins via Go module cache, core MFA/identity/sys/UI). No exploit PoC execution.

**Excluded (not re-reported):** CVE-2025-6000/5999/6037/11621/6013–6015/6004/6011/9180/3879/4166/4656/6203; CVE-2024-7594/8185; CVE-2026-3605/5052/4525/5807; GitHub Name/Slug policy confusion; Okta/RADIUS non-canonical alias MFA bypass; AWS `iam_alias=full_arn` MFA bypass; MSSQL/PostgreSQL SQLi; HANA/Redshift SQLi; userpass/LDAP lockout case bypass (CVE-2025-6004); cert auth renewal sibling binding (CVE-2026-39388).

---

## Verdict

**No new validated Medium+ vulnerabilities** with a defendable end-to-end attack path were identified in the under-covered focus areas.

Prior reviews already covered several high-signal bugs still present on this tree (Redshift/HANA revoke SQLi, ACME SSRF / CVE-2026-5052). Those remain excluded per scope.

---

## Areas reviewed (summary)

| Focus | Primary locations | Outcome |
|-------|-------------------|---------|
| 1. MFA enforcement gaps | `vault/login_mfa.go`, `vault/request_handling.go` (`CREATE_TOKEN` MFA branch), Okta/Duo/Ping/TOTP validators | No skip of login MFA via alternate core path; delegated auth refuses MFA tokens |
| 2. JWT/OIDC | `vault-plugin-auth-jwt@v0.20.3` `path_login.go` / `path_oidc.go` / `claims.go` | Algs default to asymmetric set; aud/bound claims enforced; azp handled in OIDC provider lib |
| 3. Kubernetes auth | `vault-plugin-auth-kubernetes@v0.19.0` `path_login.go` | Unsigned local parse only when no public keys; TokenReview still required |
| 4. GCP/Azure/OCI/AliCloud | respective `path_login.go` modules | No new spoof beyond excluded AWS MFA alias class |
| 5. Identity group inheritance | `vault/identity_store_util.go` `collectPoliciesReverseDFS` | Cycle detection present; policy walk looks consistent |
| 6. Plugin multiplex / gRPC | `sdk/plugin/*` | JSON maps only; no unsafe gadget chain found |
| 7. Templates | `sdk/helper/template`, SSH `renderPrincipal`, DB `QueryHelper` | See near-misses |
| 8. Unauthenticated `sys/` | `vault/logical_system.go` `PathsSpecial.Unauthenticated` | Mutating raft paths on DR secondary gated by DR operation token |
| 9. Raft/storage | `physical/raft`, `vault/logical_system_raft.go` | No new path-traversal/SSRF beyond prior ACME/known |
| 10. UI XSS | `ui/.../log-error-with-html.hbs` | Triple-stache used; content mostly self-generated control-group text |

---

## Near-misses (below Medium+ bar)

### MFA

- **Duo preauth `allow`:** `validateDuo` returns success when Duo Preauth result is `allow` (trusted-network bypass). Intended Duo behavior, not a Vault logic bug.
- **Two-phase validate RemoteAddr:** `handleMFALoginValidate` passes the *validate* request’s `RemoteAddr` into Duo (not `cachedResponseAuth.RequestConnRemoteAddr`). IP-policy skew only matters with trusted `X-Forwarded-For`; default listener does not trust arbitrary XFF.
- **TOTP `usedCodes` in-memory:** replay window is per-process; MFA validate is `ForwardPerformanceStandby`. Insufficient evidence of cross-node bypass on this OSS tree.
- **Entity merge copies `MFASecrets` metadata** (`mergeEntity`) without migrating barrier keys under `sys/mfa/totpkeys/{method}/{entity}`. Likely breaks TOTP after merge (fail-closed), not a bypass.
- **Delegated auth + MFA:** correctly rejects MFARequirement without client token (`request_handling.go`).

### JWT / K8s / cloud auth

- **OIDC `formpostHTML`:** interpolates `path`/`state` into JS `postMessage` without HTML/JS escaping (`cli_responses.go`). State is server-generated; mount comes from allowed redirect URI. Needs admin-allowed malicious redirect shape → Low / config.
- **K8s `DontVerifySignature`:** local JWT crypto skipped when `kubernetes_ca_cert`/keys unset; TokenReview remains mandatory.
- **Azure `bound_service_principal_ids=["*"]` without resource bounds:** any token for the configured app can login. Explicit admin glob, not an authz bypass.
- **GCP default `gce_alias=role_id`:** all VMs on a role share one entity (MFA/TOTP shared). Documented footgun.

### Templates / DB engines

- **Cassandra / InfluxDB `QueryHelper` string substitution** into quoted CQL/IFQL (`plugins/database/cassandra/cassandra.go`, `influxdb/influxdb.go`). Same *class* as excluded Redshift/HANA issues, but with the **default** username template the metacharacter sits mid-name (before `random`/`unix_time`), so default CREATE/DROP tend to **fail closed** rather than yield a clean injectable statement. Custom `username_template` or asymmetric quoting could elevate this; not defended here as Medium+ without that config.
- **MySQL revoke** also string-replaces `{{username}}` then `Exec` (`mysql.go` `DeleteUser`). Same caveats.

### sys / UI / well-known

- **`/.well-known/` `ResolveReference` traversal** (`vault/well_known_redirect.go` `Destination`): can rewrite outside mount prefix to another `/v1/...` path; rewritten request still uses normal ACL/auth. No unauthenticated mutate/leak demonstrated.
- **UI `{{{@content}}}`** in control-group console errors: `creation_path` / token / accessor rendered unescaped. Practical token theft needs another user to render attacker-controlled path text (self-XSS / weak social path) → below bar.
- **Unauthenticated `sys/storage/raft/*` on DR secondary:** listed unauthenticated but callbacks wrap `verifyDROperationTokenOnSecondary`.

---

## Bottom line

Preferring zero over speculative: **no new Medium+ finding** with attacker → controlled input → reachability → impact that is clearly outside the exclusion list and fully supportable from this tree alone.
