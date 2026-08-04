# Application Security Review Findings — Vault 1.18.0-beta1

Scope: focused validation of named leads (SSH CA template comma split, MySQL/Cassandra/Influx username SQLi, plus rabbitmq/consul/nomad/ssh OTP/aws, plugin Env, agent exec, http unauth, OIDC provider, MFA PingID, physical backends).

Excluded as already reported: listed CVEs; PG/MSSQL/HANA/Redshift revoke SQLi; MemDB root; ACME SSRF; Azure bound_locations; KVv2 path wipe.

---

## Validated medium+ findings

### 1. SSH CA `allowed_users_template` / `allowed_domains_template` — principal allowlist expansion via comma-bearing identity values

**Severity:** Medium–High (privilege escalation to extra SSH principals / hostnames)  
**Primary location:** `builtin/logical/ssh/path_issue_sign.go` — `renderPrincipal`, `calculateValidPrincipals` (~L153–212)  
**Related:** `sdk/helper/identitytpl/templating.go` (`aclTemplateHandler` returns strings verbatim, no comma escaping); `sdk/framework/identity.go` `PopulateIdentityTemplate`

**Mechanism:** When `allowed_users_template` (or `allowed_domains_template`) is true, Vault renders the role’s template string, then splits the **entire** result on commas (`strutil.ParseStringSlice(rendered, ",")`). Any identity value that contains `,` becomes **additional allowed principals**. Client-supplied `valid_principals` only need to be members of that expanded list.

Confirmed with the same split/membership logic used by the engine: rendered `alice,root` → allowlist `{alice, root}` → request `valid_principals=root` accepted.

**Concrete non-admin attacker paths (input → reachability → impact):**

| Attacker | Controllable input | How it reaches the template | Impact |
|----------|-------------------|-----------------------------|--------|
| JWT/OIDC end user | IdP claim string containing `,` (e.g. profile field / custom claim mapped via `claim_mappings`) | `vault-plugin-auth-jwt` `extractMetadata` → `Alias.Metadata` (`claims.go` L77–89, `path_login.go` `createIdentity`) → `{{identity.entity.aliases.<accessor>.metadata.<key>}}` | Issue user cert for extra principals (e.g. `root`) beyond the single intended account |
| Operator with **only** AppRole `secret-id` create (not SSH/admin) | Secret ID JSON metadata `{"ssh_user":"alice,root"}` | `ParseArbitraryKeyValues` accepts JSON values with commas (`path_role.go` ~L3084) → login copies to `Alias.Metadata` (`path_login.go` L332–376) → same template | Same principal escalation; common when secret-id minting is delegated to CI/self-service |
| Cert-auth client (when alias metadata enabled / CN templated) | Leaf CN containing `,` | `path_login.go` sets `Alias.Name` / metadata `common_name` from peer cert | Extra principals if role templates CN/alias name |

**Not attacker-controlled (for this bug):** default `identity.entity.name` (auto-generated in `sanitizeEntity`); userpass alias names (`GenericNameRegex` disallows commas); entity/custom metadata APIs (identity-admin ACL unless explicitly self-serviced).

**Notes:** Expand-then-split was intentionally introduced in upstream PR #16622 to allow metadata to carry comma-separated principal lists, with an explicit caveat that self-writable identity data can escalate. The gap that remains medium+ is the lack of a “single principal / reject commas in substituted values” mode: common JWT `claim_mappings` and delegated AppRole secret-id metadata are **not** equivalent to trusted identity-admin writes, yet they feed the same unsanitized split.

Same code path applies to **host** certs via `allowed_domains_template`.

**Preconditions:** SSH CA role with templating enabled and `allowed_users`/`allowed_domains` referencing attacker-influenced identity fields; attacker can `sign`/`issue` that role.

---

## Near-misses (do not meet medium+ non-admin E2E bar)

### B) MySQL `DeleteUser` / `QueryHelper` unsanitized username — **drop for non-admin**

**Where:** `plugins/database/mysql/mysql.go` `DeleteUser` (raw `strings.ReplaceAll` for `{{name}}`/`{{username}}`); create/rotate via `dbutil.QueryHelper`.

**Why it fails the bar:**
- **Static-role username** is configured only via `database/static-roles/*` (admin). Per task guidance: static-only → drop.
- **Dynamic username via `DisplayName`:** login `DisplayName` is **not** passed through `displayNameSanitize` (that regex applies only to `auth/token/create`). LDAP (`.+`) / JWT (`user_claim`) can theoretically put `'` into `DisplayName`, and the default template embeds `(.DisplayName \| truncate 10)`. In practice the default template’s short truncate + random/unix suffix makes a reliable multi-statement breakout unrealistic; create tends to fail closed rather than grant DB admin. Custom `username_template: "{{.DisplayName}}"` is admin misconfiguration amplifying a known class (sibling of fixed PG/MSSQL revoke SQLi), not a new non-admin default path.
- Role paths use `GenericNameRegex` (no quotes) for role names; no separate RegisterAuth username sink for MySQL.

### C) Cassandra / InfluxDB — **same drop**

Identical `QueryHelper` interpolation (`plugins/database/cassandra/cassandra.go`, `plugins/database/influxdb/influxdb.go`). Defaults still embed truncated `DisplayName`; static usernames are admin. No cleaner non-admin E2E than MySQL.

### Cert auth OCSP URL SSRF

`sdk/helper/ocsp/client.go` `GetRevocationStatus` GETs `subject.OCSPServer` (or admin `ocsp_servers_override`) with `newInsecureOcspTransport` and no link-local/metadata allowlist. **Attacker does not normally control AIA on a leaf that chains to a Vault-trusted CA** (CA policy sets OCSP URLs). Distinct from excluded ACME SSRF, but without a non-admin way to mint trusted leaves with attacker AIA this stays admin-/CA-compromise adjacent → near-miss.

### MFA Duo/Okta/PingID username templating

Live path uses `identitytpl.PopulateString` on `UsernameFormat` (`vault/login_mfa.go` ~L1660–1681); legacy `formatUsername` is unused. Attacker-controlled alias metadata can retarget the Duo/Okta/PingID username. Duo `preauth` result `"allow"` short-circuits MFA (~L1907–1909), which could matter if a bypass Duo user exists and is targetable—but that is environment-specific and does not yield a generic Vault auth bypass. PingID `IDPURL` is admin config SSRF → out of non-admin bar.

### Plugin catalog `Env` / `Args`

`vault/plugincatalog` + `sdk/helper/pluginutil/run_config.go` largely unconstrained; legacy layering can append `os.Environ()`. Requires plugin-registration privilege (admin) → near-miss / post-admin code exec amplifier only.

### AWS IAM auth Host vs `sts_endpoint`

`buildHttpRequest` sets URL from admin `sts_endpoint` and `Host` from client `iam_request_url` (intentional proxy design). Comment documents admin-controlled endpoint as the SSRF guard. No demonstrated non-admin signature forgery against default STS → near-miss.

### Agent/proxy template exec, rabbitmq/consul/nomad, OIDC provider, physical file

- Agent exec/templating is local agent config trust, not Vault server authz bypass.
- RabbitMQ/Consul/Nomad creds paths: no QueryHelper-style injection; DisplayName goes into token *names*, not SQL.
- OIDC provider tests cover redirect_uri mismatch; no new medium+ issue validated here.
- File physical backend rejects `..` in `validatePath` (`sdk/physical/file/file.go`).

### HTTP unauthenticated endpoints

`/sys/health`, `/sys/seal-status`, optional unauth metrics/pprof — expected; no new medium+ exposure validated beyond existing design.

---

## Summary

| Lead | Verdict |
|------|---------|
| A) SSH CA template comma injection | **Report — Medium/High** with JWT/OIDC claim_mappings and delegated AppRole secret-id metadata as concrete non-admin inputs |
| B) MySQL DeleteUser ReplaceAll | Near-miss — admin static role or weak/default DisplayName path |
| C) Cassandra / Influx | Near-miss — same |
| D) Other named surfaces | No additional medium+ with clear non-admin E2E after tracing |
