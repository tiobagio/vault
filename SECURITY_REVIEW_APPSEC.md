# Application Security Review — HashiCorp Vault (~1.18.0-beta1)

**Repository:** tiobagio/vault  
**Branch:** `cursor/application-security-review-23b7`  
**Scope:** MEDIUM+ vulnerabilities with real end-to-end attack paths in: SQL injection (database secrets engines), command injection, path traversal, SSRF/unsafe fetches (beyond ACME), template injection → secret disclosure/RCE, unsafe deserialization, webhook/callback URL abuse.

## Verdict

**No validated MEDIUM+ findings** with a complete, non-excluded end-to-end attack path were confirmed in this review.

---

## Dismissed candidates

### 1. PostgreSQL `defaultDeleteUser` unquoted schema (EXCLUDED — CVE-2026-39946)

- **Location:** `plugins/database/postgresql/postgresql.go`
- **Evidence:** Schema from `information_schema.role_column_grants` is interpolated without `QuoteIdentifier` in the first REVOKE statement (`(schema)`), while a subsequent statement correctly quotes it.
- **Dismissal:** Explicitly excluded as PostgreSQL schema CVE-2026-39946.

### 2. MSSQL `revokeUserDefault` / `dropUserSQL` string concatenation (EXCLUDED — already covered)

- **Location:** `plugins/database/mssql/mssql.go`
- **Evidence:** `dropUserSQL` embeds username via `N'%s'` and `[%s]` without `QuoteName` parameterization (unlike contained-DB / login-drop paths that use `QuoteName(@username)`).
- **Dismissal:** Explicitly excluded as MSSQL DeleteUser SQLi if already covered.

### 3. Redshift `terminateloop('%s')` / HANA unquoted identifiers (EXCLUDED — prior FP)

- **Locations:** `plugins/database/redshift/redshift.go`, `plugins/database/hana/hana.go`
- **Evidence:** Redshift calls `terminateloop` with a single-quoted username; HANA default revoke uses `fmt.Sprintf` with bare `req.Username` as an identifier.
- **Dismissal:** Explicitly excluded as Redshift/HANA template-constrained false positives from prior reviews. Dynamic usernames under default templates are constrained (`random`/base62, truncates); realistic DisplayName characters that survive auth sanitization/constraints do not yield a clean, high-impact exploit chain beyond the known FP class.

### 4. MySQL / Cassandra / InfluxDB default statements — quote interpolation

- **Locations:** `plugins/database/mysql/mysql.go`, `plugins/database/cassandra/cassandra.go`, `plugins/database/influxdb/influxdb.go`
- **Pattern:** Default creation/rotation/revocation SQL/CQL/IFQL embeds `{{username}}` / `{{password}}` inside quotes without SQL escaping (`QueryHelper` / string replace only).
- **Attacker / input considered:**
  - Dynamic path: `req.DisplayName` from auth → username template.
  - Static path: admin-configured static role username.
  - Password path: password policy charset including `'`.
- **Why not MEDIUM+ validated:**
  - Token `display_name` is sanitized to `[a-zA-Z0-9-]` (`vault/token_store.go`).
  - userpass usernames match `GenericNameRegex` (`\w` / `-.` only).
  - Default DB username templates heavily truncate and mix in `random` (base62); apostrophe-bearing real LDAP/Okta usernames typically produce syntax errors, not controlled multi-statement execution.
  - Static usernames / custom `username_template` / permissive password policies require privileges equivalent to configuring the DB engine (trusted operator), not a lower-privilege caller escalating via an untrusted field alone.
- **Dismissal:** No validated low-privilege E2E path to reliable SQLi/CQLi.

### 5. Cert auth CRL `http.Get` / OCSP fetches (SSRF)

- **Locations:** `builtin/credential/cert/backend.go` (`fetchCRL`), `sdk/helper/ocsp/client.go`
- **Evidence:** CRL distribution URLs configured on the cert auth mount are fetched with `http.Get` without SSRF allowlisting. OCSP uses cert AIA or admin `ocsp_servers_override`.
- **Dismissal:** CRL URL and `ocsp_servers_override` are privileged mount configuration (same trust class as other admin-configured egress). Client-controlled OCSP AIA only applies after chain trust to Vault-configured CAs (CA-controlled URLs). Distinct from excluded ACME SSRF, but lacks a non-privileged attacker-controlled URL → impact chain meeting MEDIUM+ bar.

### 6. Admin-configured network endpoints (GitHub `base_url`, AWS `sts_endpoint` / `iam_endpoint`, Consul/Nomad/RabbitMQ addresses)

- **Dismissal:** Privileged configuration of intentional outbound integrations; not untrusted-user SSRF. No webhook/callback abuse path beyond this admin model was found.

### 7. LDAP `EscapeLDAPValue` used inside a search filter

- **Location:** `sdk/helper/ldaputil/client.go` (`GetUserDN` UPNDomain branch)
- **Evidence:** Filter built with `EscapeLDAPValue(username)` rather than `ldap.EscapeFilter`; filter metacharacters `* ( )` are not DN-escaped.
- **Dismissal:** Reached after authentication when `UPNDomain` is set. Exploiting filter injection requires binding as a username containing filter metacharacters—not a practical E2E MEDIUM+ path in typical directories. UserFilter/GroupFilter template paths correctly use `EscapeFilter`.

### 8. Command injection / shell execution

- Reviewed `os/exec` usage (plugin catalog, agent exec, SSH CLI helper, external token helper).
- Plugin catalog rejects `..` in name/command and validates resolved path stays under plugin directory.
- Agent/exec and SSH CLI take operator-local config/args, not remote Vault API fields into a shell.
- External token helper runs BinaryPath via `/bin/sh -c` but BinaryPath is local CLI helper config.
- **Dismissal:** No server-side command injection with attacker-controlled API input.

### 9. Path traversal (audit, plugins, raft, snapshots)

- Audit `file_path` is intentional privileged sink configuration.
- Plugin command joining uses EvalSymlinks / directory containment checks.
- Raft snapshot paths are under configured storage; API snapshot upload is root/sudo streaming, not attacker path join.
- **Dismissal:** No untrusted path segment → arbitrary file read/write outside intended privileged ops.

### 10. Template injection → secret disclosure / RCE

- Username templates (`sdk/helper/template`) expose a fixed FuncMap (random, truncate, hash, uuid, time)—no `env`/`file`/`exec`.
- Identity templates (`sdk/helper/identitytpl`) interpolate entity/alias/group metadata only.
- LDAP user/group filters are Go templates over pre-escaped fields.
- **Dismissal:** No template primitive yielding RCE or cross-secret disclosure beyond intentional identity metadata rendering.

### 11. Unsafe YAML/JSON deserialization

- Production paths use `encoding/json` / mapstructure into typed structs; yaml.v2/v3 appear as transitive/indirect deps without a gob/yaml gadget-style parse of untrusted attacker blobs into executable types.
- **Dismissal:** No validated unsafe deserialization gadget chain.

### 12. Physical MSSQL storage concatenation

- `physical/mssql/mssql.go` still concatenates identifiers but validates via `identifierRegex` (CVE-2023-0620 remediation pattern).
- **Dismissal:** Not a new exploitable SQLi.

---

## Methodology (summary)

Reviewed database plugins under `plugins/database/*` and `builtin/logical/database` for unquoted identifiers and statement concatenation; scanned for `os/exec`, file path joins, outbound HTTP from auth/secrets engines, Go/`text/template` usage, and JSON/YAML decode sites; cross-checked against stated exclusions (ACME SSRF, Redshift/HANA FP, MSSQL DeleteUser, PostgreSQL CVE-2026-39946).

---

## Conclusion

Within the requested classes and exclusions, this review did **not** validate a new MEDIUM+ vulnerability with a complete attacker → controlled input → reachable sink → impact chain. Remaining interesting code patterns are either previously excluded, privileged-operator-by-design, or lack a practical untrusted-input exploit path.
