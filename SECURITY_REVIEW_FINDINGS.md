# Application Security Review — HashiCorp Vault 1.18.0-beta1 (continued)

**Target:** `/workspace` @ `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-651e`  
**Skipped (already covered):** CVE-2025-6000, 5999, 7594, 11621, 6037, 6013–6015, 6004, 6011, 5052, 4525, 8185, 6203, 5807, 4166, 3605, 3879, CVE-2025-4656, CVE-2026-39946 / PostgreSQL schema `QuoteIdentifier` in `plugins/database/postgresql/postgresql.go`.

---

## Finding 1 — MSSQL database secrets engine: unquoted identifiers in default revoke (SQL injection)

| Field | Value |
| --- | --- |
| **Severity** | Medium (confused-deputy SQLi as DB management user; same class as OpenBao CVE-2026-39946 / PG schema revoke) |
| **CWE** | CWE-89 (SQL Injection) |
| **Primary location** | `plugins/database/mssql/mssql.go` — `MSSQL.revokeUserDefault` / `dropUserSQL` |
| **Status in this tree** | **Vulnerable** (still present on upstream `main` as of review; contained-DB path correctly uses `QuoteName`) |

### Vulnerable code

Default (non-`contained_db`) revocation builds `dropUserSQL` by interpolating the **database name** from login mappings and the **username** with `fmt.Sprintf`, without `QuoteName` / escaping:

```412:421:plugins/database/mssql/mssql.go
const dropUserSQL = `
USE [%s]
IF EXISTS
  (SELECT name
   FROM sys.database_principals
   WHERE name = N'%s')
BEGIN
  DROP USER [%s]
END
`
```

Catalog-derived `dbName` and the Vault-managed `username` are inserted here:

```292:310:plugins/database/mssql/mssql.go
	for rows.Next() {
		var loginName, dbName, qUsername, aliasName sql.NullString
		err = rows.Scan(&loginName, &dbName, &qUsername, &aliasName)
		// ...
		revokeStmts = append(revokeStmts, fmt.Sprintf(dropUserSQL, dbName.String, username, username))
	}
	// ...
	for _, query := range revokeStmts {
		if err := dbtxn.ExecuteDBQueryDirect(ctx, db, nil, query); err != nil {
			lastStmtError = err
		}
	}
```

`ExecuteDBQueryDirect` runs `db.ExecContext` on the fully interpolated batch (`sdk/helper/dbtxn/dbtxn.go`). The same file already uses `QuoteName(@username)` for disable/drop-login and for the `contained_db` path — inconsistent and unsafe for this batch.

Default revoke runs when role `revocation_statements` are empty (`DeleteUser` → `revokeUserDefault`).

### Attacker / controlled input

- **Attacker:** Principal with ability to create databases (e.g. `dbcreator`) and create database users mapped to a Vault-issued login on the **target SQL Server** that Vault manages. Not Vault root. Typical shared/dev SQL hosts or a compromised app account with elevated DDL.
- **Controlled input:** SQL Server database name returned by `sp_msloginmappings` (this beta) for the Vault-managed login. Bracket identifiers allow almost any character; a literal `]` in the name is created as `]]` and breaks out of Vault’s unescaped `USE [%s]`.

### End-to-end attack path

1. Vault MSSQL database secrets engine is configured; a dynamic role uses **default** revocation (empty / unset `revocation_statements`), and `contained_db` is not set.
2. Attacker (or any user) obtains a Vault dynamic MSSQL login for that role (`database/creds/<role>`).
3. Attacker creates a malicious database whose name closes the bracket early, e.g. create `[x]]; <payload>;--]` so the stored name is `x]; <payload>;--`.
4. In that database: `CREATE USER ... FOR LOGIN [<vault-login>]` so mappings include the malicious DB.
5. Lease expiry or `vault lease revoke` calls `revokeUserDefault`.
6. Vault builds and executes a TDS batch like:
   `USE [x]; <payload>;--] IF EXISTS ...`  
   as the **Vault management** SQL connection.

Secondary issue in the same template: `WHERE name = N'%s'` does not escape `'` in `username`. Default username templates plus common auth `DisplayName` sanitization make this harder to reach than the DB-name path; still a defense-in-depth failure.

### Impact

- **Reliable:** Revocation integrity failure / incomplete cleanup.
- **Higher impact:** Arbitrary SQL batch execution as the Vault management principal (DDL/DCL/DML within that account’s privileges), including further privilege escalation on the SQL Server depending on the Vault root DB user’s rights.

### Fix direction

- Build `USE` / `DROP USER` / name predicates with `QuoteName` (parameterized dynamic SQL), matching the contained-DB and `dropLoginSQL` paths.
- Do not concatenate raw catalog names or usernames into `dropUserSQL`.

---

## Areas reviewed without new medium+ findings

| Area | Result |
| --- | --- |
| MySQL / Cassandra / Influx / MongoDB plugins | Default statements use quoted placeholders via `QueryHelper`; no catalog-derived unquoted identifier path analogous to PG/MSSQL. Snowflake/Redis plugins not present in this OSS tree. |
| HANA default revoke (`fmt.Sprintf` unquoted username) | Unsafe construction, but metacharacters typically fail as identifiers under `Prepare`; static-role writers can already supply arbitrary `rotation_statements` — no clearer confused-deputy E2E than MSSQL. |
| Redshift `terminateloop('%s')` | Username string-literal interpolation; default templates avoid `'`; no catalog-name injection (schemas already `QuoteIdentifier`’d). Below medium+ bar for this pass. |
| secrets/aws | `policy_document` / STS+IAM endpoints are admin-configured; no user-controlled policy SSTI. STS endpoint SSRF requires privileged `config/root` write. |
| secrets/nomad, consul, rabbitmq | Token names embed `DisplayName` (length/DoS at most); policies/vhosts are admin role config via APIs, not command injection. |
| auth/jwt + oidc (`vault-plugin-auth-jwt` v0.20.3) | Algorithms default to asymmetric set (no `none`/`HS*` confusion with JWKS); empty `bound_audiences` rejects non-empty `aud`; OIDC exercises `azp`; `bound_claims` validated. No new bypass locked. |
| auth/github | Org check by `organization_id`; TOFU sets ID via `Organizations.Get` for configured name; team mapping by name/slug. No membership bypass found. |
| wrapping / cubbyhole | Wrap tokens are single-use response-wrapping; no novel abuse path beyond known design. |
| UI Ember XSS | `log-error-with-html` triple-stash used for control-group link; `creation_path`/`accessor` not a practical cross-user XSS at medium+. Elsewhere `sanitized-html` / DOMPurify used. |
| Agent templates | Consul-Template runner; templates come from local agent config (operator trust boundary), not Vault secret SSTI RCE. |
| Plugin catalog | `..` rejected; `EvalSymlinks` + directory equality blocks escape on register. |
| `sys/raw` | Only mounted when `EnableRaw`; sudo; protected paths for keyring/cluster info. No authz gap beyond intentional break-glass. |
| MFA (Duo/Okta/PingID) beyond TOTP reuse | Passcode reuse cache present for TOTP (already reported class); Duo/Okta/PingID admin endpoint config only — no extra medium+ bypass. |
| Transit export / encrypt oracle | Export gated on `exportable` + ACL path; no export authz bypass; encrypt/decrypt are intentional oracles under policy. |

---

## Evidence checklist (Finding 1)

- [x] Attacker model defined (DB `dbcreator` / user-mapper on managed SQL Server)
- [x] Controlled input identified (database name via login mappings → `dropUserSQL`)
- [x] Reachability: empty `revocation_statements` → `revokeUserDefault` → `ExecuteDBQueryDirect`
- [x] Impact: revoke integrity + SQLi as management user
- [x] Primary path: `plugins/database/mssql/mssql.go`
