# Application Security Review — HashiCorp Vault

Commit: `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`

Focus: raw SQLi, shell/command execution, SSRF/network fetches, path traversal, deserialisation, webhook/callback abuse in plugins and secret engines.

Excluded (already-known / do not re-report):
- CVE-2026-5052 ACME http-01/tls-alpn-01 SSRF (`builtin/logical/pki/acme_challenges.go`)
- MSSQL `dropUserSQL` SQLi (`plugins/database/mssql/mssql.go`)
- Redshift `terminateloop('%s')` SQLi (`plugins/database/redshift/redshift.go`)
- PostgreSQL unquoted schema names in REVOKE / CVE-2026-39946 (`plugins/database/postgresql/postgresql.go`)

---

## Finding 1: SAP HANA default rotate/revoke SQL injects unquoted static-role username

**Severity:** High

**Attacker:** Authenticated Vault client with `create`/`update` on `database/static-roles/*` for a connection using `hana-database-plugin` (typical delegated DB-onboarding privilege). Does not require root, mount admin, or `rotation_statements` (works with Vault defaults; also exploitable when ACLs use `denied_parameters = ["rotation_statements"]`).

**Controlled input:** Static-role `username` body field (unvalidated `TypeString`).

**Attack path:**
1. Admin has configured a HANA connection under `database/config/*` with a privileged Vault DB user.
2. Attacker creates a static role whose `username` contains HANA SQL metacharacters / extra clauses, e.g. `TARGETUSER PASSWORD "attacker-known"` or other `ALTER USER` clause smuggling.
3. Vault immediately calls `setStaticAccount` → plugin `UpdateUser` → `updateUserPassword`, which builds `ALTER USER {{username}} PASSWORD "{{password}}"` via unescaped string substitution (`QueryHelper` / `ExecuteTxQueryDirect`).
4. Lease revoke / default delete path similarly builds `ALTER USER %s DEACTIVATE USER NOW` and `DROP USER %s RESTRICT` with `fmt.Sprintf` and no quoting.

**Impact:** Arbitrary SQL as the Vault HANA connection user (typically able to alter/drop users and escalate inside the database). Can reset passwords of other DB users or otherwise mutate HANA security state.

**Primary location:** `plugins/database/hana/hana.go`

**Evidence:**

```228:230:plugins/database/hana/hana.go
	if len(stmts) == 0 {
		stmts = []string{"ALTER USER {{username}} PASSWORD \"{{password}}\""}
	}
```

```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

Username is accepted from static-role create with no identifier sanitization:

```555:563:builtin/logical/database/path_roles.go
	username := data.Get("username").(string)
	// ...
	role.StaticAccount.Username = username
```

**Remediation:** Quote/escape HANA identifiers (and string literals) with a dialect-safe helper before interpolation; prefer bound parameters where the driver/SQL form allows; reject usernames that are not valid unquoted/quoted HANA identifiers.

---

## Finding 2: MSSQL default password-rotation SQL allows bracket-identifier breakout (distinct from dropUserSQL)

**Severity:** High

**Attacker:** Authenticated Vault client with `create`/`update` on `database/static-roles/*` for an MSSQL connection. Same privilege model as Finding 1; distinct code path from the already-known `dropUserSQL` issue.

**Controlled input:** Static-role `username`.

**Attack path:**
1. Attacker creates a static role with a username that breaks out of MSSQL bracket quoting, e.g. `a] WITH PASSWORD = 'x'; <arbitrary T-SQL>;--`.
2. On create/rotate, Vault uses the default statement `ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'` with raw `QueryHelper` substitution (no `]` → `]]` escaping, unlike `QuoteName` used in `dropLoginSQL`).
3. `ExecuteTxQueryDirect` sends the resulting batch via `ExecContext`; the TDS driver executes multi-statement batches.
4. Injected T-SQL runs as the Vault MSSQL login (commonly `securityadmin` / `processadmin`-class privileges).

**Impact:** Arbitrary T-SQL on the connected SQL Server — create logins, escalate server roles, read/modify data, etc.

**Primary location:** `plugins/database/mssql/mssql.go`

**Evidence:**

```346:350:plugins/database/mssql/mssql.go
func (m *MSSQL) updateUserPass(ctx context.Context, username string, changePass *dbplugin.ChangePassword) error {
	stmts := changePass.Statements.Commands
	if len(stmts) == 0 && !m.containedDB {
		stmts = []string{alterLoginSQL}
	}
```

```431:433:plugins/database/mssql/mssql.go
const alterLoginSQL = `
ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'
`
```

Contrast with the safer dynamic SQL used for drop-login (still not a complete fix for `dropUserSQL`, which is already known):

```423:429:plugins/database/mssql/mssql.go
const dropLoginSQL = `
DECLARE @stmt nvarchar(max)
SET @stmt = 'IF EXISTS (SELECT name FROM [master].[sys].[server_principals] WHERE [name] = ' + QuoteName(@username, '''') + ') ' +
	'BEGIN ' +
		'DROP LOGIN ' + QuoteName(@username) + ' ' +
	'END'
EXEC (@stmt)`
```

**Remediation:** Build rotation SQL with `QuoteName` (or equivalent) for the login identifier and properly quote/escape the password literal; or use parameterized/`sp_executesql` patterns consistent with `dropLoginSQL`.

---

## Finding 3: PostgreSQL default password-rotation SQL allows double-quote breakout (distinct from schema REVOKE CVE)

**Severity:** High

**Attacker:** Authenticated Vault client with `create`/`update` on `database/static-roles/*` for a PostgreSQL connection.

**Controlled input:** Static-role `username`.

**Attack path:**
1. Attacker sets static-role username to a payload such as `victim" WITH SUPERUSER; --`.
2. Vault default statement is `ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';` filled via unescaped substitution (does **not** use `dbutil.QuoteIdentifier`, which correctly doubles embedded quotes).
3. Existence check uses a bound parameter and does not block execution when the literal name is absent; rotation still proceeds.
4. `ExecuteTxQueryDirect` → `ExecContext` sends the broken-out SQL (including additional statements after `;`) as the Vault DB role.

**Impact:** Arbitrary SQL as the Vault PostgreSQL role (often CREATEROLE / high privilege) — SUPERUSER escalation, role manipulation, data access.

**Primary location:** `plugins/database/postgresql/postgresql.go`

**Evidence:**

```30:32:plugins/database/postgresql/postgresql.go
	defaultChangePasswordStatement = `
ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';
`
```

```164:168:plugins/database/postgresql/postgresql.go
	stmts := changePass.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{defaultChangePasswordStatement}
	}
```

```203:217:plugins/database/postgresql/postgresql.go
			m := map[string]string{
				"name":     username,
				"username": username,
				"password": password,
			}
			// ...
			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
```

Shared unsanitized templating:

```22:27:sdk/database/helper/dbutil/dbutil.go
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

**Remediation:** Use `dbutil.QuoteIdentifier(username)` (and proper password literal escaping / `quote_literal`) when constructing default rotation SQL; reject identifiers containing disallowed characters.

---

## Strongest dismissed candidates

| Candidate | Why dismissed |
|---|---|
| MySQL `ALTER USER '{{username}}'...` default rotate | Same class of unsanitized interpolation, but `go-sql-driver/mysql` defaults disable `multiStatements`, so practical breakout to a second statement is weak without a non-default DSN; not elevated to validated Medium+ without driver-confirmed single-statement exploit. |
| Cassandra / InfluxDB quoted username in default CQL/IFQL | Same template pattern; CQL/Influx clients generally do not run multi-statement batches the way pgx/TDS do; lower confidence. |
| Cert auth CRL `http.Get(crl.CDP.Url)` SSRF | Requires write on cert auth CRL config; fetching configured CRL URLs is intentional. No tenant secrets-engine role path. |
| AWS/Nomad/Consul `*_endpoint` / `address` | Connection targets are mount-config (admin) by design; not confused with role-writer SSRF. |
| AWS IAM auth STS submit path | Endpoint comes from server config; request URI is constrained to GetCallerIdentity. |
| File physical backend path join | `validatePath` rejects `..`. |
| LDAP user/group filter templates | Username values are `ldap.EscapeFilter`'d before template execution. |
| Agent/template/`os/exec` surfaces | Operator-local agent config or test/build helpers, not Vault server tenant attack surface. |
| MongoDB static rotate | Uses BSON command structs (`updateUser`), not string-built SQL. |
| Static-role `rotation_statements` arbitrary SQL | By design for role writers; findings above are about Vault **default** SQL still being unsafe when statements are empty / denied. |
