# Application Security Review — Database Secrets Engine SQLi

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Focus:** `plugins/database/*`, `builtin/logical/database/*`, static-role rotation / CreateUser / DeleteUser / UpdateUser  
**Excluded as already well-documented in this fork's review history:** PostgreSQL static-role quote breakout; PostgreSQL schema REVOKE (CVE-2026-39946); MSSQL `dropUserSQL` / `alterLoginSQL`; Redshift `terminateloop`; HANA unquoted ALTER/DROP; InfluxDB static-role IFQL.

---

## Finding 1 — MySQL static-role default password rotation: single-quote / `#` SQL injection

| Field | Value |
| --- | --- |
| **Title** | MySQL static-role default `ALTER USER` SQL injection via unsanitized `{{username}}` |
| **Severity** | **High** |
| **Location** | `plugins/database/mysql/mysql.go` |
| **Attacker** | Authenticated Vault principal with `create`/`update` on `database/static-roles/*` for a MySQL connection (delegated DB-onboarding; not Vault root). Works when `rotation_statements` is empty / omitted, including when ACLs use `denied_parameters = ["rotation_statements"]`. |
| **Input** | Static-role `username` (`framework.TypeString`, no identifier validation) |
| **Path** | See below |
| **Impact** | Arbitrary single-statement SQL as the Vault MySQL management user — specifically **reset any MySQL account password** the connector can `ALTER` (including other DB admins), without needing `multiStatements=true` |

### Why this is novel vs prior reviews

Prior AppSec notes dismissed MySQL rotation SQLi because `go-sql-driver/mysql` defaults `MultiStatements=false`, assuming breakout needs a second statement. That reasoning is wrong for this sink: a **single-statement** quote breakout + `#` line comment overwrites the target user's password and comments out Vault's generated password clause. No multi-statement support required.

### Attack path

1. Admin configures `database/config/<conn>` with `mysql-database-plugin` and a privileged management user (typical `CREATE USER` / `ALTER USER` grants).
2. Attacker creates a static role with malicious `username` and empty/omitted `rotation_statements`:

   ```
   username = victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#
   ```

3. `pathStaticRoleCreateUpdate` → `setStaticAccount` → plugin `UpdateUser` → `changeUserPassword` → `executePreparedStatementsWithMap`.
4. Empty statements select the default:

   ```sql
   ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
   ```

5. `dbutil.QueryHelper` does unescaped `strings.ReplaceAll` substitution. Rendered SQL:

   ```sql
   ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#'@'%' IDENTIFIED BY 'vault-rotated-never-applied';
   ```

6. MySQL executes `ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned-via-plugin';`; `#...` is a line comment. Victim authenticates with `pwned-via-plugin`; Vault's rotated secret is never applied.

### Evidence

Default rotation template and empty-statement fallback:

```26:28:plugins/database/mysql/mysql.go
	defaultMySQLRotateCredentialsSQL = `
		ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
	`
```

```211:228:plugins/database/mysql/mysql.go
func (m *MySQL) changeUserPassword(ctx context.Context, username, password string, rotateStatements []string) error {
	// ...
	if len(rotateStatements) == 0 {
		rotateStatements = []string{defaultMySQLRotateCredentialsSQL}
	}
	queryMap := map[string]string{
		"name":     username,
		"username": username,
		"password": password,
	}
	if err := m.executePreparedStatementsWithMap(ctx, rotateStatements, queryMap); err != nil {
```

Unescaped templating (same helper used across DB plugins):

```262:262:plugins/database/mysql/mysql.go
			query = dbutil.QueryHelper(query, queryMap)
```

```21:28:sdk/database/helper/dbutil/dbutil.go
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

Static-role username accepted unconstrained; create immediately rotates:

```191:194:builtin/logical/database/path_roles.go
		"username": {
			Type: framework.TypeString,
```

```555:563:builtin/logical/database/path_roles.go
	username := data.Get("username").(string)
	// ...
	role.StaticAccount.Username = username
```

```409:414:builtin/logical/database/rotation.go
	updateReq := v5.UpdateUserRequest{
		Username: input.Role.StaticAccount.Username,
	}
	statements := v5.Statements{
		Commands: input.Role.Statements.Rotation,
	}
```

### E2E validation (MariaDB 10.11, `go-sql-driver/mysql`, **actual** `plugins/database/mysql` `UpdateUser`)

```
UpdateUser OK
original: FAIL
pwned: SUCCESS
vault-rotated: FAIL
```

Payload username `victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#` with empty rotation statements; management DSN `vaultadmin@localhost`. Confirms password takeover of pre-existing user `victim` without `multiStatements`.

### Remediation

- Escape MySQL string literals (and identifiers) before `QueryHelper` substitution, or use dialect-safe quoting helpers.
- Prefer parameterized / `mysql.Config`-safe forms where possible; reject static-role usernames outside a strict charset when defaults are used.

---

## Near-misses (not reported as validated Medium+)

| Candidate | Why not reported |
| --- | --- |
| Cassandra `ALTER USER '{{username}}'...` | Same template anti-pattern; Cassandra 4.1 CQL rejects `--`/`//` comments (`expecting set null`), rejects multi-statements, and `/*` close requires controlling password content (`*/`) — no clean username-only E2E. |
| Redshift static-role `ALTER USER "{{name}}" WITH PASSWORD ...` | Existence check fails closed on the literal malicious username before the ALTER runs (`redshift.go` updateUserPassword). |
| Snowflake `alter user {{name}} set PASSWORD = '{{password}}';` | Clear unquoted-name injection in module code; treated as already-known in this fork's skip lists; not re-scored. |
| Elasticsearch `path.Join(... user, name)` | Known path-join class; skipped. |
| Redis / Couchbase / MongoDB | Structured ACL/BSON/UserManager APIs — username not string-interpolated into SQL. |
| MySQL `DeleteUser` default `DROP USER '{{name}}'` | Same ReplaceAll sink; dynamic DisplayName path is truncated by username template; static roles do not revoke via DeleteUser. |
