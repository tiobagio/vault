# Database Secrets Engine — SQL Injection Review

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Scope:** `builtin/logical/database` + SQL plugins (Postgres / MySQL / MSSQL / Redshift / HANA)  
**Bar:** Medium+ only, real end-to-end paths. Admin-authored `creation_statements` / `rotation_statements` alone are not findings unless a lower-privileged input (auth DisplayName, constrained static-role `username`, etc.) reaches the SQL sink.

Shared sink (no escaping):

```21:27:sdk/database/helper/dbutil/dbutil.go
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

```77:85:sdk/helper/dbtxn/dbtxn.go
func parseQuery(m map[string]string, tpl string) string {
	// ...
	for k, v := range m {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

---

## Finding 1 — Static-role `username` injects into default rotation SQL

| Field | Detail |
| --- | --- |
| **Title** | Static-role username SQL injection via default rotation statements |
| **Severity** | High |
| **Attacker** | Authenticated Vault principal with `create`/`update` on `database/static-roles/*` who cannot set statement bodies (ACL `denied_parameters = ["rotation_statements"]` or `allowed_parameters` limited to identifier fields such as `username`, `db_name`, `rotation_period`) |
| **Controlled input** | Static-role `username` (`framework.TypeString`, no identifier validation) |
| **Reachability** | Role write → `setStaticAccount` → plugin `UpdateUser` with empty/custom-empty rotation commands → plugin default ALTER statement → unescaped `{{username}}`/`{{name}}` substitution → `ExecContext` as Vault DB management user |
| **Impact** | Arbitrary SQL / password takeover / privilege escalation on the customer database under the Vault plugin connection identity |
| **Primary location** | `plugins/database/mysql/mysql.go` (representative; same pattern in postgresql, mssql, redshift, hana) |

### Evidence

Username accepted without sanitization and rotation triggered on create:

```555:563:builtin/logical/database/path_roles.go
	username := data.Get("username").(string)
	// ...
	role.StaticAccount.Username = username
```

**MySQL** default (single-statement driver still exploitable via `#` comment):

```26:28:plugins/database/mysql/mysql.go
	defaultMySQLRotateCredentialsSQL = `
		ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
	`
```

Payload: `victim'@'%' IDENTIFIED BY 'pwned';#`  
Rendered: `ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned';#'@'%' IDENTIFIED BY '<vault-password>';`

**PostgreSQL** default:

```30:32:plugins/database/postgresql/postgresql.go
	defaultChangePasswordStatement = `
ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';
`
```

Payload: `victim" WITH SUPERUSER;--`  
Rendered: `ALTER ROLE "victim" WITH SUPERUSER;--" WITH PASSWORD '...';`  
(`ExecuteTxQueryDirect` → `tx.ExecContext` on the interpolated string; pgx simple protocol batches.)

**MSSQL** default:

```431:433:plugins/database/mssql/mssql.go
const alterLoginSQL = `
ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'
`
```

Payload: `a] WITH PASSWORD = 'x'; <T-SQL>;--` (no `]` → `]]` escaping; contrast `QuoteName` used for `dropLoginSQL` in the same file).

**Redshift** default uses the same double-quote pattern as Postgres (`ALTER USER "{{name}}" WITH PASSWORD '{{password}}';`).

**HANA** default leaves username unquoted:

```229:229:plugins/database/hana/hana.go
		stmts = []string{"ALTER USER {{username}} PASSWORD \"{{password}}\""}
```

Payload: `X; DROP USER SA CASCADE; --`

### Why not “admin intentional SQL”

Custom `rotation_statements` are an intentional privileged capability. The `username` field is documented as the existing DB account name. Constrained operators barred from statement parameters can still smuggle SQL through `username` into **defaults**.

### Remediation

- Validate / quote identifiers per dialect before interpolation (or ban metacharacters in `username`).
- Prefer bound parameters / driver quoting (`QuoteIdentifier`, `QuoteName`) for default statements.
- Do not treat `username` as trusted SQL text even when statement fields are ACL-denied.

---

## Finding 2 — Auth `DisplayName` → username template → dynamic credential SQL injection

| Field | Detail |
| --- | --- |
| **Title** | Caller-controlled DisplayName flows into DB username templates and unsanitized SQL |
| **Severity** | High (HANA defaults and any custom `username_template` embedding `.DisplayName`); Medium on MySQL/MSSQL/Postgres/Redshift **default** templates alone (truncate + mount prefix shrink payload space, but quote/bracket breakout is still real) |
| **Attacker** | Principal who can authenticate via an auth method that places attacker-influenced text into `Auth.DisplayName` (LDAP / Okta / Radius login paths use `login/(?P<username>.+)`) and who can `read` `database/creds/<role>` |
| **Controlled input** | Auth username / DisplayName (not passed through token-create `displayNameSanitize`) |
| **Reachability** | Auth login sets `DisplayName` → `LoginCreateToken` prepends mount source only → `pathCredsCreateRead` copies `req.DisplayName` into `UsernameConfig` → plugin `username_template` renders username → `QueryHelper`/`parseQuery` into role `creation_statements` (and later revoke/rotate defaults) |
| **Impact** | SQL injection as the Vault DB management user when generating dynamic credentials against customer databases |
| **Primary location** | `builtin/logical/database/path_creds_create.go` |

### Evidence

Unsani­tized pass-through into username metadata:

```126:129:builtin/logical/database/path_creds_create.go
			UsernameConfig: v5.UsernameMetadata{
				DisplayName: req.DisplayName,
				RoleName:    name,
			},
```

LDAP (same pattern for Okta/Radius) accepts arbitrary path username and sets DisplayName directly:

```16:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```97:97:builtin/credential/ldap/path_login.go
		DisplayName: username,
```

Token-create sanitizes `display_name` (`[^a-zA-Z0-9-]` → `-`), but auth DisplayNames do **not** use that path. `LoginCreateToken` only prepends the mount source:

```2012:2016:vault/request_handling.go
	source := strings.TrimPrefix(mountPoint, credentialRoutePrefix)
	source = strings.ReplaceAll(source, "/", "-")
	auth.DisplayName = strings.TrimSuffix(source+auth.DisplayName, "-")
```

Documented creation statements interpolate `{{name}}`/`{{username}}` without engine-side escaping, e.g.:

- Postgres: `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' ...`
- MySQL: `CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';...`
- MSSQL: `CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';...`
- Redshift: `CREATE USER "{{name}}" WITH PASSWORD '{{password}}' ...`
- HANA: `CREATE USER {{name}} PASSWORD {{password}} ...` (**unquoted** name)

Example rendered HANA breakout with default template (`DisplayName | truncate 32`) after `ldap-` prefix:

`CREATE USER V_LDAP_X;DROP USER SA CASCADE__... PASSWORD Secret1 VALID UNTIL 'e';`

Secondary sinks once a malicious username is stored on the lease:

- HANA default revoke: `fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username)` / `DROP USER %s RESTRICT` (`plugins/database/hana/hana.go`)
- Redshift default revoke: `fmt.Sprintf("call terminateloop('%s');", username)` (`plugins/database/redshift/redshift.go`)
- MSSQL default revoke: `N'%s'` / `[%s]` formatting in `dropUserSQL` (`plugins/database/mssql/mssql.go`)

Upstream later fixed this class by sanitizing DisplayName before username generation (Vault CE 2.1.0 / Ent 1.21.10+); **this commit has no `sanitizeDisplayName`**.

### Remediation

- Sanitize DisplayName (and RoleName if ever attacker-influenced) to a strict identifier charset before template generation (as in later Vault).
- Prefer `truncate_sha256` / disallow raw `.DisplayName` in templates without charset filtering.
- Quote/escape all substituted values for the target dialect; never `ReplaceAll` into SQL.

---

## Out of scope / not validated as medium+ here

| Candidate | Verdict |
| --- | --- |
| Admin-only custom `creation_statements` / `rotation_statements` | Intentional privileged capability |
| Role **name** via `creds/<name>` | `GenericNameRegex` blocks quote/semicolon metacharacters |
| Default generated passwords in rotation | Default charset is alphanumeric + `-` only |
| Token `auth/token/create` `display_name` | Sanitized via `displayNameSanitize` |
| Postgres defaultDeleteUser unquoted schema from `information_schema` | Not attacker-controlled via DisplayName/static-role username alone without prior DB foothold |
