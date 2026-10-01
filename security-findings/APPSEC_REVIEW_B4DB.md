# Application Security Review — scoped categories @ `0513545dd`

**Tree:** `/workspace` @ `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`cursor/application-security-review-b4db`)  
**Scope:** (1) SQL string-building sinks, (2) LDAP filter injection, (3) command injection, (4) template injection with privileged funcs, (5) UI XSS, (6) planted/unusual insecure code.

---

## Validated medium+ findings

### Finding 1 — Database secrets plugins: static-role username → default SQL injection (High)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CWE** | CWE-89 |
| **Attacker** | Authenticated principal with `create`/`update` on `database/static-roles/*` for a connection using one of the affected plugins (delegated DB onboarding; not Vault root). Exploitable when `rotation_statements` / `revocation_statements` are empty or omitted — including when ACLs use `denied_parameters = ["rotation_statements"]`. |
| **Controlled input** | Static-role `username` (`framework.TypeString`, no identifier validation in `builtin/logical/database/path_roles.go`) |

Shared unsanitized substitution in `sdk/database/helper/dbutil/dbutil.go` (`QueryHelper`) and `sdk/helper/dbtxn/dbtxn.go` (`parseQuery` / `Execute*Direct`), which run `ExecContext` on the fully interpolated string.

#### 1a — MySQL default password rotation (single-statement; no `multiStatements` required)

**Location:** `plugins/database/mysql/mysql.go` — `defaultMySQLRotateCredentialsSQL` / `changeUserPassword`

Default template:

```
ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
```

**Attack path:**
1. Admin configures a MySQL connection with a privileged Vault management user.
2. Attacker creates a static role with empty rotation statements and username:
   `victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#`
3. `setStaticAccount` → plugin `UpdateUser` → `changeUserPassword` → `QueryHelper`.
4. Rendered SQL:
   `ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned-via-plugin';#'@'%' IDENTIFIED BY '<vault-password>';`
5. MySQL applies the password change to `victim`; `#...` is a line comment. Vault's rotated secret is never applied.

**Impact:** Reset arbitrary MySQL account passwords the connector can `ALTER`.

#### 1b — PostgreSQL default password rotation (quote breakout)

**Location:** `plugins/database/postgresql/postgresql.go` — `defaultChangePasswordStatement`

```
ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';
```

**Attack path:** username `victim" WITH SUPERUSER; --` → rendered:
`ALTER ROLE "victim" WITH SUPERUSER; --" WITH PASSWORD '...';`  
pgx executes the multi-statement batch as the Vault DB role.

**Impact:** Arbitrary SQL / privilege escalation inside PostgreSQL as the Vault management role.

#### 1c — MSSQL default `ALTER LOGIN` rotation (bracket breakout)

**Location:** `plugins/database/mssql/mssql.go` — `alterLoginSQL`

```
ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'
```

**Attack path:** username `a] WITH PASSWORD = 'x'; <T-SQL>;--` breaks out of bracket quoting (no `]` → `]]` escaping; contrast `QuoteName` used in `dropLoginSQL`). TDS executes the injected batch.

**Impact:** Arbitrary T-SQL as the Vault MSSQL login.

#### 1d — HANA default rotate / revoke (unquoted username)

**Location:** `plugins/database/hana/hana.go`

- Default rotate: `ALTER USER {{username}} PASSWORD "{{password}}"`
- Default revoke: `fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", ...)` / `DROP USER %s RESTRICT`

**Attack path:** static-role username smuggles additional `ALTER USER` clauses / comment breakout (e.g. `VICTIM PASSWORD "pwned" --`).

**Impact:** Arbitrary HANA DDL/DCL as the Vault HANA connection user.

**Proof:** `go test ./sdk/database/helper/dbutil/ -run TestQueryHelper_DefaultSQLInjectionBreakouts -count=1`

---

### Finding 2 — MSSQL default revoke: catalog DB name interpolated into `dropUserSQL` (High)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CWE** | CWE-89 |
| **Attacker** | Principal who can create databases on the **managed SQL Server** and map a Vault-issued login into them (e.g. `dbcreator`). Not Vault root. |
| **Controlled input** | Database name returned by `sp_msloginmappings` |

**Location:** `plugins/database/mssql/mssql.go` — `revokeUserDefault` / `dropUserSQL`

`dropUserSQL` uses `fmt.Sprintf` with `USE [%s]` / `N'%s'` / `DROP USER [%s]` without `QuoteName`. Contained-DB and disable-login paths correctly use `QuoteName`.

**Attack path:**
1. Dynamic MSSQL role uses default revocation; `contained_db` unset.
2. Attacker obtains a Vault dynamic login, creates a DB whose name closes the bracket early (stored name `x]; <payload>;--`), and maps the Vault login into it.
3. Lease revoke builds `USE [x]; <payload>;--] IF EXISTS ...` and executes it as the Vault management principal.

**Impact:** Arbitrary T-SQL as the Vault management SQL login; incomplete/failed revocation.

---

## Categories checked — no medium+ validated

### 2) LDAP filter injection (`builtin/credential/ldap`, `sdk/helper/ldaputil`)

- User/group filter templates inject `ldap.EscapeFilter`-escaped username / UserAttr / UserDN (`sdk/helper/ldaputil/client.go`).
- No privileged `FuncMap`; bind DN uses `EscapeLDAPValue`.
- **Verdict:** no medium+ filter injection for login input.

### 3) Command injection (plugins, scripts, token helpers, SSH secrets engine)

- Plugin catalog rejects `..`, enforces plugin directory via `EvalSymlinks`; `exec.Command` without shell.
- External token helper `/bin/sh -c` is local CLI config only.
- `builtin/logical/ssh` has no `os/exec`.
- **Verdict:** no server-side medium+ command injection.

### 4) Template injection with privileged funcs

- Username templates expose only string helpers (no fs/exec).
- LDAP templates have no custom funcs.
- **Verdict:** no privileged-func SSTI medium+.

### 5) UI XSS (custom messages, OpenAPI HTML, unescaped secrets)

- Custom messages use Ember `{{...}}` auto-escaping (`ui/app/templates/vault/cluster.hbs`).
- `sanitized-html` uses DOMPurify; OpenAPI explorer renders Vault-generated specs.
- **Verdict:** no medium+ XSS in scoped surfaces.

### 6) Planted / unusual insecure code

- Physical SQL backends validate/quote config table names; no API-user SQLi path.
- No backdoors / unexpected eval; `InsecureSkipVerify` is config-gated as usual.
- **Verdict:** none identified on this tree.

### Physical backend SQL (category 1 negative)

MySQL/MSSQL/Postgres/CockroachDB validate or quote identifiers from server config; keys are parameterized. Cassandra table concat is config-only.
