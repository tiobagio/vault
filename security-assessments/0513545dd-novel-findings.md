# Novel AppSec Findings — Vault 1.18.0-beta1 (`0513545dd`)

Scan of commit `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`VERSION` = `1.18.0-beta1`).

Scope: novel medium+ issues with concrete end-to-end paths, excluding the known set
(CVE-2025-6000/5999/6037/11621/6013–6015/6004/6011, CVE-2024-7594, Redshift/HANA
DeleteUser SQLi, PKI ACME SSRF / CVE-2026-5052, well_known_redirect).

---

## Verdict

**One novel High finding** meets the bar: MSSQL database secrets-engine default
revocation SQL injection via unquoted `username` / `dbName` interpolation in
`dropUserSQL`.

No additional novel Critical findings were validated in this pass.

---

## Finding 1 — MSSQL default DeleteUser SQL injection (HIGH)

| Field | Detail |
|---|---|
| **Severity** | High |
| **Primary location** | `plugins/database/mssql/mssql.go` |
| **Attacker identity** | (A) Authenticated Vault principal who can mint MSSQL dynamic creds **and** whose `DisplayName` can contain `'` (e.g. LDAP login `username` pattern `(?P<username>.+)`, or a custom `username_template` reflecting attacker-influenced identity fields). (B) Alternatively, a principal with `CREATE DATABASE` (and user-mapping) rights on the target SQL Server instance that Vault manages (confused deputy via malicious database name). |
| **Controlled input** | (A) LDAP/auth username → Vault `DisplayName` → generated DB username embedded into `dropUserSQL`. (B) SQL Server database name returned by `sp_msloginmappings`. |
| **Reachability** | Dynamic DB role with **empty** `revocation_statements` → lease revoke / expiry → `DeleteUser` → `revokeUserDefault` → `fmt.Sprintf(dropUserSQL, dbName, username, username)` → `ExecuteDBQueryDirect` as Vault’s management connection. |
| **Impact** | Arbitrary SQL batch execution as the Vault MSSQL management login (often highly privileged), during credential revocation. |

### Evidence

Default username template embeds truncated `DisplayName` with **no** quote/`]` sanitization:

```27:27:plugins/database/mssql/mssql.go
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 20) (.RoleName | truncate 20) (random 20) (unix_time) | truncate 128 }}`
```

LDAP auth accepts arbitrary username bytes and sets them as `DisplayName`:

```18:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```90:98:builtin/credential/ldap/path_login.go
	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
		},
		// ...
		DisplayName: username,
```

Lease revoke calls plugin `DeleteUser` with the stored username when role
`revocation_statements` are empty (default path):

```154:160:builtin/logical/database/secret_creds.go
		deleteReq := v5.DeleteUserRequest{
			Username: username,
			Statements: v5.Statements{
				Commands: statements.Revocation,
			},
		}
		_, err = dbi.database.DeleteUser(ctx, deleteReq)
```

Empty revocation commands select `revokeUserDefault`:

```179:182:plugins/database/mssql/mssql.go
func (m *MSSQL) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	if len(req.Statements.Commands) == 0 {
		err := m.revokeUserDefault(ctx, req.Username)
		return dbplugin.DeleteUserResponse{}, err
```

Unsafe interpolation (username **and** database name):

```301:301:plugins/database/mssql/mssql.go
		revokeStmts = append(revokeStmts, fmt.Sprintf(dropUserSQL, dbName.String, username, username))
```

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

Executed as a raw batch (SQL Server supports `;`-separated batches; this path does
**not** use `QuoteName` unlike the contained-DB / disable-login paths in the same file):

```307:309:plugins/database/mssql/mssql.go
	for _, query := range revokeStmts {
		if err := dbtxn.ExecuteDBQueryDirect(ctx, db, nil, query); err != nil {
			lastStmtError = err
```

Creation statements in-tree use bracket quoting for `{{name}}`, so a username
containing `'` can be created successfully, then break the `N'%s'` predicate on
revoke:

```567:568:plugins/database/mssql/mssql_test.go
CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';
CREATE USER [{{name}}] FOR LOGIN [{{name}}];
```

Note: changelog `13799` claimed removal of string interpolation on MSSQL internal
queries, but `dropUserSQL` remains interpolated — an incomplete fix relative to the
`QuoteName`-based disable/drop-login paths in the same function.

### Concrete attack sketch (path A — username)

1. Attacker authenticates via LDAP with a username whose first ~15 characters after
   the `ldap-` display-name prefix include a breakout such as `');EXEC('` (fits in
   the 20-char `DisplayName` truncate window).
2. Attacker reads `database/creds/<mssql-role>` (role uses default revocation).
3. Vault creates login/user with bracket-quoted name containing `'`.
4. On lease revoke/expiry, Vault builds
   `WHERE name = N'v-ldap-');EXEC(...` → injected batch runs as the management user.

### Concrete attack sketch (path B — database name / confused deputy)

Same class as OpenBao/Vault PostgreSQL revoke schema SQLi (CVE-2026-39946):

1. Attacker (or insider) with `CREATE DATABASE` on the managed instance creates a
   database whose name contains `]` breakout characters and maps the Vault-managed
   login into that database.
2. On revoke, `USE [%s]` becomes `USE [foo]; <injected>;--]`.
3. Injected SQL runs as Vault’s management login.

### Why this is out of the excluded set

Excluded DB SQLi items are Redshift `terminateloop` and HANA `ALTER/DROP USER`
interpolation only. This is a distinct MSSQL secrets-engine default-revocation bug.
No public CVE for this secrets-engine path was identified (CVE-2023-0620 is the
**storage** backend, different code).

---

## Near-misses (did not meet the novel medium+ bar)

### 1. PostgreSQL unquoted schema in `defaultDeleteUser` — already CVE-2026-39946

`plugins/database/postgresql/postgresql.go` still interpolates `(schema)` without
`QuoteIdentifier` in one `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA` statement
(adjacent statement correctly quotes). This is the known OpenBao/Vault issue
**CVE-2026-39946** (Medium). Present and still vulnerable in this tree, but not
reported as novel.

### 2. MySQL / Cassandra / InfluxDB username `ReplaceAll` / `QueryHelper`

Same unescaped `{{username}}`/`{{name}}` pattern exists, and LDAP can feed `'` into
`DisplayName`. Failed the bar because:

- Default MySQL DSN does not enable `multiStatements` (driver default false) →
  batched follow-on statements typically do not execute.
- gocql executes one CQL string at a time → limited to statement failure / narrow
  breakage rather than clear high-impact multi-statement RCE.
- Requires either custom `username_template` or special-character identity source;
  impact under default driver behavior is not clearly High.

### 3. Cert auth CRL URL `http.Get` SSRF (`builtin/credential/cert/backend.go`)

`fetchCRL` calls `http.Get(crl.CDP.Url)` with admin-supplied `url` and no private-IP
controls. Failed the bar: requires privilege to write `auth/cert/crls` (trusted
operator SSRF), overlapping intentional admin egress patterns; weaker than ACME
SSRF already in the excluded set.

### 4. SSH `allowed_users_template` comma expansion

Templated `allowed_users` is split on `,` after render
(`builtin/logical/ssh/path_issue_sign.go`). Extra principals require an admin to
enable templating and map attacker-writable identity metadata — treated as
misconfiguration / intended template semantics, not a standalone vuln (distinct
from excluded CVE-2024-7594 empty-principals).

### 5. well_known_redirect `ResolveReference`

Already assessed as insufficient impact per task scope.

### 6. UI XSS

`sanitized-html` helper wraps DOMPurify/`sanitize` before `htmlSafe`. No
high-impact stored XSS with a clear unauthenticated or low-privilege path was
validated in `ui/` for this commit.

### 7. Command / plugin exec

`exec.Command` usages reviewed under `command/`, `sdk/helper/pluginutil`, and
helpers are admin/local-config or test-driven; no new remote command-injection
sink with attacker-controlled argv was validated beyond known audit RCE
(CVE-2025-6000).

---

## Search coverage (this pass)

| Area | Result |
|---|---|
| `plugins/database/*` DeleteUser / revoke SQL | **MSSQL novel High**; PG = CVE-2026-39946; Redshift/HANA excluded known |
| `exec.Command` / shell | No new remote RCE |
| Authz / identity / token | Known CVE-2025-5999 still present; no new bypass validated |
| SSRF (`http.Get` / `client.Do`) | Cert CRL admin SSRF near-miss; ACME excluded |
| Path traversal file IO | No new medium+ outside excluded audit issue |
| Templates / UI | SSH template near-miss; UI sanitization present |
| Plugin catalog | `..` rejected in command path |
|
