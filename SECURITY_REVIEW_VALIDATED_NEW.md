# Independently Validated Findings (NEW)

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (1.18.0-beta1)  
**Scope:** Areas requested (DB plugins beyond HANA/Redshift, auth, identity/ACL templates, SSH/RabbitMQ/Consul/Nomad, sys/).  
**Explicitly excluded as already-known:** Redshift terminateloop SQLi, HANA revokeUserDefault SQLi, AWS AccountID cache, Raft bootstrap DoS, PKI ACME SSRF, userpass lockout/bcrypt enum, file-audit→plugin RCE.

**Method:** Static call-chain tracing + local rendering PoCs for ACL/`+` and DisplayName→SQL string construction. No live exploit against production DBs.

---

## DisplayName → username template (requested trace)

**Verdict: DisplayName is NOT sanitized before database username templates.**

1. Auth methods set `Auth.DisplayName` from login username (LDAP/Okta/userpass/etc.). LDAP/Okta use `login/(?P<username>.+)`.
2. `LoginCreateToken` only prepends the mount source; it does **not** run `displayNameSanitize`.
3. Contrast: token-create `display_name` **is** sanitized to `[a-zA-Z0-9-]` in `vault/token_store.go`.
4. `builtin/logical/database/path_creds_create.go` passes `req.DisplayName` straight into `UsernameConfig.DisplayName`.
5. DB plugins embed that value via default `username_template` (`truncate` only — no quote/wildcard stripping).

---

## Ranked validated findings

### 1. ACL identity templates allow segment-wildcard (`+`) privilege escalation

- **Severity:** High
- **Attacker:** Authenticated principal whose **entity name, alias name, or templated metadata value** can be set to `+` (or contain `/+`), while holding a templated ACL policy of the common form `path "SECRET/{{identity…}}/*"`. Practical writers of AppRole `role_id` (alias name = `role_id`) are a clear operator-boundary case; LDAP/Okta usernames matching `.+` are another.
- **Controlled input:** Identity attribute rendered by ACL templating (`identity.entity.name`, `identity.entity.aliases.<accessor>.name`, `identity.entity.metadata.<key>`, etc.).
- **Attack path:**
  1. Org publishes templated policy, e.g. `path "secret/data/{{identity.entity.aliases.auth_approle_XXX.name}}/*" { capabilities = ["create","read","update","delete","list"] }` (documented pattern).
  2. Attacker creates/updates an AppRole with `role_id=+` (only empty `role_id` is rejected) **or** authenticates with alias/entity value `+`.
  3. At request time `parseACLPolicyWithTemplating(..., performTemplating=true)` substitutes verbatim via `aclTemplateHandler` (no escaping of `+`/`*`).
  4. Rendered path `secret/data/+/*` sets `HasSegmentWildcards=true`. Wildcard validation that rejects bad `*` forms applies to **unauthenticated special paths / policy write on the raw template string**, not to post-substitution ACL compilation.
  5. Segment-wildcard matching grants the role’s capabilities on `secret/data/<any>/<any…>` (confirmed: matches `secret/data/foo/bar`, `secret/data/admin/root-creds`, `secret/data/a/b/c`).
- **Impact:** Cross-tenant / cross-path authorization bypass — access far beyond the intended per-identity prefix.
- **Location:** `vault/policy.go`
- **Evidence:**
  ```54:60:sdk/helper/identitytpl/templating.go
  func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
  	switch t := v.(type) {
  	case string:
  		if t == "" {
  			return "", ErrTemplateValueNotFound
  		}
  		return t, nil
  ```
  ```415:427:vault/policy.go
  		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
  			pc.HasSegmentWildcards = true
  		}

  		if strings.HasSuffix(pc.Path, "*") {
  			if !pc.HasSegmentWildcards {
  				pc.Path = strings.TrimSuffix(pc.Path, "*")
  				pc.IsPrefix = true
  			}
  		}
  ```
  ```1603:1614:builtin/credential/approle/path_role.go
  	if roleIDRaw, ok := data.GetOk("role_id"); ok {
  		role.RoleID = roleIDRaw.(string)
  	} else if req.Operation == logical.CreateOperation {
  		// ...
  	}
  	if role.RoleID == "" {
  		return logical.ErrorResponse("invalid role_id supplied, or failed to generate a role_id"), nil
  	}
  ```
  Alias name = `role.RoleID` at login (`builtin/credential/approle/path_login.go`).
- **Confidence:** High
- **Why not FP / requirements:** Requires templated ACLs (common) **and** attacker influence over a rendered identity field. Not “root can write any policy.” AppRole `role_id=+` is accepted without charset checks. Local rendering PoC produced `secret/data/+/*` with `segWC=true` and matcher returned true for privileged-looking paths.

---

### 2. MySQL database plugin — SQL injection via unsanitized DisplayName in usernames (default revoke + documented creation statements)

- **Severity:** High
- **Attacker:** Low-privilege Vault user who can `read database/creds/<role>` and authenticates with a DisplayName containing `'` (realistic LDAP/Okta usernames such as `o'brien`; LDAP/Okta login paths accept `.+`).
- **Controlled input:** Auth `DisplayName` → default username template (truncate 10 still keeps `'` for `ldap-o'brien`).
- **Attack path:**
  1. Login (LDAP/Okta) → `DisplayName` set from raw username; **not** passed through `displayNameSanitize`.
  2. `path_creds_create.go` copies `req.DisplayName` into `UsernameConfig`.
  3. MySQL `NewUser` builds username from template; documented creation statements use `'{{name}}'` / `'{{password}}'` via `QueryHelper` / prepare-then-exec of **already interpolated** SQL.
  4. On lease revoke with empty custom revocation statements, default path does string replace of `{{name}}` into `DROP USER '{{name}}'@'%'`.
  5. Username `v-ldap-o'bri-…` breaks out of the SQL string literal → attacker-influenced SQL as the Vault MySQL connection user.
- **Impact:** SQL injection against the managed MySQL/MariaDB instance with Vault’s (typically privileged) DB credentials — create/drop users, read/modify data per grants.
- **Location:** `plugins/database/mysql/mysql.go`
- **Evidence:**
  ```21:24:plugins/database/mysql/mysql.go
  	defaultMysqlRevocationStmts = `
  		REVOKE ALL PRIVILEGES, GRANT OPTION FROM '{{name}}'@'%';
  		DROP USER '{{name}}'@'%'
  	`
  ```
  ```180:182:plugins/database/mysql/mysql.go
  			query = strings.ReplaceAll(query, "{{name}}", req.Username)
  			query = strings.ReplaceAll(query, "{{username}}", req.Username)
  			_, err = tx.ExecContext(ctx, query)
  ```
  ```125:128:builtin/logical/database/path_creds_create.go
  		newUserReq := v5.NewUserRequest{
  			UsernameConfig: v5.UsernameMetadata{
  				DisplayName: req.DisplayName,
  ```
  ```100:101:vault/token_store.go
  	// displayNameSanitize is used to sanitize a display name given to a token.
  	displayNameSanitize = regexp.MustCompile("[^a-zA-Z0-9-]")
  ```
  (Applied only on token-create `display_name`, not auth DisplayName → DB path.)
- **Confidence:** High
- **Why not FP / requirements:** Not “admin wrote arbitrary SQL.” Default revoke + HashiCorp-documented creation statement shapes are the vulnerable sinks. Needs MySQL plugin role + auth username that embeds `'`. Truncation does **not** remove quotes when they fall inside the DisplayName window (`ldap-o'brien` → trunc10 `ldap-o'bri`). Same class as known HANA/Redshift, but **different plugins**.

---

### 3. MSSQL database plugin — SQL injection in default `dropUserSQL` (and `[{{name}}]` creation statements)

- **Severity:** High
- **Attacker:** Same as #2 against an MSSQL-backed database role (DisplayName / username with `'` or `]`).
- **Controlled input:** Generated username (DisplayName in default template, truncate 20).
- **Attack path:**
  1. Creds create embeds DisplayName into username (no sanitization).
  2. Documented/test creation statements: `CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';` — `]` in username breaks bracket quoting at create time.
  3. Default revoke (`revokeUserDefault`) builds per-DB drop via `fmt.Sprintf(dropUserSQL, dbName, username, username)` **without** `QuoteName` for the username in `WHERE name = N'%s'` / `DROP USER [%s]` (contrast: login disable/drop paths correctly use `QuoteName(@username)`).
- **Impact:** SQL injection as Vault’s MSSQL login on create and/or revoke — potentially stacked statements depending on driver/server settings; at minimum statement breakout / unintended DROP USER targets.
- **Location:** `plugins/database/mssql/mssql.go`
- **Evidence:**
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
  Safe contrast in the same file (`dropLoginSQL` uses `QuoteName(@username)`). Tests/docs use `CREATE LOGIN [{{name}}]` (`plugins/database/mssql/mssql_test.go`).
- **Confidence:** High
- **Why not FP / requirements:** Default revoke path is vulnerable without custom statements. `'` in LDAP-style DisplayNames is realistic; `]` enables bracket breakout. Contained-DB path uses `QuoteName` and is safer — non-contained default is the issue.

---

### 4. Cassandra / InfluxDB — same DisplayName→username CQL/IFQL injection on default statements

- **Severity:** High (Cassandra default create+delete; InfluxDB default create+delete)
- **Attacker:** Creds reader with quote-bearing DisplayName, as in #2.
- **Controlled input:** Username from template (`DisplayName | truncate 15`, plus replace `-`→`_` for Cassandra — does **not** strip `'` / `"`).
- **Attack path:** `NewUser` / `DeleteUser` run `dbutil.QueryHelper` substituting `{{username}}` into defaults:
  - Cassandra: `CREATE USER '{{username}}' …` / `DROP USER '{{username}}';`
  - InfluxDB: `CREATE USER "{{username}}" WITH PASSWORD '{{password}}';` / drop equivalent
- **Impact:** Injection as Vault’s DB admin connection on create and revoke.
- **Location:** `plugins/database/cassandra/cassandra.go` (InfluxDB sibling: `plugins/database/influxdb/influxdb.go`)
- **Evidence:**
  ```20:22:plugins/database/cassandra/cassandra.go
  	defaultUserCreationCQL   = `CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER;`
  	defaultUserDeletionCQL   = `DROP USER '{{username}}';`
  	defaultChangePasswordCQL = `ALTER USER '{{username}}' WITH PASSWORD '{{password}}';`
  ```
  Substitution via `dbutil.QueryHelper` in `NewUser`/`DeleteUser` (no identifier escaping).
- **Confidence:** High
- **Why not FP / requirements:** Defaults are vulnerable (no admin custom statements required for Cassandra/InfluxDB). Same DisplayName root cause as #2/#3; separate engines from known HANA/Redshift.

---

### 5. PostgreSQL — SQL injection via documented `"{{name}}"` creation statements + unsanitized DisplayName

- **Severity:** Medium
- **Attacker:** Creds reader whose DisplayName can introduce `"` into the generated username (less common than `'`, but unsanitized).
- **Controlled input:** DisplayName → default template (truncate 8) → `QueryHelper` into role `creation_statements`.
- **Attack path:** Docs recommend `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' …`. Username with `"` breaks out of identifier quotes. Default **revoke** correctly uses `dbutil.QuoteIdentifier` (safer than MySQL/MSSQL/Cassandra defaults).
- **Impact:** SQLi at user creation time as Vault’s Postgres role.
- **Location:** `plugins/database/postgresql/postgresql.go` (sink is `QueryHelper` on creation statements; docs shape is the exploit requirement)
- **Evidence:** `NewUser` maps `name`/`username` through `dbtxn.ExecuteTxQueryDirect` → `parseQuery` string replace; website docs `creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}'…"`. DisplayName unsanitized as in trace above.
- **Confidence:** Medium-High
- **Why not FP / requirements:** Needs documented quote style (near-universal) **and** a `"` in the username window. Default revoke alone is **not** enough for Postgres (quoted). Rated below MySQL/MSSQL/Cassandra because `'` alone does not break `"…"` identifiers.

---

## Areas reviewed without new medium+ validated findings

| Area | Result |
|------|--------|
| MongoDB | Username passed as BSON command field (driver-encoded); no string-SQL sink like above |
| GitHub Name vs Slug dual maps | Present; treated as already-known candidate — not re-filed |
| Okta MFA / LDAP / cert OCSP fail-open / AppRole bind | OCSP fail-open is explicit admin config; no new MFA alias bypass defended beyond known list |
| SSH host/user templates | Templating exists; `allowed_users == "*"` check is on raw config; metadata→comma-list escalation needs identity write — not clearly low-priv |
| RabbitMQ | Default username uses full DisplayName; client `url.PathEscape`s username — no path-injection finding |
| Consul / Nomad | DisplayName only in token description strings |
| sys/ CRL URL fetch | `http.Get` on admin-configured CRL URL — admin trust boundary |
| Fork deltas | No custom security-relevant forks beyond stock 1.18.0-beta1 tree |

---

## Ranking summary

| Rank | Title | Severity | Confidence |
|------|-------|----------|------------|
| 1 | ACL identity template `+` segment-wildcard escalation | High | High |
| 2 | MySQL DisplayName/username SQLi (default revoke + docs create) | High | High |
| 3 | MSSQL `dropUserSQL` / `[{{name}}]` SQLi | High | High |
| 4 | Cassandra/InfluxDB default statement SQLi via DisplayName | High | High |
| 5 | Postgres documented `"{{name}}"` create SQLi via DisplayName | Medium | Medium-High |
