# Application Security Review — Pass 2 (non–skip-listed surfaces)

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-1cc6`  
**Criterion:** Validated medium+ with end-to-end attack paths only. Skip-listed classes (Postgres/MySQL/MSSQL/HANA/Redshift/InfluxDB quote-breakout SQLi; ACL `+`/`*` template injection; Okta/LDAP `username_as_alias` MFA bypass; TOTP reuse; generate-root/rekey DoS; cert OCSP fail-open; known PKI ACME HTTP-01 SSRF) were not re-validated.

---

## Finding 1 — Elasticsearch static-role `path.Join` username path traversal → arbitrary user password reset

| Field | Value |
| --- | --- |
| **Title** | Elasticsearch database plugin: static-role `username` path traversal via `path.Join` retargets `_password` API |
| **Severity** | **High** |
| **Location** | Module `github.com/hashicorp/vault-plugin-database-elasticsearch v0.15.0` (pinned in `go.mod` L142): `client.go` `ChangePassword` / `CreateUser` / `DeleteUser` / `CreateRole` / `DeleteRole`; Vault wiring in `builtin/logical/database/path_roles.go` + `rotation.go` |
| **Attacker** | Authenticated Vault principal with `create`/`update` on `database/static-roles/*` for an Elasticsearch connection (delegated DB onboarding; not Vault root). Needs read on `database/static-creds/<role>` (or wait for rotation) to obtain the new password. |
| **Controlled input** | Static-role `username` — `framework.TypeString` with **no** path/identity sanitization (`builtin/logical/database/path_roles.go` ~191–195) |
| **Reachability** | Create/update static role → `setStaticAccount` → `UpdateUserRequest{Username: role.StaticAccount.Username}` (`rotation.go` ~409–410, ~525) → plugin `UpdateUser` → `Client.ChangePassword` |
| **Impact** | Vault’s privileged Elasticsearch management credentials are used to **set the password of an arbitrary ES security principal** (e.g. `elastic`, another app user). Attacker then authenticates to Elasticsearch as that victim with the Vault-rotated password returned via `database/static-creds/<role>`. |

### Root cause

`ChangePassword` builds the REST path with Go’s `path.Join`, which **cleans** `..` segments:

```183:196:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-database-elasticsearch@v0.15.0/client.go
func (c *Client) ChangePassword(ctx context.Context, name, newPassword string) error {
	endpoint := path.Join(c.securityPath, "user", name, "_password")
	method := http.MethodPost

	pwdChangeBodyJson, err := json.Marshal(map[string]string{"password": newPassword})
	// ...
	req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewReader(pwdChangeBodyJson))
```

Same pattern in `CreateUser` / `DeleteUser` / role APIs (`client.go` ~119–207): `path.Join(c.securityPath, "user"|"role", name, ...)`.

There is no `url.PathEscape` / allowlist on `name`.

### Attack path

1. Operator configures `database/config/<conn>` with `elasticsearch-database-plugin` and a management user that can call `/_security/user/*/_password`.
2. Attacker creates a static role:

   ```hcl
   # username deliberately traverses out of /_security/user/<literal>/_password
   username            = "../user/victim"
   rotation_period     = "24h"
   db_name             = "<conn>"
   ```

3. On create/rotate, Vault generates a password and calls `ChangePassword(ctx, "../user/victim", newPassword)`.
4. `path.Join("/_security", "user", "../user/victim", "_password")` → `/_security/user/victim/_password`.
5. Elasticsearch accepts `POST /_security/user/victim/_password` with body `{"password":"<vault-secret>"}` using the **management** Basic Auth from the connection config.
6. Attacker reads `database/static-creds/<role>` and logs into Elasticsearch as `victim` with that password.

Variants (same sink class):

| Static-role username | Resulting path | Effect |
| --- | --- | --- |
| `../user/victim` | `/_security/user/victim/_password` | Reset victim password (primary) |
| `../user/elastic` on DeleteUser | `/_security/user/elastic` | Delete privileged user (if DeleteUser ever invoked with that name) |
| `../../_cluster/settings` | `/_cluster/settings` | Path escapes security API entirely (POST body still password JSON — DoS/misconfig risk depending on ES route) |

### Evidence (validated at this commit)

Mirror of `Client.ChangePassword` against `httptest`:

```
endpoint after path.Join: /_security/user/victim/_password
ES saw: POST /_security/user/victim/_password body={"password":"VaultRotatedPassw0rd!"}
CONFIRMED: static-role username path traversal retargets ChangePassword
```

Vault accepts the username: static-role field is `TypeString` (not `TypeNameString`); printable-path checks apply to HTTP request paths, not JSON body fields.

### Why this is not skip-listed

This is **REST path traversal / confused-deputy password reset**, not SQL quote breakout. Elasticsearch was explicitly in-scope for “injection different from SQL quote breakout.”

### Fix direction

- Reject usernames containing `/`, `\`, `.`, or URL-encoded dots; or allowlist `[A-Za-z0-9_@.-]`.
- Build paths with `path.Join(securityPath, "user", url.PathEscape(name), "_password")` **after** rejecting separators (PathEscape alone does not neutralize `/`).
- Prefer ES client APIs that take a name parameter without string path concatenation.

---

## Finding 2 — Snowflake static-role default rotation: unquoted `{{name}}` enables comment-terminated password takeover

| Field | Value |
| --- | --- |
| **Title** | Snowflake database plugin: default `ALTER USER {{name}}` leaves identifier unquoted; static-role username injects SET/comment |
| **Severity** | **High** |
| **Location** | Module `github.com/hashicorp/vault-plugin-database-snowflake v0.11.0` (pinned in `go.mod` L146): `snowflake.go` defaults + `UpdateUser` / `updateUserCredential`; substitution in `sdk/helper/dbtxn/dbtxn.go` `parseQuery` |
| **Attacker** | Same model as Finding 1: `create`/`update` on `database/static-roles/*` for a Snowflake connection |
| **Controlled input** | Static-role `username` (`TypeString`) |
| **Reachability** | `setStaticAccount` → plugin `UpdateUser` → empty `rotation_statements` selects `defaultSnowflakeRotatePasswordSQL` → `ExecuteTxQueryDirect` / `parseQuery` ReplaceAll |
| **Impact** | Arbitrary single-statement Snowflake SQL as the Vault management role — specifically **set another user’s password** (and comment out Vault’s generated secret), then read it back via static-creds |

### Root cause

Default rotation SQL leaves `{{name}}` **unquoted**:

```30:32:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-database-snowflake@v0.11.0/snowflake.go
	defaultSnowflakeRotatePasswordSQL = `
alter user {{name}} set PASSWORD = '{{password}}';
`
```

When `req.Password.Statements.Commands` is empty, that default is used (`snowflake.go` ~255–258). Substitution is raw ReplaceAll:

```77:85:sdk/helper/dbtxn/dbtxn.go
func parseQuery(m map[string]string, tpl string) string {
	// ...
	for k, v := range m {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

Same unquoted `{{name}}` appears in default renew/delete SQL (`snowflake.go` ~27–37).

### Attack path

1. Configure Snowflake DB connection with a user that can `ALTER USER` broadly.
2. Create static role with:

   ```text
   username = victim set password = 'owned_by_attacker' --
   ```

   omit `rotation_statements` (or leave empty).

3. On rotation, rendered SQL:

   ```sql
   alter user victim set password = 'owned_by_attacker' -- set PASSWORD = 'vault-rotated-secret';
   ```

4. Snowflake applies password `owned_by_attacker` to `victim`; the Vault-generated clause is line-commented. Attacker authenticates to Snowflake as `victim`.

### Evidence (validated)

Substitution PoC mirroring `parseQuery` + default template:

```
Resulting SQL:
alter user victim set password = 'owned_by_attacker' -- set PASSWORD = 'vault-rotated-secret';

CONFIRMED: unquoted {{name}} enables comment-terminated password takeover SQL
```

### Why this is not skip-listed / not “quote breakout”

Skip list names Postgres/MySQL/MSSQL/HANA/Redshift/InfluxDB — **not** Snowflake. The injection is into an **unquoted identifier** slot plus `--` comment termination; it does **not** rely on breaking out of the `'{{password}}'` quotes. Password clause quotes remain intact; the attacker never opens them.

### Fix direction

- Always quote/escape identifiers (Snowflake double-quote + escape `"`); never concatenate raw `{{name}}`.
- Validate static-role usernames against an identifier allowlist before calling the plugin.
- Prefer parameterized/bound APIs where the driver supports them for `ALTER USER`.

---

## Areas reviewed without a second validated medium+ finding

| Area | Why it failed the bar |
| --- | --- |
| Agent/proxy lease cache cross-client leak | Static secret hits require `index.Tokens[token]` (`command/agentproxyshared/cache/lease_cache.go` ~260–269); capability manager drops tokens that lose read. No bypass found without already-authorized token. |
| Redis / Couchbase / MongoDB plugins | Redis `ACL SETUSER` / `DELUSER` pass username as a separate RESP argument (`radix.Cmd`); Couchbase/Mongo use SDK APIs — no string-concat path/SQL sink analogous to ES/Snowflake. |
| Cassandra CQL comment / multi-stmt | `--` / multi-statement breakouts did not yield a reliable E2E password takeover under the driver/server constraints exercised previously. |
| rabbitmq / consul / nomad / ssh / transit / aws secrets | No `os/exec` sinks with attacker-controlled shell strings; Rabbit/Consul/Nomad use HTTP/API clients; SSH OTP/sign paths validate usernames against role allowlists. |
| JWT / userpass / GitHub / cloud auth | No new auth-bypass path defended end-to-end beyond skip-listed MFA classes. |
| `http/handler.go` CORS / X-Forwarded-For / raw forward | CORS wrapper and forwarded-for handling are listener-config gated; no unauthenticated origin reflection + credential theft path validated. |
| UI stored XSS (custom messages / OIDC) | Prior review: custom-message body escaped; `link.href` scheme gap requires privileged `sys/config/ui/custom-messages` — not lower-priv stored XSS. Reconfirmed no `htmlSafe`/raw markdown render of API message body in CE UI paths checked. |
| Sys endpoint authz gaps | No additional unauthenticated or capability-bypass on `logical_system*` beyond skip-listed generate-root/rekey DoS. |

---

## Summary

Two new High findings outside the skip list:

1. **Elasticsearch `path.Join` username traversal** — static-role username `../user/<victim>` retargets password rotation onto another ES user (proven with httptest mirror of `ChangePassword`).
2. **Snowflake unquoted `{{name}}`** — static-role username injects `SET PASSWORD` + `--` comment without quote breakout (proven via `parseQuery` substitution of the default rotate SQL).

Both share the same attacker model as the documented MySQL static-role issue: delegated `database/static-roles` writers abusing Vault’s privileged DB connector as a confused deputy against other accounts in the external system.
