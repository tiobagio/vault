# Validation: CVE-2026-4525 + LDAP DisplayName SQLi @ 0513545dd

Tree: commit `0513545dd` (VERSION `1.18.0-beta1`). Branch used for review only.

---

## 1) CVE-2026-4525 / HCSEC-2026-07 — Authorization passthrough token leak

### Verdict: **INVALID** at this commit (not exploitable)

| Field | Value |
| --- | --- |
| Severity | N/A (CVE class is High/CVSS 7.5 upstream; absent here) |
| Attacker | Would need: admin-configured `passthrough_request_headers` including `Authorization`, plus a client that authenticates with `Authorization: Bearer <vault-token>` against a mount that forwards headers |
| Input | `Authorization: Bearer <vault-token>` (and mount passthrough list) |
| Path | HTTP → `requestAuth`/`getTokenFromReq` → `Core.CheckToken` header scrub → `Router.routeCommon` `filteredHeaders` → auth/secret plugin |
| Impact | Upstream: Vault client token exposed to plugin backend (credential theft / plugin abuse). **At this commit the Authz-sourced Bearer is stripped before forward.** |
| Primary location | `vault/request_handling.go:400-413` |

### Evidence

**Auth source selection** (`http/handler.go:1158-1186`):

- `X-Vault-Token` wins if present → `ClientTokenFromVaultHeader`
- Else first `Authorization: Bearer …` → `ClientTokenFromAuthzHeader`

**Scrub before route** (`vault/request_handling.go:400-413` at 0513545dd):

```go
switch req.ClientTokenSource {
case logical.ClientTokenFromVaultHeader:
    delete(req.Headers, consts.AuthHeaderName)
case logical.ClientTokenFromAuthzHeader:
    // drops every "Bearer …" value from Authorization
}
```

When the Vault token is taken from `Authorization`, Bearer values are removed before `Router` applies passthrough. `deniedPassthroughRequestHeaders` only denylists `X-Vault-Token` (`vault/router.go:25-27`); `Authorization` may pass through **after** scrubbing (intentional for SPIFFE/JWT-SVID-style mounts).

**Upstream CVE shape (for contrast):** v1.21.0 introduced a broken guard

`ClientTokenFromAuthzHeader && !unauth && te == nil`

which skipped scrubbing for successful Authz auth and for login-with-valid-token. Fixed in 1.21.5 / 2.0.0 to `(!unauth || te != nil)` (commit `9569be61`). That regression is **not** in 0513545dd.

### Residual (out of CVE precondition)

If the client authenticates with `X-Vault-Token` **and also** sends `Authorization: Bearer <vault-token>`, only `X-Vault-Token` is deleted; the Bearer can still be passthrough-forwarded. CVE text requires Authorization *used to authenticate*, so this residual is related but not the CVE.

---

## 2) LDAP DisplayName → database username template SQL injection

### Verdict: **VALID** (realistic with conditions)

| Field | Value |
| --- | --- |
| Severity | **High** if `username_template` embeds raw/`lightly truncated` `.DisplayName` into quoted SQL; **Medium** with stock DB defaults (truncate 8–10 still preserves `'`/`"`) |
| Attacker | LDAP user whose login username/CN contains SQL metacharacters, with ACL allowing `read` on `database/creds/<role>` |
| Input | Login path username (`auth/ldap/login/<username>`), later used as token `DisplayName`; flows into DB username template then `{{name}}`/`{{username}}` in `creation_statements` |
| Path | LDAP `pathLogin` → `LoginCreateToken`/`RegisterAuth` (no sanitize) → `database/creds` `path_creds_create` → plugin `NewUser` → `dbtxn.parseQuery` raw `strings.ReplaceAll` |
| Impact | SQL executed as the Vault database plugin connection user (create/alter/drop/etc. per statements + breakout) |
| Primary location | `builtin/logical/database/path_creds_create.go:125-128` (DisplayName sink into username metadata) |

### Evidence

1. LDAP sets unsanitized path username as DisplayName:

```97:97:builtin/credential/ldap/path_login.go
		DisplayName: username,
```

Pattern allows rich usernames: `login/(?P<username>.+)` (`path_login.go:18`).

2. Login token creation prepends mount source but does **not** apply `displayNameSanitize` (that regex is only for `auth/token/create`’s `display_name` field in `vault/token_store.go:100-101,2840-2844`):

```2015:2016:vault/request_handling.go
	// Prepend the source to the display name
	auth.DisplayName = strings.TrimSuffix(source+auth.DisplayName, "-")
```

```2389:2392:vault/request_handling.go
	te := logical.TokenEntry{
		Path:           path,
		Meta:           auth.Metadata,
		DisplayName:    auth.DisplayName,
```

3. Creds creation forwards token DisplayName into the DB plugin username config:

```125:128:builtin/logical/database/path_creds_create.go
		newUserReq := v5.NewUserRequest{
			UsernameConfig: v5.UsernameMetadata{
				DisplayName: req.DisplayName,
				RoleName:    name,
```

4. Statements substitute without identifier/literal quoting:

```77:85:sdk/helper/dbtxn/dbtxn.go
func parseQuery(m map[string]string, tpl string) string {
	// ...
	for k, v := range m {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

Stock Postgres template still interpolates truncated DisplayName into roles like `CREATE`/`ALTER ROLE "{{name}}"` (`plugins/database/postgresql/postgresql.go:36`, statements using `{{name}}`). Truncate does not strip quotes.

Later fixed upstream (changelog): *“Sanitize the caller-controlled DisplayName before it is used in generated usernames…”* — absent here.

### Realism notes

- Requires an LDAP account that can authenticate with a username containing `'` / `"` (or URL-encoded equivalent in the login path) **and** `database/creds` access.
- Full reliable breakout is easiest when an operator sets a custom `username_template` that heavily/unbounded-embeds `.DisplayName` (common in the wild). Default templates reduce free payload length but do not neutralize metacharacters.
