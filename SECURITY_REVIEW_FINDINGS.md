# Security Review Findings

Excluded (already validated elsewhere): ACME http-01 SSRF; UI custom-message href XSS.

## Finding 1 — Agent/Proxy auto-auth token sanitization bypass

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Location** | `command/agentproxyshared/cache/handler.go` (`sanitizeAutoAuthTokenResponse`) |
| **Attacker** | Any client that can reach a Vault Agent or Proxy listener configured with `use_auto_auth_token` / `force` |
| **Controlled input** | JSON body of `POST /v1/auth/token/lookup` (omit `token`, or set `"token": null`) |
| **Key functions** | `sanitizeAutoAuthTokenResponse`, `ProxyHandler`, `TokenStore.handleLookup` |

### Reachability

1. Agent/Proxy runs with auto-auth and `api_proxy.use_auto_auth_token = true` (or `force`).
2. Auto-auth token policy allows `auth/token/lookup` (common on tokens that also create/manage tokens; **not** granted by the built-in `default` policy alone).
3. Attacker (often localhost / sidecar network) sends:
   ```http
   POST /v1/auth/token/lookup
   Content-Type: application/json

   {}
   ```
   or `{"token": null}`  
   without `X-Vault-Token` (Agent injects the auto-auth token).
4. `sanitizeAutoAuthTokenResponse` treats a missing/non-string `token` as “input error, skip redaction” and returns without stripping.
5. Vault `handleLookup` falls back to `req.ClientToken` when the token field is empty and returns `data.id` / `data.accessor` (the auto-auth token).

### Impact

Disclosure of the long-lived auto-auth token (and accessor) that Agent intentionally redacts on `lookup-self` / `lookup`+empty-string. Enables direct Vault API use outside the Agent, persistence beyond Agent process lifetime (until lease expiry/revoke), and bypass of Agent-only network exposure assumptions.

### Root cause

```165:183:command/agentproxyshared/cache/handler.go
	case vaultPathTokenLookup, vaultPathTokenRenew:
		jsonBody := map[string]interface{}{}
		if err := json.Unmarshal(req.RequestBody, &jsonBody); err != nil {
			return err
		}
		tokenRaw, ok := jsonBody["token"]
		if !ok {
			// Input error will be caught by the API
			return nil
		}
		token, ok := tokenRaw.(string)
		if !ok {
			// Input error will be caught by the API
			return nil
		}
```

Vault does **not** treat missing/null token on `lookup` as an error; it uses the client token:

```3341:3348:vault/token_store.go
func (ts *TokenStore) handleLookup(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	id := data.Get("token").(string)
	if id == "" {
		id = req.ClientToken
	}
```

Note: `{"token":""}` **is** redacted; the gap is missing key / non-string JSON values.

---

## Areas checked without a defendable medium+ E2E finding

| Area | Result |
| --- | --- |
| `builtin/credential/*` (userpass, approle, aws, cert, github, ldap, okta, radius, token) | No additional unauth/low-priv medium+ path beyond known patterns; GitHub org TOFU, Okta `verify/*` number challenge, AWS STS proxying reviewed |
| `http/handler.go` wrapping / raw / recovery | Wrapping unwrap/lookup behavior as designed; `/sys/raw` recovery-token gated |
| `vault/` identity merge, entity upsert merge, request routing | Merge APIs privileged; auto-merge on alias upsert not attacker-driven without colliding authenticated aliases |
| Agent/Proxy SSRF | Auto-auth metadata callers use fixed IMDS URLs; API proxy forwards to configured Vault address; `X-Vault-Request` optional but separate from this finding |
| Audit devices | Secrets HMAC’d unless admin sets `log_raw` / non-HMAC keys (config footgun, not unauth bug) |
| `plugins/database` + `sdk/helper/dbtxn` QueryHelper | Unescaped `{{username}}`/`{{password}}` substitution; default username templates + transactions limit practical injection from LDAP `DisplayName`; treated as footgun without clean default-config RCE/priv-esc |
| `sdk/helper/ldaputil` / `cap/ldap` | `getUserDN` still uses DN-value escaping (`escapeValue`/`EscapeLDAPValue`) inside a **filter** when `UPNDomain` is set — wrong escaping vs `EscapeFilter`, but needs a username that both binds successfully and contains filter metacharacters; no clean unauth/low-priv E2E proven here |
| Namespace escape / Approle secret-id IDOR / token orphaning | Accessor lookups scoped by role HMAC prefix; orphan create requires sudo/`create-orphan` ACL |

---

*Review branch: `cursor/application-security-review-4f0b`*
