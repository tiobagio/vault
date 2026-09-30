# Application Security Review — Vault `0513545dd`

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`version/VERSION` = `1.18.0-beta1`)  
**Branch:** `cursor/application-security-review-9480`  
**Method:** Static analysis (grep + code reading) focused on SQL construction, template injection, deserialization, secret leakage, plugin loading, CORS, and open redirects. Only issues with concrete end-to-end attack paths are reported.

---

## Finding 1 — Redshift `DeleteUser` SQL injection via `terminateloop`

**Severity:** high  
**Attacker:** Authenticated Vault user who can request Redshift dynamic credentials (and whose auth DisplayName can contain `'`), e.g. LDAP/Okta login username matching `(?P<username>.+)`.  
**controlled_input:** Username derived from `req.DisplayName` via default `username_template` (`(.DisplayName | truncate 8)`), later passed into revoke SQL.  
**attack_path:**
1. Authenticate via LDAP/Okta with a username that keeps a single quote after truncation (e.g. mount `ldap/` → DisplayName `ldap-x'`).
2. Read `database/creds/<redshift-role>` so Vault creates a login whose name contains `'`.
3. On lease revoke/expiry, `defaultDeleteUser` builds `call terminateloop('<username>');` with string interpolation (no `QuoteIdentifier` / literal escaping).
4. Attacker-controlled quote breaks out of the SQL string literal executed as the Vault DB connection user.

**impact:** Arbitrary SQL execution during revoke as the Vault Redshift connection principal (often highly privileged): terminate other sessions, DDL/DML per grants, disrupt credential lifecycle.  
**location:** `plugins/database/redshift/redshift.go`  

**evidence:**
```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```
Nearby revoke statements correctly use `dbutil.QuoteIdentifier(username)`; this call does not. LDAP login accepts arbitrary username characters:
```18:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

**remediation:** Escape the username as a SQL string literal (e.g. `quoteLiteral(username)` / doubled quotes) before embedding, or pass a bound parameter into a procedure call that does not concatenate identifiers.

---

## Finding 2 — HANA `DeleteUser` SQL injection via unquoted username

**Severity:** high  
**Attacker:** Same class as Finding 1 for a HANA-backed database role.  
**controlled_input:** `req.Username` from dynamic credential generation (default template includes DisplayName truncated to 32 chars; only `-`→`_` and uppercasing are applied).  
**attack_path:**
1. Obtain a token whose DisplayName carries SQL metacharacters (LDAP/Okta `.+` usernames).
2. Request HANA dynamic credentials; created username retains metacharacters.
3. Lease revoke with empty custom revoke statements hits `revokeUserDefault`.
4. Username is interpolated into `ALTER USER %s` / `DROP USER %s` without quoting.

**impact:** SQL injection as the Vault HANA connection user on revoke (disable/drop unintended users; broader DDL/DML depending on privileges).  
**location:** `plugins/database/hana/hana.go`  

**evidence:**
```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

**remediation:** Quote the identifier with a HANA-safe quoter (or reject usernames outside a strict charset before create/revoke). Prefer parameterized APIs where available.

---

## Finding 3 — MSSQL `DeleteUser` SQL injection via `dropUserSQL`

**Severity:** high  
**Attacker:** Authenticated user who can obtain MSSQL dynamic credentials with a DisplayName containing `'` or `]` (LDAP/Okta).  
**controlled_input:** Dynamic username embedded into `dropUserSQL` via `fmt.Sprintf`.  
**attack_path:**
1. Login so DisplayName includes `'` or `]` (default template truncates DisplayName to 20 chars — enough to retain the metacharacter).
2. Request MSSQL creds; on revoke, `revokeUserDefault` enumerates DB mappings and builds:
   - `WHERE name = N'<username>'`
   - `DROP USER [<username>]`
3. Quote/`]` breakout yields attacker-controlled SQL executed by Vault’s MSSQL connection.

**impact:** SQL injection during revoke as the Vault MSSQL connection user.  
**location:** `plugins/database/mssql/mssql.go`  

**evidence:**
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
(Contrast: `dropLoginSQL` correctly uses `QuoteName` with parameters.)

**remediation:** Build DROP USER statements with `QuoteName` / parameterized dynamic SQL (as already done for login drop), never `fmt.Sprintf` of N'...' / `[...]` with raw usernames.

---

## Finding 4 — PKI ACME http-01 / tls-alpn-01 challenge SSRF

**Severity:** high  
**Attacker:** Anyone who can complete ACME flows against a PKI mount with ACME enabled (unauthenticated when `eab_policy` is `not-required`; otherwise holder of an EAB token). Must control DNS (or redirect) for the ordered identifier.  
**controlled_input:** ACME identifier / DNS resolution (and HTTP redirects up to 10).  
**attack_path:**
1. Enable ACME on a PKI mount (common automation setup).
2. Create an ACME order for a domain the attacker controls.
3. Point DNS A/AAAA (or an http-01 redirect) at an internal target (`127.0.0.1`, RFC1918, `169.254.169.254`, link-local).
4. Vault’s validator dials that target from the Vault host with no private/loopback filtering; TLS uses `InsecureSkipVerify: true` for ALPN.

**impact:** Server-side request forgery from the Vault node into localhost/cloud-metadata/internal services; reachability oracle and potential limited response probing via challenge errors.  
**location:** `builtin/logical/pki/acme_challenges.go`  

**evidence:**
```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	DialContext:           dialer.DialContext,
	// CheckRedirect allows up to 10 redirects with no IP family checks
	resp, err := client.Get(path)
```
`buildDialerConfig` only sets timeout/resolver — no rejection of loopback, private, or link-local addresses.

**remediation:** Resolve and validate destination IPs before dial (block loopback, unspecified, link-local, multicast, and private ranges unless explicitly allowed); apply the same checks on redirect targets; prefer a custom `DialContext` that enforces the policy.

---

## Finding 5 — Vault UI OIDC provider open redirect via `prompt=none`

**Severity:** medium  
**Attacker:** Unauthenticated remote attacker who can lure a victim browser to a crafted Vault UI URL (phishing).  
**controlled_input:** Query parameters `prompt` and `redirect_uri` on the UI OIDC authorize route.  
**attack_path:**
1. Victim opens (or is redirected to)  
   `/ui/vault/<cluster>/identity/oidc/provider/<any>/authorize?prompt=none&redirect_uri=https://evil.example/phish&state=...`
2. If the victim has no Vault UI session token, `beforeModel` runs **before** calling the authorize API and never checks the client’s configured `redirect_uris` allow-list.
3. UI executes `window.location.replace` to the attacker-supplied `redirect_uri` with `error=login_required` and the provided `state`.

**impact:** Open redirect abusing Vault’s trusted origin for phishing / OAuth-looking error pages. Backend authorize correctly validates `redirect_uri`, but this UI short-circuit bypasses that check.  
**location:** `ui/app/routes/vault/cluster/oidc-provider.js`  

**evidence:**
```36:40:ui/app/routes/vault/cluster/oidc-provider.js
    if (!currentToken && 'none' === qp.prompt?.toLowerCase()) {
      this._redirect(qp.redirect_uri, {
        state: qp.state,
        error: 'login_required',
      });
```
`_redirect` → `_buildUrl` → `location.replace` with no allow-list. Server-side validation only happens later in `model()` via the authorize API.

**remediation:** Do not client-redirect to `redirect_uri` until the authorize API has validated it (or only redirect to a fixed Vault error page). For `prompt=none` without a session, render an error in-UI or call authorize and honor only server-validated redirect behavior.

---

## Near-misses (not reported)

| Topic | Why not reported |
|-------|------------------|
| CORS `allowed_origins=*` reflecting Origin | No `Access-Control-Allow-Credentials`; Vault API auth is header-token based — no concrete credential-theft path without a separate token oracle. |
| `.well-known` `ResolveReference` `../` rewrite | Can rewrite outside mount prefix to other `/v1/...` paths, but authorization still applies; CE builtins rarely register redirects. |
| LDAP `text/template` filters | Admin-configured; username values are `ldap.EscapeFilter`’d; no dangerous FuncMap. |
| Plugin catalog / checksum | Registration requires privileged `sys/plugins` access; checksum verification present for runners. |
| Custom message `javascript:` links | Requires privileged custom-message write; treated as trusted-admin content without clear lower-privilege path. |
