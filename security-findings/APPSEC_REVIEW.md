# Application Security Review — HashiCorp Vault

**Tree:** `0513545dd` (branch `cursor/application-security-review-959f`)  
**Scope:** `http/`, `vault/`, `builtin/`, `command/agent*`, `plugins/`, `sdk/`, plus UI OIDC route for open-redirect class  
**Method:** Static analysis with end-to-end path validation. Only issues with a concrete attacker → input → reachable code → impact chain are reported.

---

## Validated findings

### 1. Redshift `DeleteUser` SQL injection via `terminateloop` (High)

| Field | Detail |
|-------|--------|
| **Attacker** | Authenticated user who can read Redshift dynamic creds, with an auth username containing `'` (LDAP/Okta `login/(?P<username>.+)`) |
| **Controlled input** | Auth username → `DisplayName` → default `username_template` (`.DisplayName \| truncate 8`) → DB username |
| **API path** | `GET/POST database/creds/<redshift-role>` then lease revoke/expiry |
| **Impact** | Arbitrary SQL as the Vault Redshift connection principal during revoke |
| **Primary location** | `plugins/database/redshift/redshift.go` |

**Evidence:** Default revoke path builds a string-literal call without escaping, while nearby statements correctly use `QuoteIdentifier`:

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Username is fed from `req.DisplayName` in `builtin/logical/database/path_creds_create.go` (`UsernameConfig.DisplayName`). LDAP/Okta accept arbitrary username characters via `.+`.

**Attack sketch:** Login as LDAP user whose name places `'` in the first 8 chars of `ldap-<user>` (e.g. `x'aaaa`), request Redshift creds, revoke lease → `call terminateloop('v-ldap-x'…');` breaks out of the string literal.

---

### 2. HANA `DeleteUser` SQL injection via unquoted username (High)

| Field | Detail |
|-------|--------|
| **Attacker** | Same class as Finding 1 for a HANA-backed role |
| **Controlled input** | `DisplayName` (default template truncates to 32; only `-`→`_` and uppercasing) |
| **API path** | `database/creds/<hana-role>` → default revoke |
| **Impact** | SQL injection on revoke as Vault HANA connection user |
| **Primary location** | `plugins/database/hana/hana.go` |

**Evidence:**

```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

No identifier quoting. A `'` in the generated username closes/reopens SQL tokens.

---

### 3. MSSQL `DeleteUser` SQL injection via `dropUserSQL` (High)

| Field | Detail |
|-------|--------|
| **Attacker** | Authenticated user who can obtain MSSQL dynamic credentials with `'` or `]` in DisplayName |
| **Controlled input** | Dynamic username embedded into `dropUserSQL` via `fmt.Sprintf` |
| **API path** | `database/creds/<mssql-role>` → default (non-contained) revoke |
| **Impact** | SQL injection during revoke as Vault MSSQL connection user |
| **Primary location** | `plugins/database/mssql/mssql.go` |

**Evidence:**

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

Contrast: `dropLoginSQL` correctly uses `QuoteName` with parameters. Contained-DB revoke path also uses `QuoteName`.

---

### 4. PKI ACME http-01 / tls-alpn-01 challenge SSRF (High)

| Field | Detail |
|-------|--------|
| **Attacker** | Unauthenticated client when ACME is enabled and EAB is `not-required` (default); otherwise EAB token holder |
| **Controlled input** | ACME order identifier (DNS or IP); DNS A/AAAA; HTTP redirects (up to 10) |
| **API path** | `POST /v1/<pki>/acme/new-order` → challenge → `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge` |
| **Impact** | SSRF from the Vault host to loopback/RFC1918/link-local/cloud metadata; reachability oracle; redirect pivot |
| **Primary location** | `builtin/logical/pki/acme_challenges.go` |

**Evidence:** ACME paths are registered unauthenticated in `acme_wrappers.go`. IP identifiers are accepted in `path_acme_order.go`. Validator:

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// DialContext: no private/loopback rejection
	// CheckRedirect: up to 10 redirects, no IP re-validation
	resp, err := client.Get(path)
```

TLS-ALPN uses `InsecureSkipVerify: true` and dials attacker-controlled host:443. Enabling ACME is a normal PKI deployment step, not an attacker-only config; once on, any external party can trigger outbound requests.

---

### 5. Vault UI OIDC `prompt=none` open redirect (Medium)

| Field | Detail |
|-------|--------|
| **Attacker** | Remote attacker who can lure a victim browser to a crafted Vault UI URL |
| **Controlled input** | Query params `prompt` and `redirect_uri` |
| **API/UI path** | `/ui/vault/<cluster>/identity/oidc/provider/<name>/authorize?prompt=none&redirect_uri=https://evil…` |
| **Impact** | Open redirect off Vault’s origin for phishing / OAuth-looking error pages (`error=login_required`) |
| **Primary location** | `ui/app/routes/vault/cluster/oidc-provider.js` |

**Evidence:** Backend authorize validates `redirect_uri` against the client allow-list (`validRedirect` in `vault/identity_store_oidc_provider.go`). The UI short-circuits **before** that check when there is no session and `prompt=none`:

```36:40:ui/app/routes/vault/cluster/oidc-provider.js
    if (!currentToken && 'none' === qp.prompt?.toLowerCase()) {
      this._redirect(qp.redirect_uri, {
        state: qp.state,
        error: 'login_required',
      });
```

---

## Near-misses (failed the bar)

1. **Cert auth CRL URL SSRF** (`builtin/credential/cert/backend.go` `fetchCRL` → `http.Get(crl.CDP.Url)`): Real outbound fetch of attacker-chosen URL, but writing `auth/cert/crls/:name` with `url=` requires mount write (admin). No unauthenticated / low-priv escalation path.

2. **`.well-known` `ResolveReference` path escape** (`vault/well_known_redirect.go` `Destination`): Absolute or `../` `remaining` can rewrite outside the mount into other `/v1/...` paths (including across namespaces), but the rewritten request still goes through normal ACL/auth — no privilege bypass demonstrated on CE builtins.

3. **CORS `allowed_origins=*` reflecting Origin** (`http/cors.go` / `vault/cors.go`): Reflects request Origin when `*` is configured, but does not set `Access-Control-Allow-Credentials`; Vault auth is header-token based — no concrete cross-origin credential theft without a separate token oracle.
