# Novel Application-Security Review Findings

**Tree:** `0513545dd` / `version/VERSION` = `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-71e7`  
**Scope:** Independent review for novel medium/high/critical issues with end-to-end attack paths.  
**Excluded known CVEs (not re-reported):** CVE-2025-6000, CVE-2025-5999, CVE-2024-7594, CVE-2025-11621, CVE-2025-6037, CVE-2025-6013, CVE-2025-6014, CVE-2025-6015, CVE-2025-6004, CVE-2025-6011.

**Method:** Static ripgrep/pattern review + reachability analysis. No exploit PoC execution.

---

## Verdict summary

| # | Finding | Status | Severity |
|---|---------|--------|----------|
| 1 | Redshift `DeleteUser` SQL injection via unsanitized username in `terminateloop` call | **STILL_VULNERABLE** | High |
| 2 | HANA `DeleteUser` SQL injection via unquoted username in `ALTER`/`DROP USER` | **STILL_VULNERABLE** | High |
| 3 | PKI ACME http-01 / tls-alpn-01 validation SSRF (no local-target rejection) | **STILL_VULNERABLE** | Medium–High |

Upstream later fixed #1 and #2 under internal ticket **VAULT-43691** (no public CVE in the exclusion list). #3 matches public **CVE-2026-5052** (also outside the exclusion list) and remains unpatched in this tree.

---

## 1. Redshift `DeleteUser` SQL injection — STILL_VULNERABLE

**Severity:** High  
**Primary location:** `plugins/database/redshift/redshift.go` (`defaultDeleteUser`)

### Attacker
Authenticated Vault principal able to obtain (and later revoke) dynamic Redshift credentials, **or** an operator who can set a static-role / generated username containing SQL metacharacters.

Strongest low-privilege path: LDAP (or any auth whose username/DisplayName allows `'`) + permission to read `database/creds/<role>` for a Redshift-backed role.

### Controlled input
Username embedded into revoke SQL. Sources:
1. **Dynamic creds:** `req.DisplayName` flows into `username_template` (default includes `(.DisplayName | truncate 8)`).
2. LDAP login accepts `username` via `(?P<username>.+)` (not `GenericNameRegex`), and sets `DisplayName: username`.
3. On lease revoke, `secretCredsRevoke` → `DeleteUser` → `defaultDeleteUser` with that username.

### Reachability
1. Login via LDAP with username such that `DisplayName` truncation still retains `'` (e.g. mount prefix `ldap-` + username `x'aaaa` → truncated DisplayName `ldap-x'`).
2. `database/creds/<role>` generates username containing `'`.
3. Lease expiry/revoke calls `defaultDeleteUser`.
4. Vulnerable statement executes via `ExecuteDBQueryDirect` (string exec, not bound params):

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Nearby revoke statements correctly use `dbutil.QuoteIdentifier(username)`; this call site does not.

### Impact
Arbitrary SQL execution as the Vault Redshift connection user during revoke (often a privileged DB user): session termination of other users, data modification/DDL depending on grants, and disruption of credential lifecycle.

### Evidence this tree is unpatched
Local code still interpolates with `'%s'`. Upstream `main` uses `quoteLiteral(username)` (VAULT-43691 / commit `8ba69fccb1`, Apr 2026):

```text
// upstream
revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop(%s);`, quoteLiteral(username)))
```

### Skeptical notes
- Requires Redshift secrets engine in use and a username that can carry `'`.
- Userpass usernames are constrained by `GenericNameRegex` (`\w`/`.`/`-` only), so userpass alone is a weak vector; LDAP/JWT-style DisplayNames and custom `username_template` are the practical paths.
- Creation SQL that already double-quotes `"{{name}}"` can still create users whose names contain `'`; the bug is specifically the single-quoted literal in `terminateloop`.

---

## 2. HANA `DeleteUser` SQL injection — STILL_VULNERABLE

**Severity:** High  
**Primary location:** `plugins/database/hana/hana.go` (`revokeUserDefault`)

### Attacker
Same class as #1: principal who can cause HANA dynamic user revocation for a username containing SQL identifier/metacharacters (LDAP DisplayName / custom username template), or static-role username control.

### Controlled input
`req.Username` interpolated directly into SQL identifier position:

```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

HANA only normalizes hyphens/case on create (`ReplaceAll("-", "_")`, `ToUpper`); it does not strip quotes, semicolons, or spaces. Default template truncates DisplayName to 32 characters, so metacharacters easily survive.

### Reachability
1. Auth → DisplayName with metacharacters → HANA username generation.
2. Lease revoke → `revokeUserDefault` when no custom revoke statements are configured.
3. Crafted username breaks out of `ALTER USER` / `DROP USER` statement text.

### Impact
SQL injection as the Vault HANA root/connection user during revoke: disable/drop unintended users, potential broader DDL/DML per connection privileges.

### Evidence this tree is unpatched
Upstream VAULT-43691 quotes the identifier:

```text
quotedUsername := dbutil.QuoteIdentifier(req.Username)
fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", quotedUsername)
fmt.Sprintf("DROP USER %s RESTRICT", quotedUsername)
```

This tree has no `QuoteIdentifier` on those paths.

### Skeptical notes
- Same engine-in-use precondition as #1.
- Custom revoke statements may bypass this default path; default path is still shipped and used when statements are empty.

---

## 3. PKI ACME challenge validation SSRF — STILL_VULNERABLE

**Severity:** Medium–High (vendor later scored CVE-2026-5052 around Medium/High depending on source)  
**Primary location:** `builtin/logical/pki/acme_challenges.go` (`ValidateHTTP01Challenge`, `ValidateTLSALPN01Challenge`)

### Attacker
Any client who can drive ACME issuance against a PKI mount with ACME enabled (unauthenticated when EAB is not required; otherwise holder of a valid EAB token). Must control DNS for an ordered identifier (or otherwise cause validation to target attacker-chosen resolution).

### Controlled input
ACME identifier / DNS resolution for the challenge host. Validation builds:

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	resp, err := client.Get(path)
```

HTTP client allows redirects (up to 10) and uses `InsecureSkipVerify: true` for TLS-ALPN. **No** rejection of loopback, link-local, unspecified, or multicast targets exists in this file (`DialACME` / `IsLoopback` filters absent).

### Reachability
1. Enable ACME on PKI (common lab/prod automation setups).
2. Create order for a domain whose DNS A/AAAA (or redirect) points at an internal target (e.g. `127.0.0.1`, `169.254.169.254`).
3. Vault server performs http-01 and/or tls-alpn-01 connections to that target from its network position.

### Impact
Server-side request forgery from the Vault node toward internal/localhost/link-local services; potential information disclosure about reachability and, depending on redirect/error behavior, limited response oracleing. Aligns with HCSEC-2026-06 / CVE-2026-5052 (fixed upstream in 2.0.0 / 1.21.5 / 1.20.10 / 1.19.16 — none present here).

### Skeptical notes
- Not in the user-supplied exclusion list, but **is** a publicly assigned CVE (included because it is still present and high-signal).
- Blind/partial oracle in many deployments; impact highest when Vault has privileged network adjacency (cloud metadata, sidecar admin ports).

---

## Near-misses (below reporting bar)

| Topic | Why dropped |
|-------|-------------|
| `.well-known` `ResolveReference` path escape (`vault/well_known_redirect.go`) | Concrete `../` rewrite outside mount prefix confirmed, but rewritten requests still pass normal ACL/auth; CE builtins rarely register redirects (mostly ENT EST/plugins). Marked insufficient impact certainty. |
| Cert auth CRL `http.Get(crl.CDP.Url)` SSRF | Real admin-gated SSRF; requires `auth/cert/crls` write. Treated as expected privileged-config risk without stronger authz bypass. |
| LDAP Go `text/template` filters | Admin-configured filters; no dangerous FuncMap; classic injection largely mitigated by `ldap.EscapeFilter` on username values. |

---

## Bottom line

Two novel (relative to the excluded CVE set), high-confidence SQL injection bugs remain in this `1.18.0-beta1` tree in Redshift and HANA revoke paths — later fixed upstream as VAULT-43691. A third still-vulnerable ACME SSRF path is present and matches CVE-2026-5052.
