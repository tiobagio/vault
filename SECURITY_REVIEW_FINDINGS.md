# Application Security Review — Vault 1.18.0-beta1

**Tree:** `0513545dd` / `version/VERSION` = `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-da9c`  
**Scope:** Auth/authz, SSRF, path traversal, command/SQL/template injection, JWT/crypto, privilege escalation  
**Method:** Static code tracing of end-to-end attack paths (no exploit PoC execution)

---

## Finding 1 — Identity entity/group root policy case bypass (CVE-2025-5999)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `vault/identity_store_entities.go` |
| **Attacker** | Authenticated operator with write on root-namespace identity APIs (`identity/entity`, `identity/entity/id/:id`, `identity/group`, etc.) — **not** a root token |
| **Input** | `policies` array containing a case variant of `root` (e.g. `ROOT`, `Root`) |
| **Impact** | Entity-/group-bound tokens gain full Vault `root` for the token lifetime |

### Attack path

1. Attacker holds a token that can write identity entities/groups in the **root namespace** (common identity-admin role; explicitly not root).
2. `PUT/POST /v1/identity/entity` (or update by id/name) with `"policies": ["ROOT"]` (or `"Root"`).
3. Write path only blocks the exact string `"root"` after `RemoveDuplicates(..., false)` (trim, no lowercase).
4. Entity is stored with `policies: ["ROOT"]`.
5. On a subsequent request by a token tied to that entity, `fetchEntityAndDerivedPolicies` loads those policies; `policyutil.SanitizePolicies` lowercases them to `"root"`.
6. ACL construction treats the sanitized name as the built-in root policy → `a.root = true`.

Same bypass exists on groups via `vault/identity_store_groups.go` (exact `"root"` check after `RemoveDuplicatesStable`).

### Evidence

```355:363:vault/identity_store_entities.go
		// Update the policies if supplied
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

```51:65:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	defaultFound := false
	for i, p := range policies {
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		// ...
		if policies[i] == "root" {
			policies = []string{"root"}
			defaultFound = true
			break
		}
```

```300:302:vault/request_handling.go
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}
```

```104:114:vault/acl.go
		if policy.Name == "root" {
			if ns.ID != namespace.RootNamespaceID {
				return nil, fmt.Errorf("root policy is only allowed in root namespace")
			}
			// ...
			a.root = true
		}
```

`GetPolicy` also lowercases names (`sanitizeName`), so `"ROOT"` resolves to the special-cased root ACL policy in the root namespace.

### Remediation

Reject root case-insensitively at write time (e.g. `strutil.StrListContainsCaseInsensitive(..., "root")`), matching upstream CE 1.20.0 / Ent 1.18.11+. Audit entities/groups for case-variant `root` assignments.

---

## Finding 2 — Redshift default revoke SQL injection via username

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `plugins/database/redshift/redshift.go` |
| **Attacker** | Authenticated low-priv Vault principal who can obtain dynamic Redshift creds (e.g. LDAP user with `database/creds/<role>`), where DisplayName can contain `'` |
| **Input** | Auth username / token DisplayName containing a single quote (LDAP login path allows `(?P<username>.+)`) |
| **Impact** | Arbitrary SQL as the Vault Redshift connection user on lease revoke (session kill, DDL/DML per grants, credential-lifecycle disruption) |

### Attack path

1. LDAP (or similar) auth: login username includes `'`, e.g. `x'aaaa`. LDAP pattern is `.+` (not `GenericNameRegex`); Auth `DisplayName` is that username.
2. Token reads `database/creds/<redshift-role>`. Creds path passes `req.DisplayName` into username generation.
3. Default username template embeds truncated DisplayName:

```37:37:plugins/database/redshift/redshift.go
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 | lowercase }}`
```

   Truncate/lowercase preserve `'`. Creation statements typically use `"{{name}}"` (quoted identifier), so user creation can succeed.
4. Lease revoke / expiry → `DeleteUser` → `defaultDeleteUser` with that username.
5. Most revoke statements correctly use `dbutil.QuoteIdentifier(username)`, but the session-terminate call does not:

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

6. Crafted username breaks out of the string literal → SQL injection via `ExecuteDBQueryDirect`.

### Evidence

Contrast with adjacent correctly quoted statements:

```414:420:plugins/database/redshift/redshift.go
	revocationStmts = append(revocationStmts, fmt.Sprintf(
		`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %s;`,
		dbutil.QuoteIdentifier(username)))

	revocationStmts = append(revocationStmts, fmt.Sprintf(
		"REVOKE USAGE ON SCHEMA public FROM %s;",
		dbutil.QuoteIdentifier(username)))
```

LDAP username acceptance:

```18:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```97:97:builtin/credential/ldap/path_login.go
		DisplayName: username,
```

### Remediation

Quote the literal (e.g. `quoteLiteral(username)` / proper escaping) before interpolating into `terminateloop(...)`, consistent with other revoke statements. Prefer bound parameters where the driver allows. Optionally harden default username templates to strip SQL metacharacters from DisplayName.

---

## Finding 3 — PKI ACME http-01 / tls-alpn-01 validation SSRF

| Field | Value |
| --- | --- |
| **Severity** | Medium (High confidentiality impact if ACME is enabled and Vault can reach sensitive internal endpoints) |
| **Location** | `builtin/logical/pki/acme_challenges.go` |
| **Attacker** | Unauthenticated remote client using ACME (paths are `PathsSpecial.Unauthenticated` once ACME is enabled) |
| **Input** | ACME order domain / identifiers (and http-01 redirect `Location` URLs) that resolve or redirect to internal/link-local addresses |
| **Impact** | Vault server performs outbound HTTP/TLS connections to attacker-chosen hosts (SSRF): probe internal networks, hit cloud metadata, or read challenge-response-shaped internal HTTP bodies |

### Attack path

1. Operator enables ACME (`pki/config/acme` `enabled=true`). Default `eab_policy` is not required; ACME directory/new-order/challenge endpoints are unauthenticated.
2. Attacker creates an ACME account and new-order for a domain they control (DNS to an attacker host, or a name resolving to an internal IP if resolver allows).
3. Challenge validation calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge`.
4. `ValidateHTTP01Challenge` builds `http://{domain}/.well-known/acme-challenge/{token}` and `client.Get`s it with **no** private/loopback/link-local rejection. `CheckRedirect` only limits redirect count/URL length — not destination address.
5. `ValidateTLSALPN01Challenge` dials `{domain}:443` via the same dialer with no destination IP policy.
6. Vault’s network position is abused to reach localhost, RFC1918, or link-local services (e.g. cloud metadata).

ACME defaults to disabled, but enabling it is a single common PKI config flag — not exotic — and there is no secondary SSRF guard.

### Evidence

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via)+1 >= maxRedirects {
				return fmt.Errorf("http-01: too many redirects: %v", len(via)+1)
			}
			reqUrlLen := len(req.URL.String())
			if reqUrlLen > urlLength {
				return fmt.Errorf("http-01: redirect url length too long: %v", reqUrlLen)
			}
			return nil
		},
	}

	resp, err := client.Get(path)
```

```471:474:builtin/logical/pki/acme_challenges.go
	address := fmt.Sprintf("%v:"+ALPNPort, domain)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return false, fmt.Errorf("tls-alpn-01: failed to dial host: %w", err)
```

No `IsPrivate` / loopback / link-local checks appear in `acme_challenges.go`. Matches the class later tracked as CVE-2026-5052.

### Remediation

Before dialing/fetching, resolve the target and reject loopback, private, link-local, and metadata ranges (including after redirects). Prefer allowlists for validation targets. Align with upstream ACME SSRF fixes (CE/Ent 2.0.0 / 1.21.5 / 1.20.10 / 1.19.16).

---

## Rejected candidates (brief)

| Candidate | Why rejected |
| --- | --- |
| HANA `revokeUserDefault` unquoted username SQLi (`plugins/database/hana/hana.go`) | Same class as Finding 2; omitted to stay within 3 findings (still valid if Redshift unused). |
| MSSQL `dropUserSQL` dbName interpolation | Requires SQL Server ability to create oddly named DBs mapped to Vault logins — weak Vault privilege-boundary story vs DisplayName→revoke path. |
| Cert auth non-CA CN impersonation (CVE-2025-6037) | Valid on this tree (`path_login.go` matches serial/AKID/pubkey, alias=presented CN) but needs non-CA trust config + key possession — more exotic than findings 1–3. |
| GitHub team Name+Slug dual map | Plausible Medium cross-team escalation via display Name colliding with another team’s Slug; needs GitHub team-create rights + GitHub auth. Solid but narrower than identity root bypass. |
| Physical backend SQL string concat | Admin storage config only; intentional privileged DB ops. |
| DB `creation_statements` / custom revoke SQL | Intentional admin-controlled SQL by design. |
| Agent `exec.Command` / token helper | Local agent config operator, not remote Vault API attacker. |
| Unauthenticated metrics/pprof | Explicit listener config; excluded by scope. |
| OCSP client SSRF | Needs cert auth OCSP enabled + attacker-influenced AIA URLs under trust assumptions; not default. |
| text/template in LDAP filters / username templates | Restricted func maps / admin-configured templates; no clear dangerous-func escape for low-priv users beyond SQLi vector above. |
| LIST trailing-slash ACL / audit plugin-dir (later CVEs) | Not re-validated as novel on this pass; policy engine paths reviewed for obvious bypasses without confirmed E2E beyond known CVE class. |
