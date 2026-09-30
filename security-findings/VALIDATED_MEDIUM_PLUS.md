# Validated MEDIUM+ Findings — HashiCorp Vault

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version:** `1.18.0-beta1`  
**Method:** Static reachability review of secrets engines, auth methods, ACME, and related handlers. No exploit PoC execution.

Only candidates with a defendable end-to-end attack path are listed. Admin-only config without privilege escalation beyond Vault admin, intentional DB-role SQL templates set by privileged operators, and speculative issues without reachability are omitted.

---

## 1. PKI ACME http-01 / tls-alpn-01 SSRF to internal targets

- **Severity:** Medium (CVE-2026-5052 / HCSEC-2026-06; HashiCorp CVSS 5.3)
- **Attacker:** Unauthenticated ACME client when `eab_policy` is `not-required` (the default in this tree), or any holder of a valid EAB token when EAB is required
- **Controlled input:** ACME order identifier (DNS name / resolution target); attacker-controlled DNS A/AAAA or HTTP redirect destination
- **Reachability path:**
  1. PKI mount has ACME enabled (`pki/config/acme`, `enabled=true`)
  2. Default `EabPolicyName = not-required` (`builtin/logical/pki/path_config_acme.go`) leaves ACME challenge/order paths on `PathsSpecial.Unauthenticated`
  3. Attacker: `new-account` → `new-order` → trigger `http-01` / `tls-alpn-01`
  4. `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge` dial the resolved host with a default dialer — **no** rejection of loopback, link-local, unspecified, or private ranges
  5. HTTP-01 follows redirects (up to 10) with only length/count checks
- **Impact:** SSRF from the Vault node into localhost / link-local / internal HTTP(S) services (e.g. cloud metadata, admin ports); internal reachability / limited response oracleing
- **Primary location:** `builtin/logical/pki/acme_challenges.go`

### Evidence

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// only redirects count + URL length — no IP/host safety checks
			return nil
		},
	}
	resp, err := client.Get(path)
```

```455:475:builtin/logical/pki/acme_challenges.go
	dialer, err := buildDialerConfig(config)
	address := fmt.Sprintf("%v:"+ALPNPort, domain)
	conn, err := dialer.Dial("tcp", address)
```

Default EAB policy allows unauthenticated ACME:

```41:49:builtin/logical/pki/path_config_acme.go
var defaultAcmeConfig = acmeConfigEntry{
	Enabled:                false,
	// ...
	EabPolicyName:          eabPolicyNotRequired,
```

Unauthenticated path registration:

```64:77:builtin/logical/pki/acme_wrappers.go
	b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, unauthPrefix+"/new-order")
	// ...
	b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, unauthPrefix+"/challenge/+/+")
```

### Why not a false positive
- Not admin-gated at challenge time once ACME is enabled
- No private-IP / loopback filter exists in this commit (upstream fix landed later as CVE-2026-5052)
- Redirects amplify SSRF beyond the ordered name’s first hop

---

## 2. Redshift secrets engine — SQL injection on default revoke via unsanitized username

- **Severity:** High
- **Attacker:** Any principal who can generate (and later revoke/expire) dynamic Redshift credentials for a role using default revoke statements, whose token `DisplayName` can contain `'` (realistic via LDAP/Okta usernames such as `O'Brien`, or custom `username_template`)
- **Controlled input:** Username derived from `req.DisplayName` via `username_template` (default truncates DisplayName to 8 chars — still enough to keep `'`)
- **Reachability path:**
  1. Auth (e.g. LDAP `login/(?P<username>.+)`) sets `DisplayName: username` without Vault’s token `displayNameSanitize`
  2. `LoginCreateToken` prefixes mount source → e.g. `ldap-O'Brien`
  3. `database/creds/<role>` → Redshift `NewUser` embeds DisplayName into username (`truncate 8` → `ldap-O'`)
  4. Lease revoke / expiry → `DeleteUser` → `defaultDeleteUser`
  5. Vulnerable call: `call terminateloop('%s')` with raw username (not `QuoteIdentifier` / literal-escaped)
- **Impact:** Arbitrary SQL as the Vault Redshift connection user during revoke (session termination of other DB users, broader DML/DDL per grants)
- **Primary location:** `plugins/database/redshift/redshift.go`

### Evidence

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Nearby revoke statements correctly use `dbutil.QuoteIdentifier(username)`; this call site does not. Execution is via `ExecuteDBQueryDirect` (string interpolation, not bound parameters).

DisplayName flow into username generation:

```125:129:builtin/logical/database/path_creds_create.go
		newUserReq := v5.NewUserRequest{
			UsernameConfig: v5.UsernameMetadata{
				DisplayName: req.DisplayName,
				RoleName:    name,
```

LDAP accepts arbitrary username characters and sets DisplayName from them:

```18:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```90:98:builtin/credential/ldap/path_login.go
	auth := &logical.Auth{
		// ...
		DisplayName: username,
```

Default Redshift username template still preserves `'` inside 8 truncated DisplayName chars:

```37:37:plugins/database/redshift/redshift.go
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 | lowercase }}`
```

### Why not a false positive
- Not “admin writes creation_statements” — the privileged operator never intended attacker-controlled SQL; only role *read*/creds generation is required
- Default revoke path is used when custom `revocation_statements` are empty (common)
- Token-create sanitizes `display_name`, but **login** DisplayNames are not run through `displayNameSanitize`
- Upstream later fixed this (VAULT-43691 / `quoteLiteral`); unpatched here

---

## 3. HANA secrets engine — SQL injection on default revoke via unquoted username

- **Severity:** High
- **Attacker:** Same class as #2 against a HANA-backed database role (LDAP/Okta DisplayName with metacharacters, or custom username template)
- **Controlled input:** Generated username containing SQL identifier breakouts (`'`, spaces, etc.). HANA only replaces `-` → `_` and uppercases; it does **not** strip quotes/semicolons
- **Reachability path:**
  1. Creds create → username from DisplayName (`truncate 32` in default template)
  2. Lease revoke with empty custom statements → `revokeUserDefault`
  3. `ALTER USER %s` / `DROP USER %s` interpolate raw `req.Username`
- **Impact:** SQL injection as Vault HANA connection user on revoke (disable/drop unintended users; further DDL/DML per grants)
- **Primary location:** `plugins/database/hana/hana.go`

### Evidence

```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

Create-time “sanitization” is incomplete:

```127:129:plugins/database/hana/hana.go
	username = strings.ReplaceAll(username, "-", "_")
	username = strings.ToUpper(username)
```

### Why not a false positive
- Same privilege split as #2: creds readers, not role writers
- Default revoke path is shipped and used when statements are empty
- Upstream VAULT-43691 adds `dbutil.QuoteIdentifier`; absent here

---

## 4. AWS auth — cross-account auth bypass via IAM/EC2 client cache missing AccountID

- **Severity:** High (CVE-2025-11621 / HCSEC-2025-30)
- **Attacker:** IAM principal (or EC2 instance) in a **different** AWS account that shares a colliding role/user name (or matches a wildcard `bound_iam_principal_arn`) with a trusted account
- **Controlled input:** Valid STS GetCallerIdentity proof from the attacker’s AWS account; cache-key collision on `(region, stsRole)` without AccountID
- **Reachability path:**
  1. Vault AWS auth configured for multiple accounts / STS role assumption, with wildcard or name-colliding `bound_iam_principal_arn`
  2. Legitimate login populates `IAMClientsMap[region][stsRole]` / `EC2ClientsMap[region][stsRole]`
  3. Attacker’s login resolves `fullArn` / instance validation using the **cached client for the wrong account**
  4. Wildcard ARN bind or inferred EC2 checks can succeed against the wrong-account client’s view
- **Impact:** Authentication bypass / cross-account privilege escalation into Vault roles intended for another AWS account
- **Primary location:** `builtin/credential/aws/client.go`

### Evidence

Maps are keyed only by region + STS role (empty STS role = “master”); AccountID is not part of the key:

```76:86:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	EC2ClientsMap map[string]map[string]*ec2.EC2
	// Map to hold the IAM client objects indexed by region and STS role.
	IAMClientsMap map[string]map[string]*iam.IAM
```

```227:231:builtin/credential/aws/client.go
	if b.EC2ClientsMap[region] != nil && b.EC2ClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		return b.EC2ClientsMap[region][stsRole], nil
	}
```

```284:289:builtin/credential/aws/client.go
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		return b.IAMClientsMap[region][stsRole], nil
	}
```

`fullArn` (used for wildcard IAM principal binds) uses that cached IAM client:

```1888:1891:builtin/credential/aws/path_login.go
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
```

### Why not a false positive
- Login is unauthenticated (`auth/aws/login`)
- Collision is realistic with multi-account STS configs and wildcards (documented attack condition in HCSEC-2025-30)
- Fix (composite `clientKey{AccountID,Region,STSRole}`) is not in this tree

---

## 5. Cert auth — non-CA trusted leaf allows CN/identity impersonation

- **Severity:** Medium (CVE-2025-6037 / HCSEC-2025-18)
- **Attacker:** Anyone who possesses a registered **non-CA** client certificate **and its private key**
- **Controlled input:** Newly minted certificate preserving the trusted leaf’s public key, serial, and Authority Key ID, but with an arbitrary Subject CN
- **Reachability path:**
  1. Admin registers a non-CA leaf under `auth/cert/certs/:name` (common for pinning a single client cert)
  2. Default: `allowed_common_names` empty → `matchesCommonName` allows all CNs
  3. Non-CA match only checks serial + AKID + public key equality — **not** subject CN equality with the registered leaf
  4. Entity alias is taken from the **presented** cert CN
  5. Attacker authenticates as another CN-mapped identity / policies
- **Impact:** Impersonation of other cert-auth identities that share the mount’s alias/policy model
- **Primary location:** `builtin/credential/cert/path_login.go`

### Evidence

```279:308:builtin/credential/cert/path_login.go
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

```160:169:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		DisplayName: matched.Entry.DisplayName,
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

```414:418:builtin/credential/cert/path_login.go
func (b *backend) matchesCommonName(clientCert *x509.Certificate, config *ParsedCert) bool {
	if len(config.Entry.AllowedCommonNames) == 0 {
		return true
	}
```

### Why not a false positive
- Requires the trusted leaf private key, but that is the expected client credential — the bug is **identity binding**, not theft of the key
- Default config does not pin CN; alias uses attacker-chosen CN
- Distinct from “admin misconfigured allowed_common_names”

---

## Investigated / not reported (high-level)

| Area | Outcome |
|------|---------|
| PostgreSQL/MySQL creation_statements SQLi via DisplayName | Default username charset from common auth methods (`GenericNameRegex`) lacks `"`;/`;` breakouts; token `display_name` is sanitized. Residual risk mainly with LDAP/custom templates — Redshift/HANA revoke paths are the clear High wins |
| SSH identity templates / principals | Template rendering is identity-driven and constrained by role allow-lists; no command execution surface validated |
| JWT/OIDC discovery/JWKS SSRF | JWT auth is **not** present as a builtin in this OSS tree |
| GitHub/Okta/LDAP/AWS endpoint SSRF | `base_url` / LDAP URL / `sts_endpoint` are admin-configured; AWS login rebuilds URL against configured STS endpoint (intentional anti-proxy comment) |
| Agent/proxy shared cache smuggling | No validated unauth smuggling/poisoning beyond known optional `require_request_header` hardening |
| Audit path traversal / log injection | File audit path is admin-gated; no medium+ non-admin path defended here |
| Identity group/entity root escalation (CVE-2024-9180) | API rejects assigning `root` policy; cache-confusion variant not independently re-proven in this pass |
| Token wrapping / cubbyhole bypasses | No medium+ bypass validated |
| UI custom messages XSS | Ember escapes message body; create is privileged |
| Plugin catalog without checksum | `sha256` required on register; launch verifies hash |
| X-Forwarded-For / client-cert header bypass | Cert import only after authorized-proxy address check |
| Raft snapshot restore path issues via API | No unsafe user-controlled restore path validated in this pass |

---

## Summary table

| # | Title | Severity | Primary file |
|---|-------|----------|--------------|
| 1 | ACME challenge validation SSRF | Medium | `builtin/logical/pki/acme_challenges.go` |
| 2 | Redshift default revoke SQL injection | High | `plugins/database/redshift/redshift.go` |
| 3 | HANA default revoke SQL injection | High | `plugins/database/hana/hana.go` |
| 4 | AWS auth client cache AccountID bypass | High | `builtin/credential/aws/client.go` |
| 5 | Cert auth non-CA CN impersonation | Medium | `builtin/credential/cert/path_login.go` |
