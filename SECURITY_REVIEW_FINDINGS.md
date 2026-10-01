# Application Security Review — Vault 1.18.0-beta1

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` / `version/VERSION` = `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-2fbe`  
**Method:** Static end-to-end code tracing (no exploit PoC execution)

---

## Finding 1 — Identity entity/group root policy case bypass (CVE-2025-5999)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `vault/identity_store_entities.go` |
| **Attacker** | Authenticated operator with write on root-namespace identity APIs (`identity/entity`, `identity/entity/id/:id`, `identity/group`, …) — **not** a root token |
| **Input** | `policies` array containing a case variant of `root` (e.g. `ROOT`, `Root`) |
| **Impact** | Entity-/group-bound tokens gain full Vault `root` for the token lifetime |

### Attack path

1. Attacker holds a token that can write identity entities/groups in the **root namespace** (common identity-admin role; not root).
2. `PUT/POST /v1/identity/entity` (or update by id/name) with `"policies": ["ROOT"]`.
3. Write path only blocks the exact string `"root"` after `RemoveDuplicates(..., false)` (trim, no lowercase). Groups use `RemoveDuplicatesStable(..., true)`, which **preserves original case** while deduping case-insensitively — so `"ROOT"` still bypasses the exact `"root"` check.
4. Entity/group is stored with `policies: ["ROOT"]`.
5. On a subsequent request by a token tied to that entity, `fetchEntityAndDerivedPolicies` loads those policies; `policyutil.SanitizePolicies` lowercases them to `"root"`.
6. `PolicyStore.sanitizeName` / `GetPolicy` also lowercases; ACL construction treats the name as the built-in root policy → `a.root = true`.

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

```249:257:vault/identity_store_groups.go
	// Update the policies if supplied
	policiesRaw, ok := d.GetOk("policies")
	if ok {
		group.Policies = strutil.RemoveDuplicatesStable(policiesRaw.([]string), true)
	}

	if strutil.StrListContains(group.Policies, "root") {
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

### Why it clears the bar

Lower-privileged identity administrator escalates to full Vault root without needing a root token. Case mismatch between write-time deny-list and request-time sanitization is a concrete, reproducible authz bug (later fixed upstream as CVE-2025-5999 / CE 1.20.0 / Ent 1.18.11+).

---

## Finding 2 — Redshift default revoke SQL injection via username

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `plugins/database/redshift/redshift.go` |
| **Attacker** | Authenticated low-priv principal who can obtain dynamic Redshift creds (`database/creds/<role>`), where auth DisplayName can contain `'` |
| **Input** | Auth username / token DisplayName containing a single quote (LDAP login path allows `(?P<username>.+)`) |
| **Impact** | Arbitrary SQL as the Vault Redshift connection user on lease revoke (session kill, DDL/DML per grants, credential-lifecycle disruption) |

### Attack path

1. LDAP (or similar) auth: login username includes `'`, e.g. `x'aaaa`. LDAP pattern is `.+`; Auth `DisplayName` is that username.
2. Token reads `database/creds/<redshift-role>`. Creds path passes `req.DisplayName` into username generation.
3. Default username template embeds truncated DisplayName; truncate/lowercase preserve `'`.
4. Lease revoke / expiry → `DeleteUser` → `defaultDeleteUser`.
5. Most revoke statements use `dbutil.QuoteIdentifier(username)`, but the session-terminate call does not:

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

6. Crafted username breaks out of the string literal → SQL injection via `ExecuteDBQueryDirect`.

### Evidence

```37:37:plugins/database/redshift/redshift.go
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 | lowercase }}`
```

```126:128:builtin/logical/database/path_creds_create.go
			UsernameConfig: v5.UsernameMetadata{
				DisplayName: req.DisplayName,
```

```18:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

Adjacent correctly quoted revoke statements contrast with the unquoted `terminateloop` call (lines 414–420 vs 451).

### Why it clears the bar

Low-priv Vault user (only needs DB creds read + an auth path that allows `'` in DisplayName) influences SQL executed by Vault’s privileged Redshift connection on revoke — classic privilege-boundary SQLi, not admin-configured statements.

---

## Finding 3 — PKI ACME http-01 / tls-alpn-01 validation SSRF

| Field | Value |
| --- | --- |
| **Severity** | Medium (High confidentiality impact when ACME is enabled and Vault can reach sensitive internal endpoints) |
| **Location** | `builtin/logical/pki/acme_challenges.go` |
| **Attacker** | Unauthenticated remote client using ACME (`PathsSpecial.Unauthenticated` once ACME is enabled) |
| **Input** | ACME order domain / identifiers (and http-01 redirect `Location` URLs) that resolve or redirect to internal/link-local addresses |
| **Impact** | Vault performs outbound HTTP/TLS to attacker-chosen hosts (SSRF): probe internal networks, hit cloud metadata, or read challenge-response-shaped internal HTTP bodies |

### Attack path

1. Operator enables ACME (`pki/config/acme` `enabled=true`). ACME directory/new-order/challenge endpoints are unauthenticated.
2. Attacker creates an ACME account and new-order for a domain they control (or a name resolving to an internal IP if DNS allows).
3. Challenge validation calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge`.
4. HTTP client `Get`s `http://{domain}/.well-known/acme-challenge/{token}` with **no** private/loopback/link-local rejection. `CheckRedirect` only limits redirect count/URL length.
5. TLS-ALPN dials `{domain}:443` with the same dialer and no destination IP policy.

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

Unauthenticated ACME paths are registered in `builtin/logical/pki/acme_wrappers.go` (directory, new-order, challenge, …).

### Why it clears the bar

Unauthenticated attacker triggers server-side fetches to attacker-influenced destinations once ACME is on. Enabling ACME is a single common PKI config flag; there is no secondary SSRF guard (class later tracked as CVE-2026-5052).

---

## Finding 4 — AWS auth IAM/EC2 client cache missing account ID (CVE-2025-11621)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `builtin/credential/aws/client.go` |
| **Attacker** | Unauthenticated AWS principal from a **different** AWS account that can present a valid STS/EC2 identity |
| **Input** | IAM login (`iam_request_*`) or EC2 login against a role whose `bound_iam_principal_arn` uses wildcards / colliding role names, or EC2 binds that rely on AMI without strict account isolation |
| **Impact** | Cross-account authentication into Vault roles intended for another AWS account (token issuance / secret access) |

### Attack path

1. Vault AWS auth is configured with a role whose `bound_iam_principal_arn` includes wildcards (e.g. `arn:aws:iam::111111111111:role/MyRole*`), and/or multi-account STS is in use with empty STS role for the default account.
2. A legitimate login from account `111111111111` creates and caches an IAM (or EC2) client keyed only by `region` + `stsRole` (empty string for default account) — **not** `accountID`.
3. Attacker from account `222222222222` with a colliding role/user friendly name authenticates via STS `GetCallerIdentity`.
4. Wildcard bind path calls `fullArn` → `clientIAM(ctx, s, region, attackerAccountID)`.
5. Cache hit returns the **default/account-A** client without re-validating `accountID`.
6. `GetRole`/`GetUser` against account A returns an ARN that matches the configured wildcard bind → login succeeds for the attacker’s Vault role.

Same cache shape for EC2: `EC2ClientsMap[region][stsRole]` used by `validateInstance`, so DescribeInstances can hit the wrong account’s API.

### Evidence

```76:86:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	EC2ClientsMap map[string]map[string]*ec2.EC2
	// Map to hold the IAM client objects indexed by region and STS role.
	IAMClientsMap map[string]map[string]*iam.IAM
```

```284:290:builtin/credential/aws/client.go
	b.configMutex.RLock()
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		// If the client object was already created, return it
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

(Account ID is checked only on cache miss in `getClientConfig` when `stsRole == ""`; the cached path skips that check.)

```1888:1914:builtin/credential/aws/path_login.go
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
	// ...
		resp, err := client.GetRoleWithContext(ctx, &input)
```

### Why it clears the bar

Unauthenticated cross-account auth bypass under realistic wildcard/multi-account AWS auth configs. Fixed upstream as CVE-2025-11621 (CE 1.21.0 / Ent 1.20.5+); this 1.18.0-beta1 tree still keys caches without account ID.

---

## Finding 5 — File audit device → plugin directory host RCE (CVE-2025-6000)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `audit/backend_file.go` |
| **Attacker** | Privileged root-namespace operator with write on `sys/audit` (and ability to register/mount a plugin when `plugin_directory` is configured) — **not** necessarily a root token / host admin |
| **Input** | Audit device `file_path` pointing into the configured plugin directory; `prefix` / controlled request content to materialize a binary; SHA256 via `sys/audit-hash` |
| **Impact** | Arbitrary code execution on the Vault host when the written file is registered and executed as an external plugin |

### Attack path

1. Vault is configured with `plugin_directory` set.
2. Attacker enables a file audit device with `file_path` under that directory (no path restriction in `newFileBackend` / `configureSinkNode`).
3. Attacker shapes request traffic (and optional `prefix`) so the audit log file bytes are a valid plugin binary; uses `sys/audit-hash` with the device HMAC key materialization path described in HCSEC-2025-14 to obtain the required SHA256.
4. Attacker registers the file in `sys/plugins/catalog` and mounts/uses it → Vault `exec`s the binary from the plugin directory.

### Evidence

```48:57:audit/backend_file.go
	// Get file path from config or fall back to the old option ('path') for compatibility
	var filePath string
	if p, ok := conf.Config[optionFilePath]; ok {
		filePath = p
	} else if p, ok = conf.Config["path"]; ok {
		filePath = p
	} else {
		return nil, fmt.Errorf("%q is required: %w", optionFilePath, ErrExternalOptions)
	}
```

No check that `filePath` is outside `plugin_directory`. Plugin catalog then joins command under that directory and executes it (`vault/plugincatalog/plugin_catalog.go` `setInternal`).

Upstream remediation (CE 1.20.1 / Ent 1.18.12+): disable audit `prefix` by default (`AllowAuditLogPrefixing`) and forbid audit destinations under the plugin directory.

### Why it clears the bar

Escalation from Vault API capabilities (`sys/audit` + plugin catalog) to **host RCE**, without needing OS shell access or a root token. Distinct from “already full Vault root,” which can already seal/destroy the cluster but is not the same as executing attacker code on the host via plugin spawn.

---

## Strongest near-misses (ruled out / not primary)

| Candidate | Why not reported as primary |
| --- | --- |
| Cert auth non-CA CN impersonation (CVE-2025-6037) | Valid on this tree (`path_login.go` matches serial/AKID/pubkey, alias = presented CN; no `tCert.Equal(clientCert)`). Needs non-CA trust config **and** possession of that leaf’s private key — narrower than findings 1–4. |
| HANA `DROP USER %s RESTRICT` unquoted username (`plugins/database/hana/hana.go`) | Same DisplayName→username class as Finding 2; Redshift path is cleaner (unquoted string literal in `terminateloop`). |
| Cert CRL/OCSP URL fetch SSRF | Requires admin write to cert/CRL config (or AIA only after trust is established). Expected privileged SSRF surface, not low-priv escalation. |
| GitHub `base_url` / AWS `sts_endpoint` SSRF | Admin-configured endpoints only. |
| AppRole secret-id-accessor cross-role destroy | Fixed (CVE-2023-24999); accessor destroy verifies role HMAC storage entry. |
| Agent/proxy `exec` command injection | Local agent config operator controls `exec.command`; not a remote Vault API attacker. Env templates forbid nested `command`. |
| Plugin catalog `..` escape | Blocked (`strings.Contains(..., "..")` + symlink EvalSymlinks directory check). |
| `sys/raw` without sudo | Still gated as root/sudo path via router `RootPath`; not an unauth/low-priv bypass. |
| Identity OIDC provider open redirect | `validRedirect` enforces allowlist (loopback port-agnostic per RFC 8252 only). |
| User lockout bypass (CVE-2025-6004) | Medium hardening issue; not fully re-traced to a novel E2E path beyond known CVE class on this pass. |
| JWT/OIDC/Kerberos **auth methods** | Not in this OSS tree’s `builtin/credential` (external plugins / agent clients only). |

---

## Summary

| # | Title | Severity | Location |
| --- | --- | --- | --- |
| 1 | Identity root policy case bypass (CVE-2025-5999) | High | `vault/identity_store_entities.go` |
| 2 | Redshift revoke SQL injection via DisplayName | High | `plugins/database/redshift/redshift.go` |
| 3 | PKI ACME challenge validation SSRF | Medium | `builtin/logical/pki/acme_challenges.go` |
| 4 | AWS auth client cache missing account ID (CVE-2025-11621) | High | `builtin/credential/aws/client.go` |
| 5 | File audit → plugin directory host RCE (CVE-2025-6000) | High | `audit/backend_file.go` |
