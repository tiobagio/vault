# Application Security Review — HashiCorp Vault OSS

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `1.18.0-beta1` (`version/VERSION`)  
**Branch:** `cursor/application-security-review-b4db`  
**Method:** Static end-to-end code tracing of attacker-controlled inputs through `http/`, `vault/`, `builtin/credential/`, `builtin/logical/`, `command/agent*`, `sdk/helper/ldaputil`, `physical/couchdb`, and related sinks.

Only issues with a concrete attacker → input → code path → impact chain are listed. Speculative `InsecureSkipVerify` options, admin-only intentional features without lower-privilege escalation, and unauthenticated intentional cluster bootstrap endpoints are excluded unless a lower-privilege attacker can trigger meaningful impact.

---

## Finding 1 — Identity entity/group root policy case bypass (CVE-2025-5999)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `vault/identity_store_entities.go` |
| **Attacker** | Authenticated operator with write on root-namespace identity APIs (`identity/entity`, `identity/entity/id/:id`, `identity/group`, …) — **not** a root token |
| **Input** | `policies` array containing a case/whitespace variant of `root` (e.g. `ROOT`, `Root`, ` root `) |
| **Impact** | Entity-/group-bound tokens gain full Vault `root` for the remainder of the token lifetime |

### Attack path

1. Attacker holds a token that can write identity entities/groups in the **root namespace** (common identity-admin role; not root).
2. `PUT/POST /v1/identity/entity` (or update by id/name) with `"policies": ["ROOT"]`.
3. Write path only rejects the exact string `"root"` after `RemoveDuplicates(..., false)` (no lowercase/trim). Groups use `RemoveDuplicatesStable(..., true)`, which preserves original case while deduping case-insensitively — so `"ROOT"` still bypasses the exact `"root"` check.
4. Entity/group is persisted with `policies: ["ROOT"]`.
5. On a subsequent request by a token tied to that entity, `fetchEntityAndDerivedPolicies` loads those policies; `policyutil.SanitizePolicies` lowercases them to `"root"`.
6. `PolicyStore.sanitizeName` / `GetPolicy` also lowercases; ACL construction treats the name as the built-in root policy → full root privileges.

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
	policiesRaw, ok := d.GetOk("policies")
	if ok {
		group.Policies = strutil.RemoveDuplicatesStable(policiesRaw.([]string), true)
	}

	if strutil.StrListContains(group.Policies, "root") {
		return logical.ErrorResponse("policies cannot contain root"), nil
	}
```

```300:302:vault/request_handling.go
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}
```

```51:62:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	// ...
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		if policies[i] == "root" {
			policies = []string{"root"}
```

```931:933:vault/policy_store.go
func (ps *PolicyStore) sanitizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
```

### Remediation

Normalize policy names with the same rules as `SanitizePolicies` / `sanitizeName` **before** the `"root"` deny check on entity and group writes (case-insensitive + trim). Reject any policy that normalizes to `root`. Fixed upstream in Vault CE 1.20.0 / Enterprise 1.18.11+ (CVE-2025-5999 / HCSEC-2025-13).

---

## Finding 2 — PKI ACME http-01 / tls-alpn-01 validation SSRF (CVE-2026-5052)

| Field | Value |
| --- | --- |
| **Severity** | Medium (High confidentiality impact when Vault can reach sensitive internal endpoints / cloud metadata) |
| **Location** | `builtin/logical/pki/acme_challenges.go` |
| **Attacker** | Unauthenticated remote client using ACME once ACME is enabled (paths registered in `PathsSpecial.Unauthenticated`) |
| **Input** | ACME order DNS/IP identifiers; http-01 redirect `Location` URLs; DNS resolution of challenge targets |
| **Impact** | Vault performs outbound HTTP/TLS to attacker-influenced hosts (SSRF): probe internal networks, hit link-local/cloud metadata, or observe challenge-sized responses |

### Attack path

1. Operator enables ACME (`pki/config/acme` `enabled=true`). Default directory policy is `sign-verbatim` with `AllowIPSANs: true` (`issuing.SignVerbatimRole`).
2. ACME directory / new-account / new-order / challenge endpoints are unauthenticated (`acme_wrappers.go`).
3. Attacker creates an ACME account and new-order for:
   - an IP identifier such as `169.254.169.254` / `127.0.0.1` (when IP SANs are allowed), **or**
   - a DNS name they control that resolves (or redirects) to an internal address.
4. Challenge validation calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge`.
5. HTTP client `Get`s `http://{domain}/.well-known/acme-challenge/{token}` with **no** private/loopback/link-local rejection. `CheckRedirect` only limits redirect count and URL length — redirects to internal URLs are followed.
6. TLS-ALPN dials `{domain}:443` with the same dialer and no destination IP policy.

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

```65:73:builtin/logical/pki/acme_wrappers.go
	b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, unauthPrefix+"/directory")
	// ... new-account, new-order, challenge/+/+, ...
```

```369:373:builtin/logical/pki/issuing/roles.go
	entry := &RoleEntry{
		AllowLocalhost:            true,
		AllowAnyName:              true,
		AllowIPSANs:               true,
```

No `challenge_excluded_ip_ranges` / `challenge_permitted_ip_ranges` exist on this tree.

### Remediation

Reject challenge targets in private, loopback, link-local, and metadata ranges; apply the same checks on redirect destinations before following them. Prefer default-deny with explicit allowlists. Fixed upstream as CVE-2026-5052 (CE 2.0.0 / Ent 1.21.5, 1.20.10, 1.19.16) via challenge IP range controls.

---

## Finding 3 — Database secrets plugins: static-role username → default SQL injection

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `plugins/database/mysql/mysql.go` (primary; same class in PostgreSQL / MSSQL / HANA / Redshift defaults) |
| **Attacker** | Authenticated principal with `create`/`update` on `database/static-roles/*` for an affected connection (delegated DB onboarding; not Vault root). Exploitable when rotation/revocation statements are empty/omitted — including when ACLs deny custom statements. |
| **Input** | Static-role `username` (`framework.TypeString`, no identifier validation) |
| **Impact** | Arbitrary SQL / password reset / privilege escalation as the Vault database management principal |

### Attack path (MySQL default rotate)

1. Admin configures a MySQL connection with a privileged Vault management user.
2. Attacker creates a static role with empty rotation statements and username:
   `victim'@'%' IDENTIFIED BY 'pwned';#`
3. Rotation → `changeUserPassword` → `QueryHelper` with default template:
   `ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';`
4. Rendered SQL becomes:
   `ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned';#'@'%' IDENTIFIED BY '<vault-password>';`
5. MySQL applies the attacker-chosen password to `victim`; `#...` is a line comment.

### Evidence

```26:27:plugins/database/mysql/mysql.go
	defaultMySQLRotateCredentialsSQL = `
		ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
```

```211:217:plugins/database/mysql/mysql.go
func (m *MySQL) changeUserPassword(ctx context.Context, username, password string, rotateStatements []string) error {
	// ...
		rotateStatements = []string{defaultMySQLRotateCredentialsSQL}
```

Related unquoted sinks (same privilege-boundary class):

- PostgreSQL `defaultChangePasswordStatement` — `ALTER ROLE "{{username}}" ...`
- MSSQL `alterLoginSQL` — `ALTER LOGIN [{{username}}] ...` (no `]` escaping)
- HANA default rotate/revoke — unquoted `{{username}}` / `%s`
- Redshift revoke — `call terminateloop('%s')` without `QuoteIdentifier` (`plugins/database/redshift/redshift.go:451`)

### Remediation

Never interpolate raw usernames into SQL. Use parameterized statements or database-specific identifier quoting (`QuoteIdentifier` / `QuoteName` with proper escaping). Validate usernames against a strict identifier charset before use. Prefer deny-by-default when custom statements are omitted rather than insecure defaults.

---

## Finding 4 — AWS auth IAM/EC2 client cache missing account ID (CVE-2025-11621)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `builtin/credential/aws/client.go` |
| **Attacker** | Unauthenticated AWS principal from a **different** AWS account that can present a valid STS/EC2 identity |
| **Input** | IAM login (`iam_request_*`) or EC2 login against roles whose binds use wildcards / colliding friendly names under multi-account STS |
| **Impact** | Cross-account authentication into Vault roles intended for another AWS account |

### Attack path

1. Vault AWS auth is configured with a role whose `bound_iam_principal_arn` includes wildcards (e.g. `arn:aws:iam::111111111111:role/MyRole*`), and/or multi-account STS with empty STS role for the default account.
2. A legitimate login from account `111111111111` creates and caches an IAM (or EC2) client keyed only by `region` + `stsRole` (empty string for default account) — **not** `accountID`.
3. Attacker from account `222222222222` with a colliding role/user friendly name authenticates via STS `GetCallerIdentity`.
4. Wildcard bind resolution calls `clientIAM(ctx, s, region, attackerAccountID)`.
5. Cache hit returns the **default/account-A** client without re-validating `accountID`.
6. `GetRole`/`GetUser` against account A returns an ARN that matches the configured wildcard bind → Vault issues a token for the attacker.

### Evidence

```76:86:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	EC2ClientsMap map[string]map[string]*ec2.EC2
	// Map to hold the IAM client objects indexed by region and STS role.
	IAMClientsMap map[string]map[string]*iam.IAM
```

```274:290:builtin/credential/aws/client.go
func (b *backend) clientIAM(ctx context.Context, s logical.Storage, region, accountID string) (*iam.IAM, error) {
	stsRole, stsExternalID, err := b.stsRoleForAccount(ctx, s, accountID)
	// ...
	b.configMutex.RLock()
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

Account ID is checked only on cache miss in `getClientConfig` when `stsRole == ""`; the cached path skips that check.

### Remediation

Include `accountID` in the client cache key (or never share a client across accounts when `stsRole` is empty). Re-validate assumed-role / default credentials match the requested account on every cache hit. Fixed upstream as CVE-2025-11621 (CE 1.21.0 / Ent 1.20.5+).

---

## Finding 5 — File audit device → plugin directory host RCE (CVE-2025-6000)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Location** | `audit/backend_file.go` |
| **Attacker** | Privileged root-namespace operator with write on `sys/audit` (and ability to register/mount a plugin when `plugin_directory` is configured) — **not** necessarily a root token or host admin |
| **Input** | Audit device `file_path` / legacy `path` under the configured plugin directory; optional `prefix` / request shaping to materialize binary bytes; SHA256 via `sys/audit-hash` |
| **Impact** | Arbitrary code execution on the Vault host when the written file is registered and executed as an external plugin |

### Attack path

1. Vault is configured with `plugin_directory` set.
2. Attacker enables a file audit device with `file_path` under that directory — `newFileBackend` / `enableAudit` perform **no** path restriction against the plugin directory on this tree.
3. Attacker shapes request traffic (and optional `prefix`) so the audit log file bytes are a valid plugin binary; uses `sys/audit-hash` with the device HMAC path described in HCSEC-2025-14 to obtain the required SHA256.
4. Attacker registers the file in `sys/plugins/catalog` and mounts/uses it → Vault `exec`s the binary from the plugin directory.

### Evidence

```48:57:audit/backend_file.go
	var filePath string
	if p, ok := conf.Config[optionFilePath]; ok {
		filePath = p
	} else if p, ok = conf.Config["path"]; ok {
		filePath = p
	} else {
		return nil, fmt.Errorf("%q is required: %w", optionFilePath, ErrExternalOptions)
	}
```

No check that `filePath` is outside `plugin_directory`. Plugin catalog then joins the command under that directory and executes it.

### Remediation

Forbid audit destinations under the plugin directory; disable audit `prefix` by default (`AllowAuditLogPrefixing`). Fixed upstream as CVE-2025-6000 (CE 1.20.1 / Ent 1.18.12+).

---

## Areas reviewed — no additional medium+ validated findings

| Area | Result |
| --- | --- |
| **Webhooks** | No webhook/callback URL feature in this OSS tree that fetches attacker-controlled URLs. |
| **Identity group aliases SSRF** | Group aliases are names attached at login; no HTTP fetch of alias content. |
| **Azure / GCP auth** | Not present under `builtin/credential/` in this OSS checkout (external plugins / agent-only clients). |
| **Agent / proxy SSRF** | `command/agentproxyshared/cache` forwards to the configured Vault API address only; no open proxy to arbitrary hosts. Auto-auth token use is intentional/local. |
| **UI asset path traversal** | `UIAssetWrapper` serves embedded `assetFS()`; no filesystem escape of `/ui/`. |
| **File physical storage traversal** | Not present as a separate package on this tree; CouchDB uses `url.PathEscape` on Put/Delete paths. |
| **LDAP injection** | Login user/group filters use `ldap.EscapeFilter` on username (`sdk/helper/ldaputil/client.go`). `EscapeLDAPValue` in `GetUserDN` filter is imperfect but only runs post-bind with authenticated username — no validated medium+ login-time injection. |
| **Command injection** | Plugin catalog rejects `..` and confines commands to the plugin directory; no remote API → shell path found. |
| **UI XSS / custom messages** | Ember auto-escaping / DOMPurify on reviewed surfaces; no medium+ XSS validated. |
| **Unsafe URL redirects** | Standby redirect uses cluster leader address (not client-controlled Host); UI redirects to fixed `/ui/`; OIDC provider enforces redirect allowlist. |
| **Secrets leakage to unauthenticated callers** | Unauth health/seal-status/feature-flags do not return secrets; ACME challenge errors do not return fetched bodies to the client. |
| **Raft join / bootstrap** | Intentionally unauthenticated for cluster formation; not reported as a vuln without a post-init join abuse path. |
| **Cert CRL URL fetch** | SSRF requires admin CRL config write — admin-configured fetch, excluded. |
| **GitHub `base_url` / AWS `sts_endpoint`** | Admin-configured endpoints only. |

---

## Summary

| # | Title | Severity | Location |
| --- | --- | --- | --- |
| 1 | Identity root policy case bypass (CVE-2025-5999) | High | `vault/identity_store_entities.go` |
| 2 | PKI ACME challenge validation SSRF (CVE-2026-5052) | Medium | `builtin/logical/pki/acme_challenges.go` |
| 3 | Database static-role username SQL injection | High | `plugins/database/mysql/mysql.go` |
| 4 | AWS auth client cache missing account ID (CVE-2025-11621) | High | `builtin/credential/aws/client.go` |
| 5 | File audit → plugin directory host RCE (CVE-2025-6000) | High | `audit/backend_file.go` |
