# Application security review — targeted surfaces at `0513545dd` (Vault 1.18.0-beta1)

Scope: AWS auth IAM/client-cache; PKI ACME HTTP-01; audit file sink; agent auto-auth; Authorization passthrough; Duo MFA Trusted Networks; userpass/LDAP lockout case variants.

## Valid findings

### 1. AWS Auth IAM/EC2 client cache cross-account auth bypass

| Field | Value |
| --- | --- |
| Severity | **High** (CVE-2025-11621 / HCSEC-2025-30, CVSS 8.1) |
| Attacker | Any IAM/EC2 principal that can call unauthenticated `auth/aws/login`, with a role name (or wildcard) colliding with a trusted account |
| Input | Valid STS `GetCallerIdentity` login material for the attacker’s AWS account; Vault role with wildcard / same-name `bound_iam_principal_arn` across accounts |
| Path | Login → `fullArn` / EC2 validation → `clientIAM`/`clientEC2` cache hit by `region`+`stsRole` only → wrong-account AWS client reused → binding check satisfied |
| Impact | Cross-account authentication bypass → Vault token for the victim role |
| Location | `builtin/credential/aws/client.go` |

Evidence — cache keyed without `accountID`:

```227:231:builtin/credential/aws/client.go
	b.configMutex.RLock()
	if b.EC2ClientsMap[region] != nil && b.EC2ClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		// If the client object was already created, return it
		return b.EC2ClientsMap[region][stsRole], nil
```

```284:289:builtin/credential/aws/client.go
	b.configMutex.RLock()
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		// If the client object was already created, return it
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
```

Wildcard ARN resolution uses that client (`fullArn` → `clientIAM`), then glob-matches `bound_iam_principal_arn`:

```1433:1448:builtin/credential/aws/path_login.go
			fullArn := b.getCachedUserId(callerUniqueId)
			if fullArn == "" {
				fullArn, err = b.fullArn(ctx, entity, req.Storage)
				// ...
				b.setCachedUserId(callerUniqueId, fullArn)
			}
			matchedWildcardBind := false
			for _, principalARN := range roleEntry.BoundIamPrincipalARNs {
				if strings.HasSuffix(principalARN, "*") && strutil.GlobbedStringsMatch(principalARN, fullArn) {
					matchedWildcardBind = true
					break
				}
			}
```

**Remediation:** Key EC2/IAM client caches by `accountID` (and region/role), as in Vault CE 1.21.0 / Ent 1.20.5+. Avoid wildcards / cross-account same-name binds in `bound_iam_principal_arn`.

---

### 2. PKI ACME HTTP-01 / TLS-ALPN-01 SSRF to internal targets

| Field | Value |
| --- | --- |
| Severity | **Medium** (CVE-2026-5052 / HCSEC-2026-06) |
| Attacker | Unauthenticated ACME client when EAB is not required; otherwise holder of an EAB token |
| Input | ACME order identifier / DNS name under attacker control (resolves to link-local, loopback, or RFC1918), or HTTP-01 redirect to an internal URL |
| Path | `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge` dials resolved address with no private-IP block; HTTP client follows redirects |
| Impact | Vault server initiates connections to internal network targets (SSRF); response body used only for key authorization, but connection/timing/errors enable recon and some info disclosure |
| Location | `builtin/logical/pki/acme_challenges.go` |

Evidence — no destination allow/deny; redirects allowed; TLS verify skipped on redirects:

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:           dialer.DialContext,
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via)+1 >= maxRedirects {
				return fmt.Errorf("http-01: too many redirects: %v", len(via)+1)
			}
			// length check only — no private/link-local/metadata IP rejection
			return nil
		},
	}
	resp, err := client.Get(path)
```

TLS-ALPN likewise dials `domain:443` via the same dialer with no IP class checks (`ValidateTLSALPN01Challenge`).

**Remediation:** Reject loopback/link-local/private/metadata destinations after resolution (and again on redirects); optionally disable ACME or require EAB on internet-facing mounts. Fixed in Vault CE 2.0.0 / Ent 1.21.5+.

---

### 3. Userpass / LDAP user lockout bypass via username case variants

| Field | Value |
| --- | --- |
| Severity | **Medium** (CVE-2025-6004 / HCSEC-2025-16) |
| Attacker | Unauthenticated remote client able to hit userpass or LDAP login |
| Input | Username with alternating character case (`user` / `User` / `USER`) and wrong passwords |
| Path | Lockout key from `AliasLookahead` (case-preserving) ≠ login canonicalization → separate failure counters per variant → threshold never reached for the real account |
| Impact | Brute-force / password-spray past the user-lockout control (enabled by default for userpass/LDAP) |
| Location | `builtin/credential/userpass/path_login.go` (LDAP: `builtin/credential/ldap/path_login.go`) |

Evidence — lockout alias is raw username; login storage key is lowercased:

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username, // NOT lowercased
			},
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

Lockout uses that alias as the map key:

```2155:2168:vault/request_handling.go
func (c *Core) getLoginUserInfoKey(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (FailedLoginUser, error) {
	// ...
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
	userInfo.mountAccessor = mountEntry.Accessor
	return userInfo, nil
}
```

LDAP `pathLoginAliasLookahead` likewise returns the request username without applying `case_sensitive_names` normalization; failed binds return `logical.ErrInvalidCredentials`, so lockout increments per case variant.

**Remediation:** Normalize AliasLookahead the same way as login (userpass: always lower; LDAP: honor `case_sensitive_names`). Fixed in Vault CE 1.20.1 / Ent 1.19.7+.

---

## Rejected (not valid at this commit / out of policy)

| Surface | Reason |
| --- | --- |
| Audit file sink → plugin dir / RCE (CVE-2026-5051) | Plugin-directory guard + legacy `path` bypass landed in later lines (CE ≥1.20.1 / Ent ≥1.19). At `0513545dd` enabling a file audit device already requires privileged audit-enable; treated as admin-only capability, not a low-priv path. |
| Agent auto-auth token leak | `sanitizeAutoAuthTokenResponse` strips id/accessor on lookup/renew of the auto-auth token. Remaining exposure is intentional `use_auto_auth_token` / file-sink design, not an unauth disclosure bug. |
| Authorization header passthrough (CVE-2026-4525) | At this revision, `CheckToken` always strips `Authorization: Bearer` when `ClientTokenSource == ClientTokenFromAuthzHeader`. The broken condition (`!unauth && te == nil`) that HCSEC-2026-07 fixed was introduced later. Residual dual-header (`X-Vault-Token` + `Authorization`) needs admin-tuned passthrough to an untrusted plugin — rejected as admin-gated. |
| Duo MFA Trusted Networks / validate-IP bypass | Client IP is passed into Duo Preauth/Auth (`validateDuo`). Unconditional accept of Duo `allow` is Trusted Networks’ intended Duo behavior. XFF spoofing requires listener `x_forwarded_for_authorized_addrs` misconfig — admin-only. |
