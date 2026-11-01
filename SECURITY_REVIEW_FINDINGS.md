# Application Security Review — AuthN/AuthZ Bypass

**Repo:** github.com/tiobagio/vault (fork of hashicorp/vault)  
**Commit reviewed:** `0513545dd` (tree `1.18.0-beta1`)  
**Scope:** Authentication / authorization bypass with end-to-end attack paths for unauthenticated or low-privilege attackers.

Only validated medium+ findings are listed.

---

## 1. AWS auth — cross-account auth bypass via IAM/EC2 client cache missing AccountID

- **Severity:** High (CVE-2025-11621 / HCSEC-2025-30 class)
- **Attacker:** Holder of valid AWS IAM/EC2 credentials in an AWS account that is **not** the Vault default credential account and is **not** registered (or shares an STS role string) under `auth/aws/config/sts`
- **Controlled input:** Signed STS `GetCallerIdentity` request (IAM auth) or EC2 identity document; role name colliding with a trusted-account principal
- **Reachability:**
  1. AWS auth mount uses IAM auth with `bound_iam_principal_arn` wildcards (and/or EC2 validation via `DescribeInstances`)
  2. Legitimate traffic from the default/trusted account populates `IAMClientsMap[region][stsRole]` / `EC2ClientsMap[region][stsRole]` (empty `stsRole` = default account)
  3. Attacker authenticates to STS successfully (own account identity is correct)
  4. Wildcard bind resolution calls `fullArn` → `clientIAM(region, attackerAccountID)`
  5. Cache hit returns the **trusted account’s** IAM client because the map key is only `(region, stsRole)`, not `accountID`
  6. `GetUser`/`GetRole` by friendly name returns the trusted account ARN → wildcard bind succeeds
- **Impact:** Authenticate to Vault roles intended for another AWS account (cross-account privilege escalation into Vault)
- **Primary location:** `builtin/credential/aws/client.go`

### Evidence

Cache keyed only by region + STS role; cache hit skips the `defaultAWSAccountID != accountID` check in `getClientConfig`:

```285:290:builtin/credential/aws/client.go
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		// If the client object was already created, return it
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

`fullArn` looks up principals by **name** through that client:

```1888:1914:builtin/credential/aws/path_login.go
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
	// ...
	case "user":
		input := iam.GetUserInput{
			UserName: aws.String(e.FriendlyName),
		}
		resp, err := client.GetUserWithContext(ctx, &input)
```

Wildcard bind trusts that resolved ARN:

```1445:1449:builtin/credential/aws/path_login.go
			for _, principalARN := range roleEntry.BoundIamPrincipalARNs {
				if strings.HasSuffix(principalARN, "*") && strutil.GlobbedStringsMatch(principalARN, fullArn) {
					matchedWildcardBind = true
					break
```

### Why not a false positive

- End-to-end path does not require admin compromise: only AWS principal credentials + common wildcard bind config
- Creation path correctly rejects wrong `accountID` when building a **new** client; only the cache hit omits the check
- Same pattern exists for `EC2ClientsMap` (`clientEC2`), enabling instance-ID confusion across accounts

---

## 2. Userpass / LDAP — user lockout bypass via case-variant AliasLookahead

- **Severity:** Medium (CVE-2025-6004 / HCSEC-2025-16 class)
- **Attacker:** Unauthenticated client guessing passwords against Userpass (always) or LDAP with `case_sensitive_names=false` (default)
- **Controlled input:** Username casing on `auth/<mount>/login[/...]`
- **Reachability:**
  1. Lockout keys are `(aliasNameFromLoginRequest, mountAccessor)` where alias name comes from `AliasLookaheadOperation`
  2. Userpass `pathLogin` lowercases the username for authentication/storage, but `pathLoginAliasLookahead` returns the **raw** username
  3. LDAP alias lookahead likewise returns the raw username
  4. Attacker rotates `Admin` / `ADMIN` / `AdMiN` / … → each casing gets its own failed-login counter (default threshold 5)
  5. Correct password still authenticates because login path normalizes case
- **Impact:** Bypass of user lockout; sustained online password guessing
- **Primary location:** `builtin/credential/userpass/path_login.go`

### Evidence

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username,
			},
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

Lockout key uses lookahead alias:

```2155:2168:vault/request_handling.go
func (c *Core) getLoginUserInfoKey(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (FailedLoginUser, error) {
	// ...
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
```

Default threshold is 5 (`internalshared/configutil/userlockout.go`).

### Why not a false positive

- Lockout is enabled by default for userpass/ldap/approle
- Authentication succeeds across case variants while counters do not share state
- Successful-login cleanup uses the lowercased `auth.Alias.Name`, so it does not clear the per-casing failure keys either

---

## 3. Login MFA (Duo) — Trusted Networks / IP policy bypass on `sys/mfa/validate`

- **Severity:** Medium–High (High when Duo Trusted Networks or IP allow policies are enabled)
- **Attacker:** Low-privilege user with valid primary credentials who can source the MFA validate request from a Duo-trusted IP (or otherwise Duo-allowed IP)
- **Controlled input:** `mfa_request_id` from a prior login; source IP of `POST /v1/sys/mfa/validate` (unauthenticated path)
- **Reachability:**
  1. Login MFA enforcement uses Duo; Duo Trusted Networks (or similar) returns Preauth `allow` for trusted IPs
  2. Primary login from an **untrusted** IP caches auth and stores `RequestConnRemoteAddr` with an explicit comment that it is needed for Duo
  3. `handleMFALoginValidate` ignores the cached login IP and passes `req.Connection.RemoteAddr` (the **validate** request IP) into `validateDuo`
  4. Duo Preauth `allow` short-circuits MFA (`return nil`) → token issued without push/passcode
- **Impact:** Bypass of Vault login MFA when Duo IP/Trusted-Network policy would allow the validate IP
- **Primary location:** `vault/login_mfa.go`

### Evidence

Login IP is cached for Duo but never consumed on validate:

```1801:1807:vault/request_handling.go
				respAuth := &MFACachedAuthResponse{
					CachedAuth:            resp.Auth,
					RequestPath:           req.Path,
					RequestNSID:           ns.ID,
					RequestNSPath:         ns.Path,
					RequestConnRemoteAddr: req.Connection.RemoteAddr, // this is needed for the DUO method
```

Validate uses the MFA request’s IP instead:

```746:748:vault/login_mfa.go
	for _, eConfig := range matchedMfaEnforcementList {
		err = b.Core.validateLoginMFA(ctx, eConfig, entity, req.Connection.RemoteAddr, mfaCreds)
```

Duo Trusted Network short-circuit:

```1896:1909:vault/login_mfa.go
	preauth, err := authClient.Preauth(authapi.PreauthUsername(username), authapi.PreauthIpAddr(reqConnectionRemoteAddr))
	// ...
	switch preauth.Response.Result {
	case "allow":
		return nil
```

`sys/mfa/validate` is unauthenticated (`vault/logical_system.go`).

### Why not a false positive

- Cached field exists solely for Duo and is unused — clear implementation bug vs. intent
- Preauth `allow` is an intentional Duo Trusted Networks success path that skips secondary factors
- Attacker only needs primary credentials + ability to hit validate from an allowed IP; no Duo factor possession required

---

## Areas checked — no additional medium+ authz bypass validated

| Area | Outcome |
|------|---------|
| HTTP unauthenticated routes (init/unseal/health/metrics/pprof/raft) | Intentional or admin-gated; raft bootstrap DoS is availability-only (out of authz-bypass scope for this report) |
| CORS / X-Forwarded-For / forwarded client cert | XFF and cert injection require authorized proxy addrs; no unauth bypass without misconfig |
| Wrapping JWT / third-party unwrap / `HasSuffix` NS special-case | Policy still limited to wrapping paths; no escalate-to-arbitrary-secret path validated |
| Token store sudo / orphan / policy subset / entity_alias | Checks present; no bypass validated |
| ACL segment-wildcard / sudo path matching | Matching logic consistent; no escalate path validated |
| AppRole bind_secret_id / CIDR | No bypass without secret_id when binding enabled |
| GitHub org TOFU / team mapping | Membership checked by `organization_id` |
| Cert auth | Requires trusted client cert; XFF cert path gated on authorized addrs |
| Okta `verify/*` correct_answer | Intentional number-challenge UX; nonce required |
| Identity OIDC provider token/authorize | Client auth + PKCE + redirect allow-list look sound |
| sdk/framework capability checks | Enforcement is in core ACL, not framework |
| JWT/OIDC auth method | Not present in this OSS tree (external plugin) |
