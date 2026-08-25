# Application Security Review Findings

**Target:** HashiCorp Vault OSS (`tiobagio/vault`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version file:** `1.18.0-beta1`  
**Scope:** Authentication/authorization bypass, token handling, privilege escalation, MFA bypass, identity/entity/alias confusion in `http/`, `vault/`, `builtin/credential/`, `command/agent/`, `command/proxy/`

---

## Finding 1 — HIGH — LDAP `username_as_alias` MFA / identity bypass via whitespace (CVE-2025-6013 / HCSEC-2025-20)

### Attacker
Unauthenticated network attacker who knows (or can guess) a valid LDAP username/password for a user that is subject to Login MFA enforced on that user's **entity** or **identity group** (not solely on auth-method accessor/type).

### Preconditions
- LDAP auth method enabled with `username_as_alias=true`
- Login MFA enforcement bound to the victim's entity ID and/or identity group IDs
- LDAP directory accepts a whitespace-variant of the username (common with Active Directory / multi-CN setups that normalize spaces)

### Controlled input
HTTP path/body username string, e.g. `alice` vs `alice ` (trailing/leading space), plus the victim's password.

### Attack path
1. Victim `alice` has MFA enrolled and enforcement matching entity/group of alias `alice`.
2. Attacker authenticates to `auth/ldap/login/alice%20` (or body username with trailing space) with alice's password.
3. LDAP bind/search succeeds after directory-side normalization.
4. Vault sets the entity alias to the **raw** request username (`alice `), not the normalized directory attribute.
5. `CreateOrFetchEntity` creates a **new** entity for alias `alice `.
6. MFA enforcement matched by the original entity/group does **not** apply to the new entity → token issued without MFA.

### Impact
Complete Login MFA bypass for LDAP users under entity/group-scoped MFA; attacker obtains a Vault client token with the LDAP-mapped policies of the victim account.

### Primary location
`builtin/credential/ldap/backend.go`

### Evidence

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

```82:100:builtin/credential/ldap/path_login.go
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	effectiveUsername, policies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	// ...
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
```

Alias lookahead (also used for lockout keys) likewise uses the raw username:

```47:59:builtin/credential/ldap/path_login.go
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}
```

MFA matching is keyed off entity ID / group IDs (so a new entity skips those bindings):

```1757:1771:vault/login_mfa.go
			if strutil.StrListContains(eConfig.IdentityEntityIDs, entity.ID) {
				matchedMfaEnforcementConfig = append(matchedMfaEnforcementConfig, eConfig)
				continue
			}
			// ...
			for _, g := range directGroups {
				if strutil.StrListContains(eConfig.IdentityGroupIds, g.ID) {
					matchedMfaEnforcementConfig = append(matchedMfaEnforcementConfig, eConfig)
					continue ECONFIG_LOOP
				}
			}
```

**Note:** If MFA is enforced only via `auth_method_accessors` / `auth_method_types`, this specific bypass does not apply (those still match the mount).

---

## Finding 2 — HIGH — Login MFA TOTP one-time-use / replay bypass via non-normalized passcodes (CVE-2025-6015 / HCSEC-2025-19)

### Attacker
Party who already completed first-factor auth (or obtained an `mfa_request_id` from a two-phase login) and can observe or reuse a valid TOTP code within its validity window (e.g., phishing the code, shared MFA device, or malicious concurrent session).

### Controlled input
TOTP passcode submitted via `X-Vault-MFA` or `sys/mfa/validate` payload — specifically whitespace-padded variants of a valid code (`"123456"`, `" 123456"`, `"123456 "`, `"123456\n"`).

### Attack path
1. Login MFA with TOTP is enforced; a valid code `C` is used once.
2. Vault records used-code key as `methodID + "_" + rawPasscode` **without** trimming.
3. `totplib.ValidateCustom` accepts leading/trailing whitespace/newlines as the same OTP.
4. Attacker resubmits `" "+C` (or trailing space / newline). Used-code cache miss → validation succeeds → second MFA success / token mint within the same OTP window.

Validated against the vendored dependency `github.com/pquerna/otp` used by this tree: `ValidateCustom` returns `valid=true` for `" CODE"`, `"CODE "`, and `"CODE\n"`.

### Impact
Breaks TOTP anti-replay / one-time-use guarantee for Login MFA; enables MFA reuse within the OTP validity window (and related rate-limit/anti-replay controls that key off the raw string).

### Primary location
`vault/login_mfa.go`

### Evidence

```2320:2392:vault/login_mfa.go
func (c *Core) validateTOTP(...) error {
	// ...
	passcode := mfaFactors.passcode

	usedName := fmt.Sprintf("%s_%s", configID, passcode)

	_, ok := usedCodes.Get(usedName)
	if ok {
		return fmt.Errorf("code already used; new code is available in %v seconds", totpSecret.Period)
	}
	// ...
	valid, err := totplib.ValidateCustom(passcode, key, time.Now(), validateOpts)
	// ...
	err = usedCodes.Add(usedName, nil, validityPeriod)
```

`parseMfaFactors` also stores the passcode without normalization:

```1821:1848:vault/login_mfa.go
func parseMfaFactors(creds []string) (*MFAFactor, error) {
	// ...
			mfaFactor.passcode = splits[1]
		// ...
			mfaFactor.passcode = cred
```

---

## Finding 3 — HIGH — User lockout bypass via alias-lookahead / auth username mismatch (CVE-2025-6004 / HCSEC)

### Attacker
Unauthenticated brute-force attacker targeting `userpass` and/or `ldap` mounts with user lockout enabled (default threshold = 5).

### Controlled input
Username spelling variants in the login path:
- **userpass:** case permutations (`admin`, `Admin`, `ADMIN`, …) — auth lowercases; lockout does not
- **ldap:** case and/or whitespace variants that the directory still authenticates as the same account

### Attack path (userpass)
1. `pathLogin` authenticates with `strings.ToLower(username)` → all case variants hit the same user record / bcrypt check.
2. Lockout counters are keyed by `aliasNameFromLoginRequest` → `AliasLookaheadOperation`.
3. Userpass alias lookahead returns the **raw** (non-lowercased) username.
4. Each case variant gets an independent failure counter (default 5), multiplying allowed guesses by `2^len(alpha_chars)`.

### Attack path (ldap)
Same lockout keying via raw alias lookahead; directory-normalized binds allow many string variants to count against separate lockout buckets while authenticating one account.

### Impact
Practical bypass of brute-force lockout for supported auth methods → enables offline-scale password guessing against live Vault login endpoints.

### Primary location
`vault/core.go` (lockout key derivation) + `builtin/credential/userpass/path_login.go`

### Evidence

Lockout key uses alias lookahead name:

```2155:2168:vault/request_handling.go
func (c *Core) getLoginUserInfoKey(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (FailedLoginUser, error) {
	// ...
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
	userInfo.mountAccessor = mountEntry.Accessor
```

```4268:4298:vault/core.go
func (c *Core) aliasNameFromLoginRequest(ctx context.Context, req *logical.Request) (string, error) {
	// ...
	resp, err := matchingBackend.HandleRequest(ctx, &logical.Request{
		// ...
		Operation:  logical.AliasLookaheadOperation,
		Data:       req.Data,
	})
	// ...
	return resp.Auth.Alias.Name, nil
}
```

Userpass: auth lowercases, lookahead does not:

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(...) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username,
			},
}

func (b *backend) pathLogin(...) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

Default lockout threshold:

```20:20:internalshared/configutil/userlockout.go
	UserLockoutThresholdDefault    = 5
```

---

## Candidates reviewed and rejected (brief)

| Area | Why rejected |
|------|----------------|
| Unauth `sys/metrics`, `pprof`, `in-flight-req` | Explicit listener opt-in; not a default auth bypass |
| Unauth `sys/mfa/validate` | By design for two-phase MFA; still requires valid MFA factors + request ID |
| Duo `RequestConnRemoteAddr` stored but unused on validate | Needs stolen `mfa_request_id` + Duo network allow; not a standalone high without that |
| Agent/proxy `use_auto_auth_token` | Intended capability for local clients; static secret cache gates on per-token allow-list |
| Identity auto-merge on alias conflict | Requires ability to assert the conflicting alias via a successful auth; not unauth privilege escalation |
| Token create sudo/orphan/root checks | Root/sudo gates present in `token_store.go`; no unexpected escalation found for non-privileged tokens |
| Cert auth non-CA public-key check | CVE-2024-2048 mitigation present (`ComparePublicKeysAndType`) at this commit |
| Wrapping unwrap / generate-root unauth paths | Shamir/OTP gated; expected recovery flows |

---

## Mapping to public advisories

These issues correspond to HashiCorp advisories fixed after this commit (Vault CE fixes in 1.20.1 / 1.20.2). This review independently re-validated the vulnerable code paths in-tree at `0513545`.
