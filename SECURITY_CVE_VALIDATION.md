# Vault CVE Validation Report

**Tree:** `0513545dd` (`version/VERSION` = `1.18.0-beta1`, tip dated 2024-06-06)  
**Branch:** `cursor/application-security-review-71e7`  
**Method:** Static code review against vendor advisories and published patches. No live exploit execution.

**Verdict summary**

| CVE | Status | Severity (vendor/NVD) |
|-----|--------|------------------------|
| CVE-2024-7594 | **STILL_VULNERABLE** | High (HC 7.5 / NVD 8.8) |
| CVE-2025-11621 | **STILL_VULNERABLE** | High (8.1) |
| CVE-2025-6013 | **STILL_VULNERABLE** | Medium–High (HC 6.5 / NVD 8.1) |

None of the upstream fix commits are present in this tree (`allow_empty_principals`, `clientKey{AccountID,...}`, LDAP DN-derived alias).

---

## 1. CVE-2024-7594 — SSH empty principals → cert valid as any user

**Status:** STILL_VULNERABLE  
**Severity:** High  
**Primary location:** `builtin/logical/ssh/path_issue_sign.go`

### Attacker
Authenticated Vault client with capability to call `ssh/sign/:role` or `ssh/issue/:role` on a CA role whose `default_user` is empty (and who omits or empties `valid_principals`).

### Controlled input
Request field `valid_principals` (omit or set empty). Role config with empty `default_user` is the enabling condition (admin misconfiguration / insecure default).

### Reachability
1. Caller invokes sign/issue helper → `pathSignIssueCertificateHelper`.
2. `calculateValidPrincipals` treats empty parsed principals as success and returns `nil, nil`.
3. Certificate is signed with empty `ValidPrincipals`.
4. OpenSSH semantics: empty principals ⇒ certificate matches any user/host principal of that cert type.

### Impact
Host privilege escalation / identity assumption: holder of an otherwise-authorized Vault token can obtain an SSH user certificate accepted as **any** local user on hosts trusting the Vault SSH CA (e.g. root), subject to other SSH server constraints.

### Evidence

No `allow_empty_principals` / `AllowEmptyPrincipals` exists anywhere under `builtin/logical/ssh` (patch from upstream `12f03b07` / HCSEC-2024-20 is absent).

Empty-principals path still succeeds unconditionally:

```192:196:builtin/logical/ssh/path_issue_sign.go
	switch {
	case len(parsedPrincipals) == 0:
		// There is nothing to process
		return nil, nil
```

Those principals are written into the signed cert with no further check:

```506:513:builtin/logical/ssh/path_issue_sign.go
	certificate := &ssh.Certificate{
		Serial:          serialNumber.Uint64(),
		Key:             b.PublicKey,
		KeyId:           b.KeyID,
		ValidPrincipals: b.ValidPrincipals,
		ValidAfter:      uint64(now.Add(-b.Role.NotBeforeDuration).In(time.UTC).Unix()),
		ValidBefore:     uint64(now.Add(b.TTL).In(time.UTC).Unix()),
		CertType:        b.CertificateType,
```

Upstream fix rejects empty principals unless `role.AllowEmptyPrincipals` (default `false`).

### Skeptical notes
- Not an unauthenticated RCE: requires Vault ACL access to the SSH role.
- Specifying a non-empty `valid_principals` against an empty `allowed_users` still errors (`role is not configured to allow any principals`); the bug is specifically the **empty** principals → “any user” OpenSSH behavior.
- `allowed_users = "*"` is intentional any-principal and is out of scope for this CVE.

---

## 2. CVE-2025-11621 — AWS IAM/EC2 auth client cache cross-account confusion

**Status:** STILL_VULNERABLE  
**Severity:** High  
**Primary location:** `builtin/credential/aws/client.go`

### Attacker
AWS principal in account B that can complete Vault AWS IAM (or EC2) login against a role whose `bound_iam_principal_arn` uses a wildcard and/or shares a role/user name with a trusted account A.

### Controlled input
Login identity material (signed STS `GetCallerIdentity` headers / EC2 identity document) selecting account B and a principal name that collides with account A under the configured bind/wildcard.

### Reachability
1. Some prior request for the **default** account caches an IAM/EC2 client under `map[region][stsRole]` with `stsRole == ""`.
2. Login for account B with **no** `auth/aws/config/sts/<accountB>` entry resolves `stsRoleForAccount` → `""`.
3. `clientIAM` / `clientEC2` return the cached default-account client **without** re-checking `accountID` (account check in `getClientConfig` is skipped on cache hit).
4. Wildcard bind path calls `fullArn` → `GetRole`/`GetUser` against the **wrong** account; a same-named role in A yields A’s ARN, which can satisfy binds like `arn:aws:iam::*:role/Name` or A-scoped wildcards.

### Impact
Authentication bypass / cross-account privilege gain: principal in an untrusted (or secondary) AWS account obtains a Vault token for a role intended for another account’s identically named principal.

### Evidence

Cache is still region + STS role only (no account ID). Backend maps:

```76:86:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	// This avoids the overhead of creating a client object for every login request.
	// When the credentials are modified or deleted, all the cached client objects
	// will be flushed. The empty STS role signifies the master account
	EC2ClientsMap map[string]map[string]*ec2.EC2

	// Map to hold the IAM client objects indexed by region and STS role.
	// This avoids the overhead of creating a client object for every login request.
	// When the credentials are modified or deleted, all the cached client objects
	// will be flushed. The empty STS role signifies the master account
	IAMClientsMap map[string]map[string]*iam.IAM
```

Cache hit ignores `accountID`:

```274:290:builtin/credential/aws/client.go
func (b *backend) clientIAM(ctx context.Context, s logical.Storage, region, accountID string) (*iam.IAM, error) {
	stsRole, stsExternalID, err := b.stsRoleForAccount(ctx, s, accountID)
	if err != nil {
		return nil, err
	}
	// ...
	b.configMutex.RLock()
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		// If the client object was already created, return it
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

`stsRoleForAccount` still returns empty STS role for accounts with no STS config (no “non-default requires STS config” error from the 1.21 patch):

```208:218:builtin/credential/aws/client.go
func (b *backend) stsRoleForAccount(ctx context.Context, s logical.Storage, accountID string) (string, string, error) {
	// Check if an STS configuration exists for the AWS account
	sts, err := b.lockedAwsStsEntry(ctx, s, accountID)
	if err != nil {
		return "", "", fmt.Errorf("error fetching STS config for account ID %q: %w", accountID, err)
	}
	// An empty STS role signifies the master account
	if sts != nil {
		return sts.StsRole, sts.ExternalID, nil
	}
	return "", "", nil
}
```

`fullArn` uses that confused client to resolve names:

```1889:1914:builtin/credential/aws/path_login.go
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
	// ...
	case "role":
		input := iam.GetRoleInput{
			RoleName: aws.String(e.FriendlyName),
		}
		resp, err := client.GetRoleWithContext(ctx, &input)
```

Upstream fix (`8d07273`) introduces `clientKey{AccountID, Region, STSRole}` and rejects missing STS config for non-default accounts.

### Skeptical notes
- Requires AWS auth mounted and a colliding bind (wildcard and/or same principal name across accounts). Exact ARN binds with `resolve_aws_unique_ids=true` and no wildcards are much harder to abuse via this cache bug.
- Cache must already hold the default-account client (common after any prior default-account IAM/EC2 API use).
- Distinct per-account STS role ARNs as cache keys reduce (but do not fully eliminate, per upstream’s account-id keying) collision risk; the empty-`stsRole` default-account case is the clearest path in this tree.

---

## 3. CVE-2025-6013 — LDAP `username_as_alias` MFA enforcement bypass

**Status:** STILL_VULNERABLE  
**Severity:** Medium (HashiCorp 6.5) / High (NVD 8.1)  
**Primary location:** `builtin/credential/ldap/backend.go`  
*(alias assigned in `path_login.go`; MFA matching is identity-store / login-MFA, driven by that alias)*

### Attacker
Party with valid LDAP credentials for a directory user, where MFA is enforced on the canonical entity/alias, and the directory admits username/CN variants that differ only by leading/trailing whitespace (or LDAP bind succeeds for a whitespace-variant input).

### Controlled input
`username` on `auth/ldap/login/:username` (whitespace variants), with mount config `username_as_alias=true`.

### Reachability
1. LDAP auth succeeds; bind DN is discovered/normalized by the LDAP client.
2. With `username_as_alias`, `Login` returns the **raw request username** as the entity alias — not the DN attribute value.
3. `pathLogin` sets `Alias.Name = effectiveUsername` from that raw value.
4. Login MFA enforcements keyed to the canonical entity/alias do not match the whitespace-variant alias → second factor not required / wrong entity created.

### Impact
MFA **enforcement** bypass (not merely enrollment UI): attacker completes password auth and receives a Vault token without satisfying configured login MFA. Can also create a parallel entity alias that never inherited MFA enrollment.

### Evidence

Raw username returned as alias source:

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

Used directly as alias name (metadata keeps the same raw username):

```82:103:builtin/credential/ldap/path_login.go
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	effectiveUsername, policies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	// ...
	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
		},
		// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
			Metadata: map[string]string{
				"name": username,
			},
		},
	}
```

Upstream fix (PR #31427 / `a72d310`) parses `c.UserDN` and sets the alias from the `userattr` RDN value so whitespace variants collapse to the directory-canonical name. That DN-derived path is absent here.

### Skeptical notes
- Only applies when `username_as_alias=true`. With the default (`false`), alias comes from LDAP user attribute values (different code path).
- Needs a directory/auth path where whitespace-variant usernames still bind successfully (advisory: multiple CNs equal modulo spaces).
- Severity depends on MFA being bound to entity/alias identity; auth-method-wide MFA may still apply depending on enforcement selectors — advisory still treats the alias split as an MFA enforcement failure in affected configs.

---

## Patch presence check

| Fix | Upstream | In this tree? |
|-----|----------|---------------|
| SSH `allow_empty_principals` | `12f03b07` (→ 1.17.6) | No |
| AWS `clientKey` + STS required for non-default | `8d07273` (→ 1.21.0) | No |
| LDAP alias from UserDN/`userattr` | `a72d310` / #31427 (→ 1.20.2) | No |

This snapshot predates all three fixes despite the `1.18.0-beta1` version label (tip is 2024-06-06; SSH fix landed 2024-09).
