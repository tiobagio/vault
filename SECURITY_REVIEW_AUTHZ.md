# Auth/Authz Application Security Review

**Tree:** `0513545dd` (`version/VERSION` = `1.18.0-beta1`)  
**Scope:** Authentication / authorization attack surfaces with medium+ severity and a concrete end-to-end path  
**Method:** Static tracing from attacker-controlled input through HTTP/logical handlers to privilege impact; cross-checked against HCSEC/CVE advisories where the vulnerable code is still present

---

## Finding 1 — Identity entity/group root policy case (and group whitespace) bypass (CVE-2025-5999)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker model** | Authenticated operator with write on root-namespace identity APIs (`identity/entity`, `identity/group`, …) — **not** a root token |
| **Controlled input** | `policies` array containing a case (entity/group) or whitespace (group) variant of `root`, e.g. `ROOT`, `Root`; groups also accept `" root "` |
| **Primary location** | `vault/identity_store_entities.go` |

### Attack path

1. Attacker holds a non-root token that can write identity entities/groups in the **root** namespace.
2. Victim (or attacker) already has a live token with `EntityID` set (normal login).
3. Attacker writes `policies=["ROOT"]` on that entity (or a group the entity belongs to).
4. Write path rejects only the exact string `"root"` via case-sensitive `StrListContains` after dedupe that does **not** lowercase (entity: `RemoveDuplicates(..., false)`; group: `RemoveDuplicatesStable(..., true)` which preserves original casing/spacing).
5. On the next request with the existing token, `fetchEntityAndDerivedPolicies` returns stored `ROOT`; `SanitizePolicies` lowercases it to `root` and collapses the set to `["root"]`.
6. `PolicyStore.GetPolicy` / `NewACL` treat that as the built-in root policy → `a.root = true` → full admin for the remainder of the token TTL.

Login-time minting is **not** the exploit vector: `LoginCreateToken` rejects when sanitized identity policies already contain `root`. Escalation is **post-login** entity/group policy update. Child namespaces do not grant root (`NewACL` errors outside root NS).

### Impact

Full Vault root privileges for any entity-bound token whose identity policies were poisoned.

### Evidence

```355:363:vault/identity_store_entities.go
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

```51:64:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	// ...
		policies[i] = strings.ToLower(strings.TrimSpace(p))
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
			// ...
			a.root = true
		}
```

---

## Finding 2 — AWS auth IAM/EC2 client cache missing account ID (CVE-2025-11621)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker model** | AWS principal in a secondary/connected account that can call Vault AWS auth login |
| **Controlled input** | Valid STS GetCallerIdentity (or EC2 identity) for a same-named / wildcard-colliding role in a different AWS account |
| **Primary location** | `builtin/credential/aws/client.go` |

### Attack path

1. Vault AWS auth is configured with `bound_iam_principal_arn` wildcards (or identical role names across accounts) and multi-account STS setup (or shared empty STS / master credentials).
2. A legitimate login for account A warms `IAMClientsMap` / `EC2ClientsMap` keyed only by `region` + `stsRole` (account ID discarded after STS role lookup).
3. Attacker in account B authenticates with a colliding role name / wildcard match.
4. Cache returns account A’s client; `fullArn` / EC2 validation runs in the wrong account context and can pass binds that encode account only via wildcard ARN metadata.
5. Attacker receives a Vault token for the role intended for another account.

### Impact

Cross-account authentication bypass → Vault token with the target role’s policies (secret access / further escalation depending on role).

### Evidence

```274:290:builtin/credential/aws/client.go
func (b *backend) clientIAM(ctx context.Context, s logical.Storage, region, accountID string) (*iam.IAM, error) {
	stsRole, stsExternalID, err := b.stsRoleForAccount(ctx, s, accountID)
	// ...
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		return b.IAMClientsMap[region][stsRole], nil
	}
```

Same pattern for EC2 at `clientEC2` (lines ~221–231). Backend documents maps as region+STS role only (`builtin/credential/aws/backend.go`). Wildcard bind resolution calls `fullArn` → `clientIAM` (`builtin/credential/aws/path_login.go`). Fixed upstream by caching clients by account ID (CE 1.21.0+); absent here.

---

## Finding 3 — LDAP `username_as_alias` MFA/identity bypass (CVE-2025-6013)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker model** | Party with valid LDAP credentials for a user; Login MFA enforced on the canonical **entity** (or identity binding keyed to the canonical alias) while `username_as_alias=true` |
| **Controlled input** | Login username whitespace/variant (`alice` vs ` alice` / `alice `) that still binds in LDAP |
| **Primary location** | `builtin/credential/ldap/backend.go` |

### Attack path

1. LDAP auth mount has `username_as_alias=true`. MFA enforcement is bound to the canonical entity/alias for user `alice`.
2. Attacker (or stolen password) logs in via `POST /v1/auth/ldap/login/<padded-username>` with a whitespace-variant username that LDAP still accepts.
3. Alias is set to the **raw** client-supplied username (no trim/canonicalize), creating a distinct entity alias.
4. `buildMFAEnforcementConfigList` does not match entity-scoped MFA for the new entity → MFA skipped.
5. Token is issued with LDAP-mapped policies from the successful bind/group resolution.

### Impact

Login MFA bypass; Vault token with the LDAP user’s policies without the second factor.

### Evidence

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

```16:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```90:103:builtin/credential/ldap/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
```

No `TrimSpace`/canonicalization of the alias before return. Mount-accessor–scoped MFA still applies; entity-ID–scoped MFA is the primary bypass.

---

## Finding 4 — Cert auth non-CA leaf CN impersonation (CVE-2025-6037)

| Field | Value |
| --- | --- |
| **Severity** | **medium** |
| **Attacker model** | Holder of a trusted non-CA client certificate **and** its private key |
| **Controlled input** | Crafted client cert: same serial + AKID + public key as the registered leaf; different Subject CN |
| **Primary location** | `builtin/credential/cert/path_login.go` |

### Attack path

1. Cert auth registers a non-CA leaf as trusted; aliases/entities are keyed by CN (default when `allowed_common_names` is empty).
2. Attacker forges a twin certificate (same key/serial/AKID, victim CN) and presents it with TLS client auth to `POST /v1/auth/cert/login`.
3. Non-CA match accepts on serial + AKID + pubkey only (not full cert / CN equality).
4. Alias uses the **presented** CN → attacker inherits the victim entity’s policies and group memberships.

### Impact

Impersonate another cert-auth identity (entity takeover for that alias).

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
		// ...
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

Upstream fix requires full certificate equality (`tCert.Equal(clientCert)`); this tree only has the CVE-2024-2048 public-key check.

---

## Finding 5 — Cert renew SKID/AKID binding uses logical AND

| Field | Value |
| --- | --- |
| **Severity** | **medium** |
| **Attacker model** | Holder of a stolen cert-auth token **and** any other client cert from the same issuing CA that still satisfies the cert role |
| **Controlled input** | TLS client certificate on `auth/token/renew` / `renew-self` |
| **Primary location** | `builtin/credential/cert/path_login.go` |

### Attack path

1. Attacker steals a cert-auth service token (still within TTL).
2. Cert role is CA-trusted with loose/empty name constraints so `verifyCredentials` accepts another leaf under that CA.
3. On renew, identity binding denies only if **both** SKID and AKID differ (`&&`). Same-CA leaf keeps AKID equal → condition false → renew succeeds without the original private key.
4. Attacker extends the stolen token’s lifetime, defeating the intended renew binding (`disable_binding` defaults false).

### Impact

Extend stolen cert-auth tokens without the victim’s private key.

### Evidence

```213:216:builtin/credential/cert/path_login.go
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Correct logic is separate equality checks (SKID must match **and** AKID must match).

---

## Finding 6 — Userpass/LDAP lockout bypass via AliasLookahead case (CVE-2025-6004)

| Field | Value |
| --- | --- |
| **Severity** | **medium** |
| **Attacker model** | Network attacker targeting userpass (or LDAP) login with lockout enabled |
| **Controlled input** | Username case variants (`alice`, `Alice`, `ALICE`, …) |
| **Primary location** | `builtin/credential/userpass/path_login.go` |

### Attack path

1. User lockout is enabled (default for userpass/ldap).
2. Lockout keys are built from `AliasLookahead` alias names (`getLoginUserInfoKey` → `aliasNameFromLoginRequest`).
3. Userpass `pathLoginAliasLookahead` returns the **raw** username; `pathLogin` authenticates with `strings.ToLower(username)`.
4. Attacker rotates case variants across failed attempts → distinct lockout counters for the same underlying user → brute-force past the threshold.
5. LDAP lookahead similarly returns the raw username without applying `case_sensitive_names` normalization.

### Impact

User lockout (anti-bruteforce) bypass → online password guessing against userpass/LDAP.

### Evidence

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(...) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{Name: username},
}
func (b *backend) pathLogin(...) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

```47:57:builtin/credential/ldap/path_login.go
func (b *backend) pathLoginAliasLookahead(...) (*logical.Response, error) {
	username := d.Get("username").(string)
	// raw username into Alias.Name — no ToLower / trim
```

```2156:2168:vault/request_handling.go
func (c *Core) getLoginUserInfoKey(...) (FailedLoginUser, error) {
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
```

---

## Near-misses (below medium+ E2E bar)

1. **MFA TOTP reuse / rate-limit (CVE-2025-6015 class):** `validateTOTP` keys `usedCodes` on raw `passcode` without normalization (`vault/login_mfa.go`). Advisory-confirmed on this version line, but the precise alternate encoding that both validates and misses the cache was not independently reproduced here beyond the missing-normalization evidence — treated as near-miss for this report’s bar.
2. **Unauthenticated `sys/generate-root`, rekey, unseal, raft join/bootstrap:** Intentional Shamir / join protocols; challenge answers require seal material — not under-auth bugs.
3. **X-Forwarded client-cert injection (`http/handler.go`):** Prepends header PEMs to `PeerCertificates` without PoP, but only after `x_forwarded_for_authorized_addrs` match — documented trust-proxy model, not a remote unauthenticated bypass.

---

## Summary

| # | Title | Severity | Primary file |
| --- | --- | --- | --- |
| 1 | Identity entity/group root policy case bypass (CVE-2025-5999) | high | `vault/identity_store_entities.go` |
| 2 | AWS auth client cache missing account ID (CVE-2025-11621) | high | `builtin/credential/aws/client.go` |
| 3 | LDAP username_as_alias MFA/identity bypass (CVE-2025-6013) | high | `builtin/credential/ldap/backend.go` |
| 4 | Cert auth non-CA CN impersonation (CVE-2025-6037) | medium | `builtin/credential/cert/path_login.go` |
| 5 | Cert renew SKID/AKID AND binding flaw | medium | `builtin/credential/cert/path_login.go` |
| 6 | Userpass/LDAP lockout bypass via AliasLookahead (CVE-2025-6004) | medium | `builtin/credential/userpass/path_login.go` |
