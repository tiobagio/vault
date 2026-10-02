# Application Security Review — AUTH / AUTHORIZATION / HTTP Handlers

**Repo:** tiobagio/vault  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `1.18.0-beta1`  
**Scope:** Auth methods, ACL/identity authorization, HTTP/RPC request handlers  
**Date:** 2026-10-02  

Up to five strongest medium+ candidates with end-to-end attack paths follow.

---

## 1. Identity entity root policy case/normalization bypass (CVE-2025-5999)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker** | Privileged operator with write on root-namespace identity entity APIs |
| **Controlled input** | `policies` array with a case variant of `root` (e.g. `ROOT`, `Root`) |
| **Reachability** | `POST/PUT /v1/identity/entity` (or `/id/:id`, `/name/:name`) → entity store → later request ACL via `SanitizePolicies` |
| **Impact** | Entity-bound tokens gain Vault `root` for the remainder of the token lifetime (full cluster admin) |
| **Primary location** | `vault/identity_store_entities.go` |

### Evidence

Write-time check is exact-string `"root"` after dedupe **without** lowercasing:

```355:363:vault/identity_store_entities.go
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

Request-time normalization lowercases and collapses to real `root`:

```51:64:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	defaultFound := false
	for i, p := range policies {
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		// ...
		if policies[i] == "root" {
			policies = []string{"root"}
```

Applied when building the ACL:

```300:302:vault/request_handling.go
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}
```

ACL grants IsRoot when the sanitized name is `root` in the root namespace:

```104:114:vault/acl.go
		if policy.Name == "root" {
			if ns.ID != namespace.RootNamespaceID {
				return nil, fmt.Errorf("root policy is only allowed in root namespace")
			}
			if len(policies) != 1 {
				return nil, fmt.Errorf("other policies present along with root")
			}
			a.root = true
		}
```

### Why not a false positive

End-to-end: assign `policies=["ROOT"]` on a root-namespace entity → persists → any token attached to that entity has identity policies sanitized to `["root"]` → ACL `a.root = true`. Upstream fixed with case-insensitive contains (CE 1.20.0 / Ent 1.18.11+); this tree still uses exact match. Groups use `RemoveDuplicatesStable(..., true)` before the check (harder), but the entity path is clearly bypassable.

---

## 2. AWS auth IAM/EC2 client cache missing account ID (CVE-2025-11621)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker** | AWS principal in a secondary/connected account that can call Vault AWS auth login |
| **Controlled input** | Valid STS GetCallerIdentity (or EC2 identity) for a same-named role (or wildcard-colliding principal) in a different AWS account |
| **Reachability** | `POST /v1/auth/aws/login` → `clientIAM` / `clientEC2` cache keyed by region+stsRole only → principal resolution / bind check |
| **Impact** | Cross-account authentication bypass: obtain a Vault token for a role intended for another account when `bound_iam_principal_arn` uses wildcards or colliding role names across accounts |
| **Primary location** | `builtin/credential/aws/client.go` |

### Evidence

IAM clients are cached by `region` and `stsRole` only — `accountID` is used to *select* STS role then discarded from the cache key:

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

Same pattern for EC2:

```221:231:builtin/credential/aws/client.go
func (b *backend) clientEC2(ctx context.Context, s logical.Storage, region, accountID string) (*ec2.EC2, error) {
	stsRole, stsExternalID, err := b.stsRoleForAccount(ctx, s, accountID)
	// ...
	if b.EC2ClientsMap[region] != nil && b.EC2ClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		return b.EC2ClientsMap[region][stsRole], nil
	}
```

Backend documents the map as region+STS role only (empty STS role = master account):

```76:80:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	// ...
	// The empty STS role signifies the master account
	EC2ClientsMap map[string]map[string]*ec2.EC2
```

Login wildcard bind uses that client path when resolving full ARNs (`fullArn` → `clientIAM`):

```1443:1449:builtin/credential/aws/path_login.go
			matchedWildcardBind := false
			for _, principalARN := range roleEntry.BoundIamPrincipalARNs {
				if strings.HasSuffix(principalARN, "*") && strutil.GlobbedStringsMatch(principalARN, fullArn) {
					matchedWildcardBind = true
					break
				}
			}
```

### Why not a false positive

HCSEC-2025-30: cache lookup does not validate account ID. After a legitimate login warms the cache for account A, a principal in account B with a colliding role name / wildcard match can be resolved with the wrong client context and pass binds that rely on ARN wildcards. Fixed upstream by caching clients by account ID (CE 1.21.0+); absent here.

---

## 3. LDAP `username_as_alias` MFA/identity bypass via non-canonical alias (CVE-2025-6013)

| Field | Value |
| --- | --- |
| **Severity** | **high** |
| **Attacker** | Network attacker who knows the victim LDAP password; Login MFA enforced on the victim **entity/group** (not only mount-wide) |
| **Controlled input** | Login username whitespace/variant (`alice` vs `alice `) while password remains valid for LDAP bind |
| **Reachability** | `POST /v1/auth/ldap/login/:username` with `username_as_alias=true` → alias = raw path username → new entity → MFA enforcement miss |
| **Impact** | Login MFA bypass; Vault token with LDAP-mapped policies without completing entity-scoped MFA |
| **Primary location** | `builtin/credential/ldap/backend.go` |

### Evidence

Path captures arbitrary username; alias uses client-supplied string when `username_as_alias` is set:

```16:18:builtin/credential/ldap/path_login.go
		Pattern: `login/(?P<username>.+)`,
```

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

```90:103:builtin/credential/ldap/path_login.go
	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
		},
		// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
```

No trimming/canonicalization of the alias before return (contrast: group/user policy lookup lowercases when `case_sensitive_names` is false, but the alias path returns the raw `username` unchanged).

### Why not a false positive

LDAP authenticate often succeeds for whitespace-adjacent usernames that still bind as the same directory user. Identity treats `"alice"` and `"alice "` as distinct aliases → distinct entities. Entity-/group-scoped MFA attached to the canonical entity does not apply to the new entity, while LDAP policies still attach from group membership resolved during that successful bind. Matches HCSEC/CVE-2025-6013; fixed in later releases.

---

## 4. Cert auth non-CA leaf CN impersonation (CVE-2025-6037)

| Field | Value |
| --- | --- |
| **Severity** | **medium** |
| **Attacker** | Principal who possesses a trusted non-CA client certificate **and** its private key |
| **Controlled input** | Crafted client certificate: same serial + AKID + public key as the trusted leaf, different Subject CN |
| **Reachability** | TLS client auth → `POST /v1/auth/cert/login` → non-CA branch of `verifyCredentials` → alias from presented CN |
| **Impact** | Impersonate another cert-auth identity (entity alias keyed by CN); inherit that entity’s policies and group memberships |
| **Primary location** | `builtin/credential/cert/path_login.go` |

### Evidence

Non-CA match checks serial, AuthorityKeyId, and public key — not full certificate / CN equality:

```276:308:builtin/credential/cert/path_login.go
	if len(trustedNonCAs) != 0 {
		for _, trustedNonCA := range trustedNonCAs {
			tCert := trustedNonCA.Certificates[0]
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

Alias uses the **presented** CN:

```160:169:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

`matchesCommonName` defaults to allow-all when `allowed_common_names` is unset:

```412:421:builtin/credential/cert/path_login.go
func (b *backend) matchesCommonName(clientCert *x509.Certificate, config *ParsedCert) bool {
	if len(config.Entry.AllowedCommonNames) == 0 {
		return true
	}
```

### Why not a false positive

Attacker with the trusted leaf’s private key forges a twin cert (same key material/serial/AKID, victim CN). TLS proves possession; Vault matches the trusted non-CA entry; alias becomes the victim CN → entity takeover. Upstream fix requires `tCert.Equal(clientCert)` (CE 1.20.1 / Ent 1.18.12+). This tree only has the CVE-2024-2048 public-key check.

---

## 5. Cert auth renewal identity binding uses logical AND (shared-CA renew of stolen tokens)

| Field | Value |
| --- | --- |
| **Severity** | **medium** |
| **Attacker** | Holder of a stolen cert-auth token **and** any other client cert from the same issuing CA that still satisfies the cert role |
| **Controlled input** | TLS client certificate presented on `auth/token/renew` / `renew-self` |
| **Reachability** | Token renew → `pathLoginRenew` → `verifyCredentials` (role still matches) → SKID/AKID check with `&&` |
| **Impact** | Extend stolen token lifetime without the victim’s private key, defeating intended renew binding |
| **Primary location** | `builtin/credential/cert/path_login.go` |

### Evidence

Deny only if **both** SKID and AKID differ (should require both to match):

```213:216:builtin/credential/cert/path_login.go
		// Certificate should not only match a registered certificate policy.
		// Also, the identity of the certificate presented should match the identity of the certificate used during login
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Login stores both into `InternalData`:

```160:164:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"subject_key_id":   skid,
			"authority_key_id": akid,
		},
```

Gate is active when `disable_binding` is false (default):

```192:192:builtin/credential/cert/path_login.go
	if !config.DisableBinding {
```

### Why not a false positive

For CA-trusted roles with loose/empty name constraints, `verifyCredentials` already accepts any client cert under that CA. The SKID/AKID check is the only per-identity renew gate. With `&&`, presenting another leaf from the same CA keeps AKID equal → condition false → renew succeeds without the original private key. Correct logic is separate equality checks (SKID must match **and** AKID must match).

---

## Near-misses (not reported as medium+ E2E)

- **X-Forwarded client-cert injection** (`http/handler.go`): prepends header PEMs to `PeerCertificates` without PoP, but only after `x_forwarded_for_authorized_addrs` match — documented trust-proxy model.
- **CORS `*` reflecting Origin**: allows custom headers including `X-Vault-Token`, but tokens are not ambient browser credentials; no automatic credentialed cross-origin theft without a separate XSS/token leak.
- **Unauthenticated `sys/generate-root`, rekey, unseal, raft join/bootstrap**: intentional Shamir/join protocols; challenge answers require seal material.
- **In-flight XFF spoof without authz**: logging/display only; rate-limit path uses `RemoteAddr` after the authorized XFF rewriter when configured.

---

## Summary

| # | Title | Severity | Primary file |
| --- | --- | --- | --- |
| 1 | Identity entity root policy case bypass (CVE-2025-5999) | high | `vault/identity_store_entities.go` |
| 2 | AWS auth client cache missing account ID (CVE-2025-11621) | high | `builtin/credential/aws/client.go` |
| 3 | LDAP username_as_alias MFA/identity bypass (CVE-2025-6013) | high | `builtin/credential/ldap/backend.go` |
| 4 | Cert auth non-CA CN impersonation (CVE-2025-6037) | medium | `builtin/credential/cert/path_login.go` |
| 5 | Cert renew SKID/AKID AND binding flaw | medium | `builtin/credential/cert/path_login.go` |
