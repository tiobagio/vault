# Application Security Review — Auth / Authz

**Target:** HashiCorp Vault fork `tiobagio/vault`  
**Commit:** `0513545dd` (`version/VERSION` = `1.18.0-beta1`)  
**Branch:** `cursor/application-security-review-3753`  
**Scope:** HTTP token/header handling, `builtin/credential/*`, ACL/policy, unauthenticated sys paths  
**Note:** JWT/OIDC auth method is not bundled in this OSS tree (external plugin); identity OIDC *provider* paths were reviewed.

---

## Validated findings (medium+)

### 1. High — Identity entity/group `root` policy case bypass (CVE-2025-5999)

| Field | Detail |
| --- | --- |
| **Severity** | High |
| **Attacker** | Privileged operator with write on root-namespace identity entity (or group) APIs |
| **Controlled input** | `policies` array containing a case variant of `root` (e.g. `ROOT`, `Root`) |
| **Code path** | `POST/PUT /v1/identity/entity*` → `vault/identity_store_entities.go` → request ACL via `SanitizePolicies` |
| **Impact** | Entity-/group-bound tokens become full `root` for the token lifetime |

**Why exploitable end-to-end:** Write-time check is exact-string `"root"` after `RemoveDuplicates(..., false)` (no lowercasing). Request-time `SanitizePolicies` lowercases and collapses to real `root`, and ACL construction grants IsRoot.

```355:363:vault/identity_store_entities.go
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
	// ...
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		if policies[i] == "root" {
			policies = []string{"root"}
```

Same exact-check pattern in `vault/identity_store_groups.go` (~255–257). Upstream fixed with case-insensitive contains; this tree still uses exact match.

---

### 2. Medium — Cert auth non-CA leaf CN impersonation (CVE-2025-6037)

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Principal who possesses a trusted non-CA client certificate **and** its private key |
| **Controlled input** | Crafted client cert: same serial (+ AKID/pubkey as checked), different Subject CN |
| **Code path** | TLS client auth → `POST /v1/auth/cert/login` → `verifyCredentials` non-CA branch → alias from presented CN |
| **Impact** | Impersonate another cert-auth identity (entity alias by CN); inherit that entity’s policies/groups |

**Why exploitable end-to-end:** Non-CA match checks serial, AuthorityKeyId, and public key — not full cert equality / CN. Alias is taken from the *presented* cert CN. Attacker with the trusted leaf’s private key forges a twin cert with victim CN → TLS proves key possession → Vault matches leaf → new/target entity alias.

```283:308:builtin/credential/cert/path_login.go
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

```146:149:builtin/credential/cert/path_login.go
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
```

Upstream fix uses full cert equality (`tCert.Equal(clientCert)`). This tree does not.

---

### 3. High — LDAP `username_as_alias` MFA/identity bypass via whitespace (CVE-2025-6013)

| Field | Detail |
| --- | --- |
| **Severity** | High |
| **Attacker** | Network attacker with victim LDAP password; MFA enforced on victim **entity/group** (not only mount-scoped) |
| **Controlled input** | Username with whitespace variant (`alice` vs `alice `) |
| **Code path** | `auth/ldap/login/:username` → `Login(..., usernameAsAlias=true)` returns raw username as alias → new entity → MFA miss |
| **Impact** | Login MFA bypass; token with LDAP-mapped policies |

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

---

### 4. High — Login MFA TOTP anti-replay bypass via non-normalized passcodes (CVE-2025-6015)

| Field | Detail |
| --- | --- |
| **Severity** | High |
| **Attacker** | Party who can observe/reuse a valid TOTP within its window (phish, shared device, concurrent session) |
| **Controlled input** | Whitespace-padded passcode (`"123456"`, `" 123456"`, `"123456\n"`) |
| **Code path** | `validateTOTP` keys used-code cache on raw string; `totplib.ValidateCustom` accepts padded equivalents |
| **Impact** | Breaks TOTP one-time-use within validity window |

```2324:2392:vault/login_mfa.go
	passcode := mfaFactors.passcode
	usedName := fmt.Sprintf("%s_%s", configID, passcode)
	_, ok := usedCodes.Get(usedName)
	// ...
	valid, err := totplib.ValidateCustom(passcode, key, time.Now(), validateOpts)
	// ...
	err = usedCodes.Add(usedName, nil, validityPeriod)
```

---

### 5. Medium — Okta auth entity alias uses client-supplied username (MFA/identity bypass)

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Holder of victim Okta password; Login MFA enforced by **entity ID** / internal identity group |
| **Controlled input** | Login username: Okta accepts login **or** email for the same account |
| **Code path** | `auth/okta/login/:username` → AuthN succeeds → `Alias.Name = username` (client string) → distinct entity |
| **Impact** | New entity not covered by entity-scoped MFA; token without intended MFA |

```118:129:builtin/credential/okta/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: username,
		},
	}
```

Okta embeds canonical user id in the AuthN result (used for group fetch) but does not use it for the alias. Contrast: GitHub auth aliases from IdP-canonical login.

---

### 6. Medium — ACL privilege escalation via `+`/`*` in identity-templated policy paths

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Authenticated principal who can influence a templated identity field (metadata, alias name, JWT claim mapping, etc.) |
| **Controlled input** | Identity value set to `+` or a string ending in `*` |
| **Code path** | Templated ACL render (`parsePaths` + `identitytpl.PopulateString`) → wildcard flags from rendered path |
| **Impact** | Broaden path matching beyond intended tenancy (segment wildcard / prefix glob) |

```349:427:vault/policy.go
		// template substitution into path key, then:
		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}
		if strings.HasSuffix(pc.Path, "*") { /* IsPrefix */ }
```

```54:60:sdk/helper/identitytpl/templating.go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
	case string:
		return t, nil  // no rejection of + / *
```

This tree has no `ErrTemplatedWildcard` rejection present in later upstream.

---

### 7. Medium — Cert auth renewal identity binding uses AND (same-CA renew of stolen tokens)

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Holder of a stolen cert-auth token **and** any other client cert from the same issuing CA that still satisfies the cert role |
| **Controlled input** | TLS client certificate presented on `auth/token/renew[-self]` |
| **Code path** | `pathLoginRenew` → `verifyCredentials` (role match) → SKID/AKID check with `&&` |
| **Impact** | Extend stolen token lifetime without the victim’s private key, defeating intended renew binding |

```213:216:builtin/credential/cert/path_login.go
		// intended: both identities must match; implemented as deny only if BOTH differ
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Upstream requires separate checks (SKID **and** AKID). For CA-trusted roles with loose/empty name constraints, `verifyCredentials` already accepts any cert from that CA; the binding check is the only per-identity renew gate and is bypassable via shared AKID.

Requires `disable_binding=false` (default).

---

## Near-misses (not medium+ E2E on this tree)

- **X-Forwarded client-cert header injection** (`http/handler.go` `WrapForwardedForHandler`): prepends header PEMs to `PeerCertificates` without PoP, but only after `x_forwarded_for_authorized_addrs` match. Documented trust-proxy model; no authz bypass of that CIDR gate found. Missing `return` after TLS-nil `respondError` is a response bug, not an auth bypass.
- **AWS IAM `iam_request_url` SSRF:** request is forced to configured STS endpoint; Host comes from client URL for SigV4 compatibility. Admin-controlled STS endpoint only.
- **Unauthenticated `sys/storage/raft/bootstrap/{challenge,answer}`:** challenge is seal-encrypted; answering requires unseal/recovery material (join protocol by design). `remove-peer` on DR secondary is gated by DR operation token wrapper.
- **`sys/wrapping/lookup` unauthenticated:** requires possession of wrapping token; metadata only.
- **`X-Vault-Policy-Override`:** wired into request object; OSS `performEntPolicyChecks` is a stub — no Sentinel override privilege escalation in CE.
- **JWT/OIDC auth method:** not present under `builtin/credential/` in this OSS snapshot.
- **AppRole / userpass / GitHub / Radius:** no additional medium+ auth bypass with clear E2E path beyond known MFA/alias classes above.
- **In-flight request XFF spoof (logging only):** display fields, not used for CIDR-bound auth decisions when XFF handler is not configured.

---

## Summary

Seven medium+ issues with end-to-end paths remain on this `1.18.0-beta1` tree, including known CVEs 2025-5999 / 6037 / 6013 / 6015 plus Okta alias MFA gap, ACL template wildcard injection, and cert renew binding logic. HTTP token header handling and core `CheckToken`/`LoginPath` gating did not yield additional validated bypasses beyond those classes.
