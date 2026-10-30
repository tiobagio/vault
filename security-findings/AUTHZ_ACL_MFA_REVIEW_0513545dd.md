# Application Security Review — AuthZ / ACL / Identity / MFA

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`version/VERSION` = `1.18.0-beta1`)  
**Scope:** Authentication/authorization, ACL, identity policy templates, ROOT policy bypass, MFA bypass  
**Method:** End-to-end static tracing + proof unit tests in `vault/authz_proof_test.go`  
**Criterion:** Only medium+ issues with a concrete attacker → input → code path → impact chain that still works on this tree

---

## Summary

| # | Finding | Severity | Verdict on this tree |
|---|---------|----------|----------------------|
| 1 | Identity entity/group `ROOT`/`Root` policy assignment → built-in root ACL | **High** | **Exploitable** |
| 2 | ACL identity-template path injection (`+` segment wildcard / `/` segment escape) | **Medium** | **Exploitable** (when templated ACLs bind on attacker-influenced identity fields) |
| 3 | Login MFA TOTP anti-replay bypass via non-normalized passcode cache key | **High** | **Exploitable** |
| 4 | LDAP `username_as_alias` non-canonical alias → entity/group MFA miss | **High** | **Exploitable** (entity/group-scoped MFA only; needs directory-accepted username variant) |
| 5 | Okta alias uses client-supplied username → entity/group MFA miss | **Medium** | **Exploitable** (entity/group-scoped MFA; Okta accepts login **or** email) |
| 6 | Userpass lockout counter keyed by raw alias lookahead (case variants) | **Medium** | **Exploitable** |

No additional medium+ ROOT/ACL/MFA bypasses were validated beyond the table above in this pass.

Proof tests: `go test ./vault/ -run TestProof_ -count=1` (passes).

---

## Finding 1 — Identity entity/group root policy case bypass

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Primary location** | `vault/identity_store_entities.go`, `vault/identity_store_groups.go` |
| **Supporting** | `sdk/helper/policyutil/policyutil.go` `SanitizePolicies`; `vault/request_handling.go` policy merge; `vault/policy_store.go` `GetPolicy`; `vault/acl.go` `NewACL` |
| **Attacker** | Authenticated principal with write on root-namespace identity APIs (`identity/entity`, `identity/entity/id/:id`, `identity/group`, …) — **not** a root token |
| **Controlled input** | `policies` array containing a case (and for groups, whitespace) variant of `root`, e.g. `ROOT`, `Root`; groups also accept `" root "` |
| **Impact** | Existing entity-bound tokens inherit Vault `root` for the remainder of the token TTL (full admin) |

### Attack path

1. Attacker holds a non-root token that can write identity entities/groups in the **root** namespace (common identity-admin role).
2. Victim (or attacker) already has a live token with `EntityID` set (normal login first).
3. Attacker writes `"policies": ["ROOT"]` on that entity (or a group the entity belongs to).
4. Write path rejects only the exact string `"root"` via case-sensitive `StrListContains` after dedupe that does **not** lowercase.
5. On the next request with the existing token, `fetchEntityAndDerivedPolicies` returns stored `ROOT`; `SanitizePolicies` lowercases it to `root` and collapses the set to `["root"]`.
6. `PolicyStore.GetPolicy` / `NewACL` treat that as the built-in root policy → `a.root = true` → full root privileges.

Login-time minting is **not** the exploit vector: `LoginCreateToken` rejects when sanitized identity policies already contain `root`. Escalation is **post-login entity/group policy update** against an already-issued token.

Child namespaces do not grant root: `NewACL` errors if policy name `root` appears outside the root namespace.

### Evidence

Entity write — exact `"root"` only; `RemoveDuplicates(..., false)` trims but does not lowercase:

```355:363:vault/identity_store_entities.go
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

Group write — same exact check; `RemoveDuplicatesStable(..., true)` preserves original case/spacing (so `"ROOT"` and `" root "` both bypass):

```249:257:vault/identity_store_groups.go
	policiesRaw, ok := d.GetOk("policies")
	if ok {
		group.Policies = strutil.RemoveDuplicatesStable(policiesRaw.([]string), true)
	}

	if strutil.StrListContains(group.Policies, "root") {
		return logical.ErrorResponse("policies cannot contain root"), nil
	}
```

Request-time merge lowercases and collapses to real `root`:

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

Contrast: token create sanitizes **before** root checks (`vault/token_store.go`), so `"ROOT"` cannot be assigned directly onto a token. Identity write is the inconsistent path.

**Note on `" root "`:** entity `RemoveDuplicates(..., false)` trims → becomes exact `root` and **is** blocked. Group path preserves spacing → bypass. Case variants bypass **both**.

### Exploitability on this tree

**Confirmed.** Proof: `TestProof_IdentityRootPolicyCaseBypass`, `TestProof_NewACLRootFromSanitizedName`.

---

## Finding 2 — ACL identity-template `+` / `/` injection

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Primary location** | `sdk/helper/identitytpl/templating.go` (`aclTemplateHandler`); `vault/policy.go` `parsePaths` |
| **Attacker** | Authenticated principal who can influence an identity value referenced by a templated ACL path (not Vault root) |
| **Controlled input** | `identity.entity.metadata.*`, `identity.entity.aliases.<accessor>.metadata.*` / `name` (e.g. AppRole secret-id metadata, JWT/OIDC claim mappings, user-influenced alias names) |
| **Impact** | Capabilities intended for one path segment apply across tenants/segments (`+` → segment wildcard; `/` → multi-segment prefix escape) |

### Attack path

1. Operator publishes a templated ACL for tenant isolation, e.g.:
   ```hcl
   path "kv/data/{{identity.entity.metadata.department}}/*" {
     capabilities = ["read"]
   }
   ```
   or `{{identity.entity.aliases.<approle_accessor>.metadata.team}}`.
2. Attacker sets the referenced value to `+` (or embeds `/`, e.g. `finance/admin`) via AppRole secret-id metadata / claim mapping / entity metadata they can write.
3. On ACL render, `aclTemplateHandler` returns the string **verbatim** (no rejection of `+`, `*`, or `/`).
4. `parsePaths` then sets `HasSegmentWildcards` for `+`, or builds a multi-segment `IsPrefix` path for `/`.

AppRole persists secret-id metadata onto `Alias.Metadata` at login (`builtin/credential/approle/path_login.go`), which identity templating can read.

### Evidence

```54:60:sdk/helper/identitytpl/templating.go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", ErrTemplateValueNotFound
		}
		return t, nil
```

```349:427:vault/policy.go
		if performTemplating {
			_, templated, err := identitytpl.PopulateString(...)
			key = templated
		}
		// ...
		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}
		if strings.HasSuffix(pc.Path, "*") {
			if !pc.HasSegmentWildcards {
				pc.Path = strings.TrimSuffix(pc.Path, "*")
				pc.IsPrefix = true
			}
		}
```

This tree has **no** `ErrTemplatedWildcard` (or equivalent) rejection of rendered `+`/`*`.

### Exploitability on this tree

**Confirmed** when operators use identity fields the principal can influence inside ACL path templates (a documented multi-tenant pattern). Not a default-config RCE; still a real authorization bypass under that common deployment model.

Proof: `TestProof_ACLTemplateWildcardAndSlashInjection`.

---

## Finding 3 — Login MFA TOTP one-time-use bypass (passcode whitespace)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Primary location** | `vault/login_mfa.go` `validateTOTP`, `parseMfaFactors` |
| **Attacker** | Party who completed first-factor auth (or holds `mfa_request_id`) and can reuse a valid TOTP within its window |
| **Controlled input** | TOTP passcode via `X-Vault-MFA` / `sys/mfa/validate` — whitespace-padded variants of a used code |
| **Impact** | Breaks TOTP anti-replay; second MFA success with `" "+code` / `code+" "` / `code+"\n"` after `code` was consumed |

### Attack path

1. Login MFA with TOTP is enforced; valid code `C` is used once.
2. Vault records used-code key as `methodID + "_" + rawPasscode` **without** trimming.
3. Vendored `pquerna/otp` `ValidateCustom` → HOTP `ValidateCustom` does `strings.TrimSpace(passcode)` before comparing.
4. Attacker resubmits `" "+C` (or trailing space/newline). Used-code cache miss → validation succeeds.

### Evidence

```2320:2392:vault/login_mfa.go
	passcode := mfaFactors.passcode
	usedName := fmt.Sprintf("%s_%s", configID, passcode)
	_, ok := usedCodes.Get(usedName)
	// ...
	valid, err := totplib.ValidateCustom(passcode, key, time.Now(), validateOpts)
	// ...
	err = usedCodes.Add(usedName, nil, validityPeriod)
```

`parseMfaFactors` stores the passcode without normalization (`vault/login_mfa.go` ~1821–1848).

External proof against the exact module version in `go.mod`: `ValidateCustom` accepts `" CODE"`, `"CODE "`, `"CODE\n"`, `"\tCODE"`.

### Exploitability on this tree

**Confirmed.**

---

## Finding 4 — LDAP `username_as_alias` entity/group MFA bypass

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Primary location** | `builtin/credential/ldap/backend.go`, `builtin/credential/ldap/path_login.go` |
| **Attacker** | Holds valid LDAP credentials for a user under **entity- or identity-group-scoped** Login MFA |
| **Controlled input** | Login username spelling variant (whitespace / case) that the directory still authenticates |
| **Impact** | New entity alias → MFA enforcement tied to the canonical entity/group does not match → token without MFA |

### Attack path

1. Victim `alice` has MFA enrolled; enforcement matches entity/group of alias `alice`.
2. Attacker authenticates as `alice%20` / `Alice` (directory accepts variant).
3. With `username_as_alias=true`, Vault returns the **raw** request username as the alias (not a directory-canonical attribute; not even `canonicalUsername` when case-insensitive).
4. `CreateOrFetchEntity` creates a new entity for the variant alias.
5. `buildMFAEnforcementConfigList` matches on entity ID / group IDs → miss → token issued.

If MFA is enforced only via `auth_method_accessors` / `auth_method_types`, this bypass does **not** apply.

### Evidence

```157:159:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
	}
```

```82:100:builtin/credential/ldap/path_login.go
	username := d.Get("username").(string)
	// ...
	Alias: &logical.Alias{
		Name: effectiveUsername,
```

```1757:1771:vault/login_mfa.go
			if strutil.StrListContains(eConfig.IdentityEntityIDs, entity.ID) {
				matchedMfaEnforcementConfig = append(matchedMfaEnforcementConfig, eConfig)
```

Login path pattern is `login/(?P<username>.+)` — spaces are accepted in the path.

### Exploitability on this tree

**Confirmed in code** with the stated MFA-scope and directory-normalization preconditions (common for Active Directory).

---

## Finding 5 — Okta client-supplied username as entity alias (MFA miss)

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Primary location** | `builtin/credential/okta/path_login.go` |
| **Attacker** | Holds valid Okta password; Login MFA enforced by identity entity ID and/or internal identity groups |
| **Controlled input** | Login `username` — Okta AuthN accepts the user’s login **or** email |
| **Impact** | Distinct Vault entity/alias for the alternate identifier → entity-scoped MFA skipped |

### Attack path

Same class as Finding 4: Okta succeeds and returns embedded user/groups, but Vault sets `Alias.Name` from the **client** username string, not Okta’s canonical user id / profile login.

```118:129:builtin/credential/okta/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: username,
		},
	}
```

Canonical user is available and used for group listing in `builtin/credential/okta/backend.go`, but not for the alias.

### Exploitability on this tree

**Confirmed** for entity/group-scoped MFA when Okta accepts dual identifiers for the same account. Mount-scoped MFA still applies.

---

## Finding 6 — Userpass lockout bypass via alias-lookahead case mismatch

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Primary location** | `builtin/credential/userpass/path_login.go`; lockout keying in `vault/request_handling.go` / `vault/core.go` |
| **Attacker** | Unauthenticated brute-force attacker against userpass (lockout enabled by default) |
| **Controlled input** | Username case permutations (`admin`, `Admin`, `ADMIN`, …) |
| **Impact** | Independent failure counters per spelling → multiplies allowed guesses by case variants |

### Attack path

1. `pathLogin` authenticates with `strings.ToLower(username)` → all case variants hit the same user record.
2. Lockout counters key on `aliasNameFromLoginRequest` → `AliasLookaheadOperation`.
3. Userpass alias lookahead returns the **raw** (non-lowercased) username.
4. Each case variant gets its own counter (default threshold = 5).

### Evidence

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(...) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{ Name: username },
}
func (b *backend) pathLogin(...) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

```2155:2168:vault/request_handling.go
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	userInfo.aliasName = aliasName
```

Default: `UserLockoutThresholdDefault = 5`, `DisableUserLockoutDefault = false` (`internalshared/configutil/userlockout.go`).

LDAP alias lookahead has the same raw-username pattern and can combine with Finding 4 for lockout dilution; userpass is the cleanest E2E case here.

### Exploitability on this tree

**Confirmed.**

---

## Explicit non-findings / false positives in scope

| Candidate | Why not reported as validated medium+ here |
| --- | --- |
| Assigning exact `"root"` via identity APIs | Correctly blocked |
| New login while identity already has sanitized `root` | Blocked by `LoginCreateToken` |
| MFA enforced only by auth mount accessor/type + LDAP/Okta alias variants | Mount still matches; Findings 4–5 do not apply |
| ACL templates that only reference non-attacker-controlled fields (e.g. immutable entity UUID) | No useful injection surface |
| Duo Trusted-Networks / unused stored login IP | Known class / incomplete binding; not newly validated beyond existing discussion |
| Token-store `"ROOT"` assignment | Sanitized before root checks — not vulnerable |

---

## Remediation sketch (for operators / maintainers)

1. Normalize identity entity/group policies with the same rules as `SanitizePolicies` **before** the deny-root check (case-insensitive + trim); reject anything that normalizes to `root`.
2. In ACL templating mode, reject rendered path segments containing `+`, `*`, or `/` (or encode them safely).
3. Trim/normalize TOTP passcodes before used-code cache keying **and** validation.
4. LDAP `username_as_alias`: return a directory-canonical attribute (or at least trimmed/lowercased `canonicalUsername`), never the raw client string.
5. Okta: set `Alias.Name` from Okta user id or `profile.login` after AuthN.
6. Userpass (and LDAP) alias lookahead: use the same normalization as the login path for lockout keys.
