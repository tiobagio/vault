# Vault 1.18.0-beta1 (0513545dd) — NEW AppSec Findings

Hunt focused on under-covered areas (MFA, auth quirks, AWS auth cache, LDAP aliasing).
Known items 1–11 from the task brief were **not** re-validated as primary findings.

## Finding 1 — HIGH/MEDIUM: Login MFA TOTP reuse + rate-limit bypass (CVE-2025-6015 / HCSEC-2025-19)

**Status at 0513545dd:** Vulnerable (fixed later in 1.18.12 / 1.20.1).

### Attacker
Anyone who can complete (or observe) a login subject to Login MFA TOTP — typically an attacker who already has a valid password / primary factor, or who phishes one TOTP code.

### Controlled input
TOTP passcode string in `X-Vault-MFA` (single-phase) or `mfa_payload` on `sys/mfa/validate` (two-phase).

### Sink
`vault/login_mfa.go` → `validateTOTP`:

```go
usedName := fmt.Sprintf("%s_%s", configID, passcode)  // RAW passcode, no TrimSpace
_, ok := usedCodes.Get(usedName)
...
valid, err := totplib.ValidateCustom(passcode, key, time.Now(), validateOpts)
```

Underlying `github.com/pquerna/otp/hotp.ValidateCustom` **does** normalize:

```go
passcode = strings.TrimSpace(passcode)
```

(`hotp/hotp.go` in module `github.com/pquerna/otp@v1.2.1-0.20191009055518-468c2dd2b58d`)

### Attack steps
1. Victim (or attacker with password) authenticates; Login MFA TOTP is required.
2. Attacker submits valid code `123456` once → cached under key `{methodID}_123456`.
3. Attacker resubmits ` 123456` or `123456 ` (whitespace variants).
4. Replay check misses (different cache key); `ValidateCustom` trims and accepts the same OTP.
5. Rate-limit side issues in the same function compound impact:
   - Used-code check runs **before** rate-limit increment → distinct error `"code already used..."` enables used-code oracle.
   - Rate-limit TTL is only `Period` seconds while used-code TTL is `Period*(2+Skew)` → window where rate limit expires but code is still cryptographically valid.
   - Limits are per `EntityID`; combined with Finding 2, entity rotation further evades limits (CVE-2025-6016 aggregate).

### Impact
Replay of a single observed TOTP within its validity window; weakened MFA rate limiting. Medium (CVSS ~5.7) alone; higher when chained with LDAP entity aliasing.

---

## Finding 2 — HIGH: LDAP `username_as_alias` MFA / identity split via whitespace (CVE-2025-6013 / HCSEC-2025-20)

**Status at 0513545dd:** Vulnerable (fixed later in 1.18.13 / 1.20.2).

### Attacker
User with valid LDAP credentials when `username_as_alias=true` and Login MFA is bound to entity IDs / identity groups (not solely mount accessor/type).

### Controlled input
Login username string on `auth/ldap/login/:username` (regex allows spaces: `(?P<username>.+)`).

### Sink
`builtin/credential/ldap/backend.go` → `Login`:

```go
if usernameAsAlias {
    return username, policies, ldapResponse, allGroups, nil  // RAW client username
}
```

LDAP bind/search typically succeeds for whitespace variants of the same CN; Vault stores a **different** entity alias for `"alice"` vs `"alice "` / `" alice"`.

### Attack steps
1. Admin configures LDAP auth with `username_as_alias=true`.
2. MFA enforcement targets a specific EntityID or Identity Group for the canonical user.
3. Attacker logs in as `"alice "` (trailing space) with Alice’s password.
4. Vault creates/uses a **new** entity alias/entity that is **not** in the MFA-bound entity/group set.
5. `buildMFAEnforcementConfigList` does not match → login proceeds **without MFA**.

Related lockout weakness (CVE-2025-6004 / Cyata): failed-login counters key on raw alias strings (`FailedLoginUser.aliasName`), so case/space variants reset lockout against the same LDAP principal.

### Impact
Complete Login MFA bypass for LDAP users under the stated config; also enables entity proliferation for TOTP rate-limit evasion when chained with Finding 1.

---

## Finding 3 — HIGH: AWS auth IAM/EC2 client cache keyed without account ID (CVE-2025-11621 / HCSEC-2025-30)

**Status at 0513545dd:** Vulnerable (fixed later in 1.21.0 / Ent 1.20.5).

### Attacker
IAM principal in AWS account B that shares a role **name** (or matches a wildcard `bound_iam_principal_arn`) with a trusted principal in account A, after a successful auth has populated Vault’s AWS client cache.

### Controlled input
Signed `sts:GetCallerIdentity` login material to `auth/aws/login` (and related IAM unique-ID resolution paths).

### Sink
`builtin/credential/aws/client.go` → `clientIAM` / `clientEC2`:

```go
// Cache key: region + stsRole ONLY — accountID not part of the key
if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
    return b.IAMClientsMap[region][stsRole], nil  // no accountID check on cache hit
}
```

`getClientConfig` validates `defaultAWSAccountID != accountID` only when **creating** a new client with empty `stsRole`. Cache hits skip that check.

### Attack steps
1. Vault AWS auth role uses `bound_iam_principal_arn` with same role name across accounts and/or trailing `*` wildcards.
2. Trusted principal in account A authenticates; Vault caches IAM/EC2 client under `(region, stsRole)` (often `stsRole==""`).
3. Attacker in account B with colliding role name / wildcard match authenticates.
4. Cache returns account A’s client; unique-ID / existence checks run in the wrong account context.
5. Attacker receives a Vault token for the role intended for the other account’s principal.

### Impact
Cross-account authentication bypass → Vault token with policies of the bound role. High when multi-account wildcards/shared role names are in use.

---

## Secondary observation (not scored as primary)

**Duo two-phase MFA uses validate-time IP, ignoring cached login IP**

- `MFACachedAuthResponse.RequestConnRemoteAddr` is populated in `request_handling.go` (“needed for the DUO method”) but **never read**.
- `handleMFALoginValidate` passes `req.Connection.RemoteAddr` into `validateDuo`.
- Impact depends on Duo “Allow Networks” / preauth `allow`; treated as supporting evidence / hardening gap rather than a standalone critical without that Duo policy.

---

## Areas searched without NEW medium+ validated findings

| Area | Result |
|------|--------|
| MFA enrollment ACL / admin-generate | Entity-scoped generate; admin paths ACL-gated; no novel bypass beyond Findings 1–2 |
| AppRole CIDR / secret_id num_uses | Locking present; no new medium+ path |
| Okta/RADIUS auth | No novel escalation beyond config features (`bypass_okta_mfa` is admin) |
| Userpass | Timing/lockout nuances exist historically; no new medium+ beyond known Cyata low/enum class |
| Transit | Known nonce issue already fixed in this line |
| PKI non-ACME | No novel medium+ beyond listed ACME SSRF |
| MySQL/Cassandra/Mongo/Influx revoke | Template/`ReplaceAll` patterns; no novel default-path SQLi class beyond listed engines |
| UI CORS / internal UI mounts | Unauth mounts only with `listing_visibility=unauth`; no CSRF token theft chain validated |
| Raft `remove-peer` unauthenticated list | DR-secondary only + `verifyDROperationTokenOnSecondary` |
| Plugin gRPC / mlock | No end-to-end exploit path validated |
| Policy/ACL glob edge cases | No new medium+ beyond listed ROOT policy CVE |
| Identity policy / MFA username_format templates | Admin-configured; Duo/Okta username targeting needs identity write — below bar |

---

## Summary

Three **new** medium/high issues (relative to the provided “already documented” list) validated with end-to-end paths at commit `0513545dd`:

1. **CVE-2025-6015** — TOTP Login MFA replay via whitespace + rate-limit weaknesses  
2. **CVE-2025-6013** — LDAP `username_as_alias` MFA enforcement bypass via unnormalized usernames  
3. **CVE-2025-11621** — AWS auth client cache missing account ID → cross-account auth bypass  
