# Application Security Review — Vault 1.18.0-beta1

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `version/VERSION` = `1.18.0-beta1` (CHANGELOG top: `1.17.0-rc1`)  
**Method:** Static end-to-end code tracing + public HCSEC/CVE correlation; otp `TrimSpace` reuse confirmed with a local library check  
**Skip list (excluded from findings):** identity ROOT (CVE-2025-5999), audit file→plugin RCE (CVE-2025-6000), SSH ValidPrincipals (CVE-2024-7594), AWS AccountID cache (CVE-2025-11621), ACME SSRF, cert CN ignore, identitytpl +, AppRole CIDR burn, Agent lookup token leak

**CHANGELOG SECURITY note:** This tree’s CHANGELOG SECURITY section tops out around HCSEC-2024-10 / CVE-2024-2660 / CVE-2024-2048. Later 2024–2025 CVEs below are **not** recorded as fixed here and remain present in code.

---

## Finding 1 — Unauthenticated Raft bootstrap challenge memory DoS (CVE-2024-8185)

| Field | Value |
| --- | --- |
| **Severity** | High (CVSS 7.5 / AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) |
| **CVE / advisory** | CVE-2024-8185 / HCSEC-2024-26 |
| **Primary location** | `vault/logical_system.go` (Unauthenticated), `vault/logical_system_raft.go` (`handleRaftBootstrapChallengeWrite`) |
| **Attacker** | Unauthenticated remote client who can reach the Vault API on a raft-backed cluster |
| **Controls** | Repeated `POST /v1/sys/storage/raft/bootstrap/challenge` with distinct `server_id` values |
| **Impact** | Unbounded `pendingRaftPeers` growth + per-request seal encryption → host memory exhaustion / process crash |
| **Fixed upstream** | CE 1.18.1 / Ent 1.18.1, 1.17.8, 1.16.12 (this tree is 1.18.0-beta1 → still vulnerable) |

### Attack path

1. Victim cluster uses Integrated Storage (`storage "raft"`) and is unsealed (seal Access available for challenge sealing).
2. Paths `storage/raft/bootstrap/challenge` and `.../answer` are registered in `PathsSpecial.Unauthenticated` — no Vault token required.
3. Attacker sends many `POST /v1/sys/storage/raft/bootstrap/challenge` bodies with unique `server_id` strings.
4. For each new `server_id`, handler allocates a 16-byte answer and **stores it forever** in `Core.pendingRaftPeers` (`sync.Map`) until a matching answer consumes it.
5. Every request also calls `sealer.Seal` (seal-wrap / crypto) and returns a sealed challenge blob — CPU + allocation pressure independent of map growth.
6. Map entries are not capped or expired → memory grows with distinct IDs until OOM / host instability.

### Evidence

```143:182:vault/logical_system.go
			Unauthenticated: []string{
				// ...
				"storage/raft/bootstrap/challenge",
				"storage/raft/bootstrap/answer",
				// ...
			},
```

```269:309:vault/logical_system_raft.go
func (b *SystemBackend) handleRaftBootstrapChallengeWrite(makeSealer func() snapshot.Sealer) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		serverID := d.Get("server_id").(string)
		// ...
		answerRaw, ok := b.Core.pendingRaftPeers.Load(serverID)
		if !ok {
			answer, err = uuid.GenerateRandomBytes(16)
			// ...
			b.Core.pendingRaftPeers.Store(serverID, answer)
		} else {
			answer = answerRaw.([]byte)
		}
		sealer := makeSealer()
		protoBlob, err := sealer.Seal(ctx, answer)
		// ...
```

### Why exploitable vs mitigated

Exploitable whenever the raft API is network-reachable (common for join workflows). Default rate-limit exempt paths do not include this endpoint, but **no quota is required for the bug**; without an operator-configured global RLQ the flood is unconstrained. Upstream replaced the per-ID map with a constant-size HKDF challenge key (OpenBao/Vault 1.18.1+).

### Remediation

Upgrade to ≥1.18.1 (or Ent backports). Interim: network-restrict who can reach `/v1/sys/storage/raft/*` and apply a path rate-limit quota on `sys/storage/raft/bootstrap/challenge`.

---

## Finding 2 — TOTP secrets engine code reuse via whitespace (CVE-2025-6014)

| Field | Value |
| --- | --- |
| **Severity** | Medium (CVSS 6.5 / AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| **CVE / advisory** | CVE-2025-6014 / HCSEC-2025-17 |
| **Primary location** | `builtin/logical/totp/path_code.go` (`pathValidateCode`) |
| **Attacker** | Authenticated client with `update` on `totp/code/:name` (validator role) |
| **Controls** | Same TOTP code with appended/prepended whitespace (`"123456 "`, `"\t123456"`, etc.) |
| **Impact** | Once-per-period anti-reuse cache bypass → same OTP accepted multiple times within skew window |
| **Fixed upstream** | CE 1.20.1 / Ent 1.20.1, 1.19.7, 1.18.12, 1.16.23 |

### Attack path

1. Mount TOTP engine; create a key; obtain a valid period code `C`.
2. First `POST totp/code/<name>` with `code=C` → `usedCodes` key is `"<name>_C"`; `ValidateCustom` succeeds.
3. Second request with `code=C+" "` (or leading space / `\n` / `\t`).
4. Cache lookup uses the **raw** string → miss.
5. `github.com/pquerna/otp/hotp.ValidateCustom` does `strings.TrimSpace(passcode)` before length/compare → treats it as `C` → **valid=true**.
6. Attacker reuses the OTP for any system that trusts Vault’s validate endpoint as the second factor / gate.

### Evidence

```105:136:builtin/logical/totp/path_code.go
	usedName := fmt.Sprintf("%s_%s", name, code)

	_, ok := b.usedCodes.Get(usedName)
	if ok {
		return logical.ErrorResponse("code already used; wait until the next time period"), nil
	}

	valid, err := totplib.ValidateCustom(code, key.Key, time.Now(), totplib.ValidateOpts{
		Period:    key.Period,
		Skew:      key.Skew,
		Digits:    key.Digits,
		Algorithm: key.Algorithm,
	})
	// ...
	err = b.usedCodes.Add(usedName, nil, time.Duration(/* period * (2+skew) */))
```

Library behavior (same otp revision as `go.mod`): `TrimSpace` then length check — whitespace variants validate as the canonical code. Confirmed locally: `"525299 "` / `" 525299"` / `"525299\n"` all return `ok=true`.

### Remediation

Normalize (trim) before cache keying **and** enforce `len(code) == digits` before validation (upstream PR #31246). Upgrade to fixed releases.

---

## Finding 3 — Login MFA TOTP reuse + rate-limit bypass (CVE-2025-6015)

| Field | Value |
| --- | --- |
| **Severity** | Medium (CVSS 5.7 / AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N) |
| **CVE / advisory** | CVE-2025-6015 / HCSEC-2025-19 |
| **Primary location** | `vault/login_mfa.go` (`validateTOTP`) |
| **Attacker** | Principal mid login-MFA challenge (holds MFA pending creds) who observed/used a valid TOTP once |
| **Controls** | Whitespace variants of a used TOTP passcode on `sys/mfa/validate` |
| **Impact** | Replay MFA within validity window; successful whitespace replay also `Delete`s the per-entity attempt counter → rate-limit reset |
| **Fixed upstream** | CE 1.20.1 / Ent 1.20.1, 1.19.7, 1.18.12, 1.16.23 |

### Attack path

1. Target requires login MFA TOTP. Attacker completes first factor and reaches MFA validation.
2. Submit passcode `P` once (success or observe it). Cache entry `usedName = configID + "_" + P`.
3. Resubmit `P+" "` (or other `TrimSpace`-equivalent). Cache miss; `ValidateCustom` trims → success.
4. On success the handler deletes `rateLimitID = configID + "_" + entityID`, clearing failed-attempt throttling.
5. Attacker obtains a fully authenticated Vault token / continues MFA brute force after limit reset.

### Evidence

```2320:2400:vault/login_mfa.go
	passcode := mfaFactors.passcode
	// ...
	usedName := fmt.Sprintf("%s_%s", configID, passcode)
	_, ok := usedCodes.Get(usedName)
	if ok {
		return fmt.Errorf("code already used; ...")
	}
	rateLimitID := fmt.Sprintf("%s_%s", configID, entityID)
	// ... increment attempt counter ...
	valid, err := totplib.ValidateCustom(passcode, key, time.Now(), validateOpts)
	// ...
	err = usedCodes.Add(usedName, nil, validityPeriod)
	usedCodes.Delete(rateLimitID)
```

No pre-trim / digit-length gate in this tree (added upstream in login MFA fix PRs).

### Remediation

Same as Finding 2 for MFA path; upgrade to fixed releases.

---

## Finding 4 — Userpass/LDAP lockout key not normalized (CVE-2025-6004)

| Field | Value |
| --- | --- |
| **Severity** | Medium (CVSS 5.3 / AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N) |
| **CVE / advisory** | CVE-2025-6004 / HCSEC-2025-16 |
| **Primary location** | `vault/core.go` (`aliasNameFromLoginRequest`), `builtin/credential/userpass/path_login.go` (`pathLoginAliasLookahead`), LDAP alias lookahead |
| **Attacker** | Unauthenticated login brute-forcer |
| **Controls** | Case variants of the same username (`user` / `User` / `USER`) when lockout is enabled |
| **Impact** | Failed-login counters keyed per raw alias → lockout threshold bypassed; continues credential guessing |
| **Fixed upstream** | CE 1.20.1 / Ent 1.20.1, 1.19.7, 1.18.12, 1.16.23 |

### Attack path

1. User lockout enabled (default for userpass/ldap/approle unless disabled).
2. Lockout map key comes from `aliasNameFromLoginRequest` → credential backend `AliasLookaheadOperation`.
3. Userpass lookahead returns **raw** `username` (no `ToLower`); login path lowercases for storage lookup.
4. Attacker rotates case (`alice`, `Alice`, `ALICE`, …). Each variant is a distinct `FailedLoginUser.aliasName` → independent counters.
5. LDAP: lookahead also returns request username verbatim; when `case_sensitive_names=false`, auth still succeeds case-insensitively while lockout keys diverge.

### Evidence

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(...) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username, // NOT lowercased
			},
}
func (b *backend) pathLogin(...) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

```2155:2168:vault/request_handling.go
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
	userInfo.mountAccessor = mountEntry.Accessor
```

### Remediation

Normalize alias names for lockout keys the same way login/entity alias normalization works; upgrade to fixed releases. Interim: rate-limit quotas on login paths.

---

## Near-misses / negative results (scoped areas)

| Area | Result |
| --- | --- |
| **Identity ROOT case bypass (CVE-2025-5999)** | Present (`StrListContains(..., "root")` case-sensitive) — **skipped by policy** |
| **CVE-2024-9180 in-memory root via name path** | `MemDBEntityByName(..., false)` then mutate `Policies` before reject can leave live memdb tainted — same identity-ROOT class as skip; not reported separately |
| **Audit→plugin RCE / SSH ValidPrincipals / AWS AccountID / ACME SSRF / cert CN / identitytpl / AppRole CIDR / Agent token leak** | Skipped |
| **Proxy protocol DoS (CVE-2024-6468)** | Listener validation accepts `deny_authorized` but runtime expects `deny_unauthorized` → config for the DoS mode is not reachable on this tree (regression near-miss) |
| **JWT aud list skip (CVE-2024-5798)** | Fixed in 1.17.0 line; this tree vendors `vault-plugin-auth-jwt v0.20.3` — treated as already addressed |
| **pprof / metrics unauth** | Only when listener explicitly sets `unauthenticated_pprof_access` / `unauthenticated_metrics_access` — intentional operator footgun, not a default authz gap |
| **Custom UI messages HTML** | Enterprise custom-messages write is admin-gated (`sys/config/ui/custom-messages`); no non-admin set path validated in OSS stubs |
| **Cubbyhole / response wrapping / control-group / generate-root / rekey** | No novel medium+ authz bypass validated beyond known unauthenticated bootstrap/rekey ceremony design |
| **HCP / activity write** | `activity/write` appears test-only gated in this tree |

---

## Summary

| # | Issue | Sev | CVE | In skip list? |
| --- | --- | --- | --- | --- |
| 1 | Raft bootstrap challenge unbounded memory | High | CVE-2024-8185 | No |
| 2 | TOTP engine OTP reuse via whitespace | Medium | CVE-2025-6014 | No |
| 3 | Login MFA TOTP reuse + RL bypass | Medium | CVE-2025-6015 | No |
| 4 | User lockout case-variant bypass | Medium | CVE-2025-6004 | No |

Highest-priority unpatched, non-skipped issue on this commit: **CVE-2024-8185** (unauthenticated, High, Integrated Storage).
