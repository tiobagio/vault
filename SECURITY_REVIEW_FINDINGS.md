# Application Security Review — HashiCorp Vault

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version:** `1.18.0-beta1`  
**Scope:** HTTP handlers, secret engines, trust-boundary bugs with medium+ end-to-end paths

---

## FINDING-1: PKI ACME http-01 / tls-alpn-01 SSRF to internal network targets

- **Severity:** Medium (CVE-2026-5052 / HCSEC-2026-06; HashiCorp CVSS 5.3)
- **Primary location:** `builtin/logical/pki/acme_challenges.go` (`ValidateHTTP01Challenge`, `ValidateTLSALPN01Challenge`)
- **Also:** `builtin/logical/pki/acme_challenge_engine.go` (challenge dispatch)

### Attacker model
Network attacker who can obtain an ACME account on an enabled PKI ACME directory (unauthenticated when `eab_policy=not-required`, or with a leaked/issued EAB token otherwise), and who controls DNS for at least one identifier used in an ACME order.

### Controlled input
ACME order identifier (DNS name). Attacker points that name at a loopback/link-local/RFC1918 address (or redirects http-01 to one).

### Reachability
1. Admin enables ACME (`pki/config/acme` `enabled=true`). In this tree, omitting `eab_policy` leaves `defaultAcmeConfig.EabPolicyName = not-required` (`path_config_acme.go`), so challenge endpoints stay on the unauthenticated path set.
2. Attacker creates account / order / authz and triggers `http-01` or `tls-alpn-01`.
3. Vault resolves the name and dials it with a default `net.Dialer` — **no private/loopback/link-local rejection**.
4. `CheckRedirect` only limits redirect count/URL length; it does **not** block redirects to internal URLs.

Evidence (no SSRF guards):

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via)+1 >= maxRedirects {
				return fmt.Errorf("http-01: too many redirects: %v", len(via)+1)
			}
			// ... length check only ...
			return nil
		},
	}
	resp, err := client.Get(path)
```

```455:475:builtin/logical/pki/acme_challenges.go
	dialer, err := buildDialerConfig(config)
	// ...
	address := fmt.Sprintf("%v:"+ALPNPort, domain)
	conn, err := dialer.Dial("tcp", address)
```

Affected range includes this tree (CE 1.14.0–1.21.4). Fix is not present here.

### Impact
Server-side request forgery from the Vault node to internal HTTP/TLS services during challenge validation, enabling internal network probing and potential information disclosure via response differentiation.

---

## FINDING-2: Cert auth non-CA trust does not bind entity alias to trusted leaf identity (CN impersonation)

- **Severity:** Medium (CVE-2025-6037 / HCSEC-2025-18)
- **Primary location:** `builtin/credential/cert/path_login.go` (`verifyCredentials` non-CA branch + `pathLogin` alias construction)

### Attacker model
Principal who possesses a trusted **non-CA** client certificate **and its private key** (e.g., issued leaf registered in `auth/cert/certs/:name`), on a mount that uses CN-based identity aliases (default).

### Controlled input
A newly minted client certificate that reuses the trusted leaf’s public key, serial number, and Authority Key ID, but sets an arbitrary Subject CN.

### Reachability
Non-CA match only checks serial + AKID + public key equality, then optional `allowed_*` constraints (empty = allow all). Entity alias is taken from the **presented** cert CN, not the registered trusted leaf’s CN:

```279:308:builtin/credential/cert/path_login.go
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

```160:169:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

`matchesCommonName` is skipped when `allowed_common_names` is unset (default allow).

### Impact
Identity impersonation: attacker authenticates as another CN-mapped entity, inheriting that entity’s policies/groups. Affects CE &lt; 1.20.1 (this tree included).

---

## FINDING-3: Login MFA / TOTP secrets engine — TOTP reuse via non-normalized passcodes

- **Severity:** Medium (CVE-2025-6015 / HCSEC-2025-19; related HCSEC-2025-17 for secrets engine)
- **Primary locations:**
  - `vault/login_mfa.go` (`validateTOTP`)
  - `builtin/logical/totp/path_code.go` (`pathValidateCode`)

### Attacker model
Attacker who can observe or reuse a just-consumed TOTP code (phishing, shoulder-surf, compromised first factor mid-MFA), against login MFA TOTP or the TOTP secrets engine validate API.

### Controlled input
Passcode string variants that `pquerna/otp` still accepts as valid (leading/trailing spaces/tabs) but that miss the used-code cache key.

### Reachability
Used-code / rate-limit keys are built from the **raw** passcode with no normalization:

```2324:2336:vault/login_mfa.go
	passcode := mfaFactors.passcode
	// ...
	usedName := fmt.Sprintf("%s_%s", configID, passcode)
	_, ok := usedCodes.Get(usedName)
	if ok {
		return fmt.Errorf("code already used; ...")
	}
```

```105:118:builtin/logical/totp/path_code.go
	usedName := fmt.Sprintf("%s_%s", name, code)
	_, ok := b.usedCodes.Get(usedName)
	// ...
	valid, err := totplib.ValidateCustom(code, key.Key, time.Now(), totplib.ValidateOpts{...})
```

Empirical check against the same library version: `"560833"`, `" 560833"`, `"560833 "`, and `"\t560833"` all validate `true`, so cache keys differ while crypto validation succeeds.

### Impact
Bypass of once-per-window TOTP reuse protection and weakening of MFA rate limiting / second-factor guarantees.

---

## FINDING-4: Privileged `sys/audit` operator → host code execution via file audit + plugin directory

- **Severity:** High (CVE-2025-6000 / HCSEC-2025-14) — included because it breaks the Vault↔host trust boundary; not an intentional admin capability
- **Primary locations:**
  - `audit/backend_file.go` (arbitrary `file_path` / legacy `path`, `prefix` support)
  - `vault/logical_system.go` / plugin catalog (`sys/plugins/catalog`) + `sys/audit-hash`

### Attacker model
Root-namespace operator with write on `sys/audit` (and ability to register/use plugins), when `plugin_directory` is configured.

### Controlled input
File audit device options (`file_path`/`path`, `prefix`) and subsequent plugin catalog registration of a binary written into the plugin directory.

### Reachability
In this tree there is **no** guard preventing a file audit sink from targeting the configured plugin directory; `prefix` is freely configurable. Combined with `sys/audit-hash` to compute the required SHA-256, a malicious operator can materialize a plugin binary and execute it in Vault’s process context. HashiCorp’s later fix disables prefix-by-default and blocks audit writes into the plugin directory — absent here.

### Impact
Arbitrary code execution on the Vault host (escape from intended Vault admin plane to OS).

---

## Rejection notes (investigated, not validated as medium+ E2E in this tree)

| Area | Why rejected |
| --- | --- |
| `http/handler.go` / `logical.go` / `util.go` auth bypass | Token extraction, wrap TTL, and forwarding headers behave as designed; no unauthenticated ACL bypass found. |
| `X-Forwarded-For` / client-cert header injection | Cert import only after authorized-proxy address check; misconfiguration is operator risk, not a code auth bypass. |
| `vault/logical_raw.go` | `sys/raw` is sudo/root (and recovery-token) by design; protected path list is intentional. |
| `vault/well_known_redirect.go` `Destination` + `url.ResolveReference` path traversal | Real rewrite bug (`../` can escape mount prefix to other `/v1/...` paths), but **no builtin** calls `RequestWellKnownRedirect` in this OSS tree; still ACL-enforced after rewrite. Not a standalone medium+ path without a registering plugin. |
| Transit nonce / CVE-2023-4680 | Fix present (`ErrNonceNotAllowed` when non-convergent). |
| Cert auth CVE-2024-2048 / OCSP CVE-2024-2660 | Public-key compare + OCSP issuer/serial checks present. |
| Plugin catalog hash bypass | `SecureConfig` SHA-256 enforced for non-container plugins at launch. |
| Request forwarding identity confusion | Forwarding preserves client request; no confused-deputy auth swap found. |
| Audit log readable by unauthenticated clients | Audit devices are sinks, not unauth HTTP readers; HCSEC-2024-01/`log_raw` fix is in tree lineage. |
| UI custom messages XSS | Ember escapes message body; create requires privileged policy. `javascript:` links would be admin-stored content (out of scope as admin-only). |
| KV / cubbyhole cross-token access | No medium+ privilege bug validated beyond intended token-scoped cubbyhole. |

---

## Summary

Four validated medium+ issues remain exploitable in this commit, all aligned with later HashiCorp advisories still unfixed in `1.18.0-beta1`: ACME SSRF, cert-auth CN impersonation, TOTP reuse via whitespace, and audit-device→plugin host RCE.
