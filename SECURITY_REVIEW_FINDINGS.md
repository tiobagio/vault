# Vault Security Review Findings

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Focus:** auth/authz bypasses and SSRF with complete end-to-end attack paths  
**Scope:** Candidate areas 1–7 as specified  

---

## VALIDATED FINDINGS (Medium+)

### 1. Identity entity/group policy assignment case-sensitivity bypass grants `root`

| Field | Detail |
| --- | --- |
| **Severity** | Critical |
| **Attacker** | Identity administrator (or any principal with `identity/entity` / `identity/group` write) — **not** root |
| **Controlled input** | `policies` on `identity/entity` or `identity/group` (e.g. `"Root"`, `"ROOT"`) |
| **Primary location** | `vault/identity_store_entities.go` |

**Attack path**

1. Attacker has permission to update identity entities/groups (common identity-admin ACL), but cannot assign policy name `"root"` (blocked).
2. Attacker writes `policies=["Root"]` (or `"ROOT"`) on an entity they control or can attach their alias to.
3. Entity path uses case-**sensitive** duplicate removal and an exact `"root"` denylist check — `"Root"` is accepted and stored.
4. On subsequent requests, `fetchACLTokenEntryAndEntity` merges identity policies through `policyutil.SanitizePolicies`, which lowercases names and collapses any `root` variant to sole policy `["root"]`.
5. `PolicyStore.GetPolicy` / `NewACL` treat that as the special root policy → full root privileges.

**Evidence**

```355:363:vault/identity_store_entities.go
		// Update the policies if supplied
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

Group path has the same exact-match denylist after `RemoveDuplicatesStable(..., true)`, which **preserves original case**:

```249:257:vault/identity_store_groups.go
	// Update the policies if supplied
	policiesRaw, ok := d.GetOk("policies")
	if ok {
		group.Policies = strutil.RemoveDuplicatesStable(policiesRaw.([]string), true)
	}

	if strutil.StrListContains(group.Policies, "root") {
		return logical.ErrorResponse("policies cannot contain root"), nil
	}
```

Escalation sink (lowercase + root collapse):

```300:302:vault/request_handling.go
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}
```

```51:64:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	defaultFound := false
	for i, p := range policies {
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		// ...
		if policies[i] == "root" {
			policies = []string{"root"}
```

**Impact**

Complete privilege escalation to Vault root from identity-entity/group writers.

**Remediation**

- Reject root with case-insensitive comparison (`strutil.StrListContainsCaseInsensitive` or lowercase before check).
- Normalize identity policy names with `strings.ToLower` at assignment time (same as `PolicyStore.sanitizeName` / `SanitizePolicies`).
- Add regression tests for `Root` / `ROOT` / mixed case on both entity and group write paths.

---

### 2. Cert auth token renew SKID/AKID binding uses AND-of-inequalities

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Holder of a stolen cert-auth token who also possesses a different valid client certificate under the same CA / role |
| **Controlled input** | TLS client certificate presented at renew (`subject_key_id` / `authority_key_id`) |
| **Primary location** | `builtin/credential/cert/path_login.go` |

**Attack path**

1. Victim authenticates via cert auth; token stores `subject_key_id` and `authority_key_id` in `Auth.InternalData`.
2. Attacker steals the token.
3. Attacker presents a **different** leaf certificate that still passes `verifyCredentials` for the same cert role (same CA → same AKID, different SKID).
4. Binding check fails closed only when **both** SKID **and** AKID differ. Same-CA different leaf (AKID matches) passes.
5. Token renews; certificate-binding intended to bind the lease to the original client identity is bypassed.

**Evidence**

```210:217:builtin/credential/cert/path_login.go
		skid := base64.StdEncoding.EncodeToString(clientCerts[0].SubjectKeyId)
		akid := base64.StdEncoding.EncodeToString(clientCerts[0].AuthorityKeyId)

		// Certificate should not only match a registered certificate policy.
		// Also, the identity of the certificate presented should match the identity of the certificate used during login
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Boolean intent requires OR (`||`): reject if either identity attribute changed.

**Impact**

Defeats cert-auth renew binding: stolen tokens can be prolonged with any other role-matching cert from the same CA, enabling persistence after the original cert is rotated/revoked (depending on OCSP/CRL config).

**Remediation**

- Change `&&` to `||`.
- Prefer constant-time compare of both fields; treat missing `InternalData` entries as binding failure when binding is enabled.
- Add renew tests: same AKID / different SKID must deny; both matching must allow.

---

### 3. PKI ACME HTTP-01 challenge follows redirects to arbitrary hosts (SSRF)

| Field | Detail |
| --- | --- |
| **Severity** | High (when ACME is enabled; especially with `eab_policy=not-required` or compromised EAB) |
| **Attacker** | Unauthenticated ACME client (public ACME) or any holder of a valid EAB |
| **Controlled input** | ACME order identifier domain / IP; HTTP redirect `Location` from attacker-controlled challenge host |
| **Primary location** | `builtin/logical/pki/acme_challenges.go` |

**Attack path**

1. Operator enables ACME (`pki/config/acme` `enabled=true`). ACME directory/order/challenge APIs are on the unauthenticated path list.
2. Attacker creates an ACME account and an order for a domain/IP allowed by the ACME role (default IP SANs allow private addresses such as `192.168.0.1`; `sign-verbatim` allows broad identifiers; DNS identifiers under allowed domains also work).
3. Attacker hosts `http://attacker.example/.well-known/acme-challenge/<token>` that **HTTP-redirects** to an internal target (e.g. `http://169.254.169.254/...`, `http://127.0.0.1:<port>/...`, RFC1918 hosts).
4. Attacker triggers challenge validation. Vault’s HTTP client follows up to 10 redirects with **no destination host/IP allowlist**, `InsecureSkipVerify: true` on TLS, and custom dialer.
5. Vault initiates outbound requests to attacker-chosen internal URLs (blind SSRF): metadata services, link-local, loopback, and internal HTTP APIs.

**Evidence**

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	transport := &http.Transport{
		// ...
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via)+1 >= maxRedirects {
				return fmt.Errorf("http-01: too many redirects: %v", len(via)+1)
			}
			// length check only — no private/link-local/localhost blocking
			return nil
		},
	}
	resp, err := client.Get(path)
```

Unauthenticated ACME surfaces:

```64:77:builtin/logical/pki/acme_wrappers.go
	b.PathsSpecial.Unauthenticated = append(b.PathsSpecial.Unauthenticated, unauthPrefix+"/directory")
	// ... new-account, new-order, challenge, etc.
```

Role validation allows private IPs when `allow_ip_sans` is true (default), confirmed by unit tests expecting `192.168.0.1` success.

**Impact**

Blind SSRF from the Vault server into cloud metadata, localhost, and internal networks whenever ACME HTTP-01 is reachable. Does not return response bodies to the attacker, but enables internal reachability probing and request forging.

**Remediation**

- Block redirects (or re-validate that redirect targets resolve to the same authorized identifier).
- Deny connection to loopback, link-local, RFC1918, CGNAT, and metadata ranges (including after DNS resolution / redirect).
- Prefer requiring EAB (`always-required`) for Internet-exposed Vault; restrict ACME roles’ allowed domains/IPs.
- Consider disabling HTTP-01 when only DNS-01 is required.

---

### 4. ACL policy template path injection via identity-controlled `+` segment

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Low-privilege auth user who can influence templated identity fields (alias name, entity name, or metadata values) used in ACL path templates |
| **Controlled input** | Alias name / entity metadata / group metadata containing path segment `+` (or crafted multi-segment values) |
| **Primary location** | `sdk/helper/identitytpl/templating.go` |

**Attack path**

1. Admin installs a templated ACL such as:
   `path "secret/data/{{identity.entity.aliases.<accessor>.name}}/*" { capabilities = ["read","create","update"] }`  
   intending per-user isolation.
2. Attacker authenticates with an alias name of `+` (cert CN, JWT subject/username claim, userpass username, etc.), or sets metadata value `+` where policies template `identity.entity.metadata.*` (metadata **values** are not character-restricted beyond length).
3. At request time, `parseACLPolicyWithTemplating` substitutes the field literally; path becomes `secret/data/+/*`.
4. Policy parser treats `/+` as a segment wildcard (`HasSegmentWildcards`), matching **any** segment — i.e. all tenants’ paths under that prefix.

**Evidence**

Raw substitution with no path-metacharacter escaping:

```54:60:sdk/helper/identitytpl/templating.go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", ErrTemplateValueNotFound
		}
		return t, nil
```

Wildcard recognition after templating:

```411:417:vault/policy.go
		if strings.Contains(pc.Path, "+*") {
			return fmt.Errorf("path %q: invalid use of wildcards ('+*' is forbidden)", pc.Path)
		}
		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}
```

Metadata values allow arbitrary characters (including `+`, `/`):

```1717:1734:vault/identity_store_util.go
func validateMetaPair(key, value string) error {
	// key charset validated; value only length-checked
	if len(value) > metaValueMaxLength {
		return fmt.Errorf("value is too long (limit: %d characters)", metaValueMaxLength)
	}
	return nil
}
```

**Impact**

Breaks intended path isolation of templated policies; horizontal privilege escalation across templated path prefixes.

**Remediation**

- Escape or reject ACL-significant characters (`+`, `*`, and ideally `/`) in templated identity values when `ACLTemplating` mode is used.
- Document that identity fields used in path templates must be treated as path-critical and constrained at auth/identity write time.
- Add tests: metadata/alias `+` must not yield segment-wildcard paths.

---

### 5. UI Identity OIDC provider `prompt=none` open redirect

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Unauthenticated web attacker (phishing / open-redirect chain) |
| **Controlled input** | Query params `prompt=none` and `redirect_uri` on Vault UI OIDC provider authorize route |
| **Primary location** | `ui/app/routes/vault/cluster/oidc-provider.js` |

**Attack path**

1. Attacker crafts a Vault UI URL for the Identity OIDC provider route with `prompt=none` and `redirect_uri=https://evil.example/cb` (plus optional `state`).
2. Victim (not logged into Vault) visits the link.
3. `beforeModel` short-circuits: if no token and `prompt=none`, it redirects **directly** to `qp.redirect_uri` with `error=login_required` — **without** calling the authorize API that enforces allowed redirect URIs.
4. Victim’s browser is sent to the attacker origin (open redirect), carrying `state` if present.

**Evidence**

```31:40:ui/app/routes/vault/cluster/oidc-provider.js
  beforeModel(transition) {
    const currentToken = this.auth.currentTokenName;
    const qp = transition.to.queryParams;
    qp.redirect_to = null;
    if (!currentToken && 'none' === qp.prompt?.toLowerCase()) {
      this._redirect(qp.redirect_uri, {
        state: qp.state,
        error: 'login_required',
      });
```

Allowed-URI validation only occurs later via the authorize backend call in `model()` (`invalid_redirect_uri`), which this branch never reaches.

**Impact**

Open redirect on the Vault UI origin — phishing aid, OAuth/OIDC confusion, trust abuse of the Vault hostname.

**Remediation**

- Do not redirect to `redirect_uri` until it is validated against the OIDC client’s allowed redirect URIs (call authorize or a dedicated validation endpoint first).
- Alternatively, for `prompt=none` + unauthenticated, render an error in-UI instead of redirecting to a client-supplied URL.
- Add an acceptance test that `prompt=none` with a non-allowlisted `redirect_uri` does not navigate off-origin.

---

### 6. Unauthenticated generate-root / rekey cancel and init state abuse

| Field | Detail |
| --- | --- |
| **Severity** | Medium (availability / operational; not credential theft by itself) |
| **Attacker** | Unauthenticated network client who can reach Vault’s API |
| **Controlled input** | HTTP methods on `/v1/sys/generate-root/*` and `/v1/sys/rekey*` |
| **Primary location** | `http/sys_generate_root.go` |

**Attack path**

1. Handlers are registered on the root HTTP mux **without** token ACL checks (intentional break-glass design).
2. During a legitimate generate-root (or rekey) ceremony, attacker sends `DELETE /v1/sys/generate-root/attempt` (or rekey init DELETE) → `GenerateRootCancel` / `RekeyCancel` clears progress.
3. Attacker can also `PUT` init to start a spurious attempt (`GenerateRootInit`), blocking a concurrent legitimate init (`root generation already in progress`) until cancelled.
4. Ceremony is disrupted; repeated cancel/init races delay emergency recovery.

**Evidence**

Unauthenticated route registration:

```190:199:http/handler.go
		mux.Handle("/v1/sys/generate-root/attempt", handleRequestForwarding(core,
			handleAuditNonLogical(core, handleSysGenerateRootAttempt(core, vault.GenerateStandardRootTokenStrategy))))
		mux.Handle("/v1/sys/generate-root/update", handleRequestForwarding(core,
			handleAuditNonLogical(core, handleSysGenerateRootUpdate(core, vault.GenerateStandardRootTokenStrategy))))
		mux.Handle("/v1/sys/rekey/init", handleRequestForwarding(core, handleSysRekeyInit(core, false)))
```

Cancel has no auth gate:

```135:141:http/sys_generate_root.go
func handleSysGenerateRootAttemptDelete(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	err := core.GenerateRootCancel()
	// ...
	respondOk(w, nil)
}
```

Status GET without token succeeds in tests (`http.Get(addr + "/v1/sys/generate-root/attempt")`).

**Impact**

Denial of service against root-token recovery and rekey operations. Does not mint root without unseal/recovery key shares, but can strand operators during incident response.

**Remediation**

- Require a shared recovery nonce/OTP from init to authorize cancel/update, or bind cancel to the init nonce.
- Rate-limit and audit aggressively; optionally allow listener-level restriction of these paths to management networks.
- Document network exposure risk; prefer restricting listeners that face untrusted clients.

---

## REJECTED CANDIDATES

### Okta/LDAP MFA bypass via non-canonical aliases — **not validated**

- Okta group lookups intentionally use `EqualFold` for policy mapping; MFA challenge flow is driven by Okta API status / Vault Login MFA enforcement lists.
- Identity alias indexes default to case-insensitive uniqueness (`Lowercase` indexer unless `disableLowerCasedNames`), which blocks simple case-variant duplicate-alias MFA skips.
- No complete unauthenticated / low-priv MFA bypass path was established from non-canonical alias handling alone. `bypass_okta_mfa` is an explicit admin configuration, not a bypass bug.

### Cert auth non-CA CN/SAN impersonation — **not validated as stated**

- Trusted non-CA leaves require matching serial, AKID, **and** public key (`ComparePublicKeysAndType`) before constraint checks — forged same-serial certs without the private key are rejected.
- CN/SAN-based aliasing for CA-trusted logins is design behavior under operator trust of the CA; not a standalone unauthenticated impersonation bug without a trusted CA issuance path.

---

## Summary table

| # | Title | Severity | Attacker privilege |
| --- | --- | ---: | --- |
| 1 | Identity policy `Root`/`ROOT` → root ACL | Critical | Identity write |
| 2 | Cert renew SKID/AKID `&&` binding bug | Medium | Stolen token + other valid cert |
| 3 | ACME HTTP-01 redirect SSRF | High | Unauth ACME (when enabled) |
| 4 | ACL template `+` path injection | Medium | User-influenced identity field |
| 5 | UI OIDC `prompt=none` open redirect | Medium | Unauthenticated web user |
| 6 | generate-root/rekey unauth cancel/init DoS | Medium | Unauthenticated API client |
