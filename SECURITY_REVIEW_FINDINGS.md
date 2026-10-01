# Application Security Review — Vault 1.18.0-beta1

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `version/VERSION` = `1.18.0-beta1`  
**Scope:** auth/authz, SSRF, injection, traversal, templates, JWT/cert, policy matching, fork diffs  
**Method:** Static code tracing of end-to-end attack paths (no exploit execution)

**Fork note:** No fork-specific malicious diffs vs typical Vault patterns. Commit history and authorship match upstream HashiCorp Vault around the 1.17/1.18-beta window.

---

## Finding 1 — Identity entity/group root policy case bypass

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CVE / advisory** | CVE-2025-5999 / HCSEC-2025-13 (also related class CVE-2024-9180) |
| **Primary location** | `vault/identity_store_entities.go` |
| **Attacker** | Authenticated operator with write on root-namespace identity APIs (`identity/entity`, `identity/entity/id/:id`, `identity/group`, …) — **not** a root token |
| **Controls** | `policies` array containing a case variant of `root` (e.g. `ROOT`, `Root`) |

### Attack path

1. Attacker holds a non-root token that can write identity entities/groups in the **root namespace**.
2. `PUT/POST /v1/identity/entity` (or update by id/name) with `"policies": ["ROOT"]`.
3. Write path only blocks the exact string `"root"` after `RemoveDuplicates(..., false)` (no lowercasing).
4. Entity is stored with `policies: ["ROOT"]`.
5. On a later request by a token tied to that entity, `fetchEntityAndDerivedPolicies` loads those policies; `policyutil.SanitizePolicies` lowercases them to `"root"`.
6. `GetPolicy` sanitizes names to lowercase and special-cases root ACL; `NewACL` sets `a.root = true` → full root for the token lifetime.

Same exact-string check on groups in `vault/identity_store_groups.go`.

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

```51:65:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	// ...
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		if policies[i] == "root" {
			policies = []string{"root"}
```

```535:544:vault/policy_store.go
	if policyType == PolicyTypeACL && name == "root" && ns.ID == namespace.RootNamespaceID {
		p := &Policy{
			Name:      "root",
			namespace: namespace.RootNamespace,
		}
```

### Why exploitable vs mitigated

Exploitable: write-time validation is case-sensitive; request-time policy resolution is case-insensitive and collapses to real root.  
Not mitigated in this tree: no `StrListContainsCaseInsensitive` / equivalent at write time. Upstream fixed in CE 1.20.0 / Ent 1.18.11+.

### Remediation

Reject root case-insensitively at entity/group write time; audit existing entities/groups for case-variant `root` assignments.

---

## Finding 2 — PKI ACME http-01 / tls-alpn-01 SSRF

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CVE / advisory** | CVE-2026-5052 / HCSEC-2026-06 |
| **Primary location** | `builtin/logical/pki/acme_challenges.go` |
| **Attacker** | Unauthenticated ACME client (or EAB holder if EAB required) once ACME is enabled |
| **Controls** | Order identifiers (DNS names / IPs) and DNS answers that resolve (or redirect) to loopback / link-local / other local targets |

### Attack path

1. Operator enables ACME on a PKI mount (`config/acme` `enabled=true`; default is off but a single config flip enables the surface).
2. Attacker creates an ACME account and `new-order` for an attacker-controlled DNS name (or IP identifier when roles allow IP SANs).
3. Attacker DNS resolves the name to `127.0.0.1` / `169.254.169.254` / etc., or serves http-01 with a redirect to an internal URL (up to 10 redirects allowed).
4. Vault’s challenge engine calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge`, which dial the resolved address with **no** GlobalUnicast / loopback / link-local rejection.
5. Vault connects to the internal target (information disclosure / internal service probing). ACME paths are registered unauthenticated in `acme_wrappers.go`.

### Evidence

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// counts redirects / URL length only — no destination IP policy
			return nil
		},
	}
	resp, err := client.Get(path)
```

No `IsLoopback` / `IsLinkLocal` / `IsGlobalUnicast` checks exist under `builtin/logical/pki/` in this tree. Upstream later added validation-target rejection + optional permitted/excluded CIDR config.

### Why exploitable vs mitigated

Exploitable when ACME is enabled: unauthenticated server-side fetches to attacker-influenced destinations, including redirect pivot.  
Partial mitigation: ACME defaults to `enabled=false`; EAB can be required. Neither blocks unsafe dial targets once challenges run.

### Remediation

Reject non-global-unicast destinations before dial (and optionally configure `challenge_permitted_ip_ranges` / `challenge_excluded_ip_ranges`); upgrade to fixed Vault releases.

---

## Finding 3 — File audit device → plugin directory host RCE

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CVE / advisory** | CVE-2025-6000 / HCSEC-2025-14 |
| **Primary location** | `audit/backend_file.go` |
| **Attacker** | Root-namespace operator with write on `sys/audit` (plus plugin catalog/mount when `plugin_directory` is set) — not necessarily a root token or OS admin |
| **Controls** | Audit `file_path` under `plugin_directory`; optional `prefix` / request shaping; SHA256 via `sys/audit-hash` |

### Attack path

1. Vault config sets `plugin_directory`.
2. Attacker enables a file audit device with `file_path` inside that directory — `newFileBackend` / `configureSinkNode` impose no plugin-dir exclusion.
3. Attacker shapes audit output (traffic + optional `prefix`) into a valid plugin binary; uses `sys/audit-hash` as described in HCSEC-2025-14 to materialize the required SHA256.
4. Attacker registers the file via `sys/plugins/catalog` and mounts it → Vault executes the binary from the plugin directory (`plugincatalog.setInternal`).

### Evidence

```48:57:audit/backend_file.go
	var filePath string
	if p, ok := conf.Config[optionFilePath]; ok {
		filePath = p
	} else if p, ok = conf.Config["path"]; ok {
		filePath = p
	} else {
		return nil, fmt.Errorf("%q is required: %w", optionFilePath, ErrExternalOptions)
	}
```

No `AllowAuditLogPrefixing` gate and no plugin-directory destination block exist in this tree. Plugin catalog still joins and execs under `plugin_directory`.

### Why exploitable vs mitigated

Escalation from Vault API capabilities (`sys/audit` + plugin catalog) to **host code execution**. Distinct from “already Vault root” (seal/destroy) because it yields OS-level process execution via plugin spawn. Upstream: disable audit `prefix` by default and forbid audit destinations under the plugin directory (CE 1.20.1+).

### Remediation

Upgrade; until then, avoid configuring `plugin_directory` with operators who can write `sys/audit`, or restrict audit device management tightly.

---

## Finding 4 — AWS auth IAM/EC2 client cache missing account ID

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CVE / advisory** | CVE-2025-11621 |
| **Primary location** | `builtin/credential/aws/client.go` |
| **Attacker** | Unauthenticated AWS principal from a **different** AWS account that can present valid STS/EC2 identity |
| **Controls** | IAM/EC2 login against roles using wildcard binds and/or multi-account STS where the default-account client is cached without account ID |

### Attack path

1. AWS auth role uses wildcard `bound_iam_principal_arn` (e.g. `arn:aws:iam::111111111111:role/MyRole*`) and/or multi-account STS with empty STS role for the default account.
2. Legitimate login from account `111111111111` caches an IAM/EC2 client keyed only by `region` + `stsRole` (not `accountID`).
3. Attacker from account `222222222222` with a colliding friendly role/user name authenticates.
4. Wildcard resolution calls `clientIAM(..., attackerAccountID)`; cache hit returns the **account-A** client, skipping `getClientConfig`’s account-ID check.
5. `GetRole`/`GetUser` against account A returns an ARN matching the wildcard bind → Vault issues a token for the attacker.

### Evidence

```284:290:builtin/credential/aws/client.go
	b.configMutex.RLock()
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

Account ID is validated in `getClientConfig` only on cache miss when `stsRole == ""`. Same map shape for EC2 clients.

### Why exploitable vs mitigated

Unauthenticated cross-account auth bypass under realistic wildcard/multi-account configs. Fixed upstream by including account ID in the cache key (CE 1.21.0 / Ent 1.20.5+).

### Remediation

Upgrade; avoid wildcard principal binds across accounts until patched; flush/reload AWS auth after credential config changes does not fix the missing cache key dimension.

---

## Finding 5 — Redshift default revoke SQL injection via username / DisplayName

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Primary location** | `plugins/database/redshift/redshift.go` |
| **Attacker** | Authenticated client who can request dynamic Redshift credentials and influence `DisplayName` (e.g. via auth username) so the generated username embeds SQL metacharacters |
| **Controls** | Username content flowing into `call terminateloop('%s')` on default revoke |

### Attack path

1. Database secrets engine uses Redshift with **default** revocation (no custom `revocation_statements`).
2. Default username template embeds truncated/lowercased `DisplayName` without stripping quotes:  
   `v-%s-%s-%s-%s` with `(.DisplayName | truncate 8)`.
3. Attacker authenticates with a DisplayName/username containing `'` (e.g. userpass user `a'`…), requests `database/creds/:role`, and obtains a lease whose username includes that quote.
4. On lease revoke, `defaultDeleteUser` builds `call terminateloop('<username>');` via `fmt.Sprintf` — breaking out of the string literal executes attacker SQL as the Vault DB user.  
   Nearby `DROP USER` uses `QuoteIdentifier`; the `terminateloop` call does not.

### Evidence

```37:37:plugins/database/redshift/redshift.go
	defaultUserNameTemplate = `{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 8) (.RoleName | truncate 8) (random 20) (unix_time) | truncate 63 | lowercase }}`
```

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

### Why exploitable vs mitigated

Default path is injectable; parameterized existence checks earlier do not protect the later string-built CALL. Custom revocation statements that properly quote `{{name}}` avoid this specific sink, but defaults are widely used.

### Remediation

Pass username as a bound parameter / properly escape for the CALL; strip or reject unsafe characters in generated usernames; prefer quoted identifiers consistently.

---

## Finding 6 — Cert auth non-CA leaf CN impersonation

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **CVE / advisory** | CVE-2025-6037 |
| **Primary location** | `builtin/credential/cert/path_login.go` |
| **Attacker** | Principal who possesses a trusted non-CA client certificate **and** its private key |
| **Controls** | Forged leaf with same serial + AKID + pubkey, different Subject CN |

### Attack path

1. Admin registers a non-CA leaf in cert auth (common for pinned clients).
2. Attacker with that leaf’s private key forges a twin certificate: same serial, AuthorityKeyId, and public key, but victim CN.
3. Non-CA match checks serial/AKID/pubkey only — not full cert equality / CN.
4. Alias is taken from the **presented** CN → attacker binds to victim entity / policies.

### Evidence

```283:308:builtin/credential/cert/path_login.go
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

Alias uses `clientCerts[0].Subject.CommonName`. Upstream fix uses `tCert.Equal(clientCert)`.

### Why exploitable vs mitigated

Requires possession of the trusted leaf private key (narrower than Findings 1–4) but is a real identity swap once that key is obtained (theft, shared device, mis-issued leaf).

### Remediation

Require full certificate equality for non-CA matches; prefer CA-based trust with SANs constraints.

---

## Near-misses (mitigated or below bar)

| Candidate | Outcome |
| --- | --- |
| Plugin catalog `..` / symlink escape | Blocked: `..` rejected; `EvalSymlinks` must stay in `plugin_directory`. |
| File physical backend path traversal | `validatePath` rejects `..`. |
| LDAP UserFilter Go templates | Admin-configured; username/UserAttr escaped before execute — not end-user template injection. |
| Agent/proxy `exec` | Local config operator controls command; not remote Vault API attacker. |
| Cert CRL/OCSP `http.Get` SSRF | Admin-configured URLs (or AIA after trust); expected privileged fetch surface. |
| `sys/raw` | Still root/sudo-gated via router `RootPath`. |
| Raft join / bootstrap HTTP handlers | Require sealed/unsealed state constraints and challenge/answer; not unauthenticated cluster takeover alone. |
| ACME when `enabled=false` | Default-off removes Finding 2 until enabled. |
| JWT/OIDC **auth methods** | Not bundled in this OSS `builtin/credential` tree (external plugins). |

---

## Summary

| # | Title | Severity | Location |
| --- | --- | --- | --- |
| 1 | Identity root policy case bypass (CVE-2025-5999) | High | `vault/identity_store_entities.go` |
| 2 | PKI ACME challenge SSRF (CVE-2026-5052) | High | `builtin/logical/pki/acme_challenges.go` |
| 3 | File audit → plugin dir host RCE (CVE-2025-6000) | High | `audit/backend_file.go` |
| 4 | AWS auth client cache missing account ID (CVE-2025-11621) | High | `builtin/credential/aws/client.go` |
| 5 | Redshift default revoke SQLi | High | `plugins/database/redshift/redshift.go` |
| 6 | Cert non-CA CN impersonation (CVE-2025-6037) | Medium | `builtin/credential/cert/path_login.go` |
