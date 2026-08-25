# Application Security Review Findings

**Target:** HashiCorp Vault (Go) at commit `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version:** `1.18.0-beta1` (`version/VERSION`)  
**Scope:** Unauthenticated endpoints, authz bypass, SSRF, path traversal, command/template injection, identity privilege escalation  

Only findings with a defended end-to-end attack path at medium or higher are listed below.

---

## Finding 1 — HIGH — Unauthenticated generate-root / rekey DoS (CVE-2026-5807 / HCSEC-2026-08)

**Severity:** High (CVSS 7.5 per HashiCorp)  
**CWE:** CWE-770  

### Attack path

1. **Attacker:** Anyone who can reach the Vault HTTP API (no token required).
2. **Action:** Repeatedly `PUT`/`DELETE` `/v1/sys/generate-root/attempt`, `/v1/sys/rekey/init`, and/or `/v1/sys/rekey-recovery-key/init`.
3. **Effect:** Occupies the single in-progress operation slot and/or cancels legitimate operator progress, blocking root-token generation and unseal/recovery rekey ceremonies.

### Evidence

Handlers are registered outside the authenticated logical router:

```190:199:http/handler.go
		mux.Handle("/v1/sys/generate-root/attempt", handleRequestForwarding(core,
			handleAuditNonLogical(core, handleSysGenerateRootAttempt(core, vault.GenerateStandardRootTokenStrategy))))
		mux.Handle("/v1/sys/generate-root/update", handleRequestForwarding(core,
			handleAuditNonLogical(core, handleSysGenerateRootUpdate(core, vault.GenerateStandardRootTokenStrategy))))
		mux.Handle("/v1/sys/rekey/init", handleRequestForwarding(core, handleSysRekeyInit(core, false)))
		mux.Handle("/v1/sys/rekey/update", handleRequestForwarding(core, handleSysRekeyUpdate(core, false)))
		mux.Handle("/v1/sys/rekey/verify", handleRequestForwarding(core, handleSysRekeyVerify(core, false)))
		mux.Handle("/v1/sys/rekey-recovery-key/init", handleRequestForwarding(core, handleSysRekeyInit(core, true)))
		mux.Handle("/v1/sys/rekey-recovery-key/update", handleRequestForwarding(core, handleSysRekeyUpdate(core, true)))
		mux.Handle("/v1/sys/rekey-recovery-key/verify", handleRequestForwarding(core, handleSysRekeyVerify(core, true)))
```

Init/cancel require no client token:

```18:30:http/sys_generate_root.go
func handleSysGenerateRootAttempt(core *vault.Core, generateStrategy vault.GenerateRootStrategy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handleSysGenerateRootAttemptGet(core, w, r, "")
		case "POST", "PUT":
			handleSysGenerateRootAttemptPut(core, w, r, generateStrategy)
		case "DELETE":
			handleSysGenerateRootAttemptDelete(core, w, r)
```

Single-slot lock:

```175:181:vault/generate_root.go
	c.generateRootLock.Lock()
	defer c.generateRootLock.Unlock()

	// Prevent multiple concurrent root generations
	if c.generateRootConfig != nil {
		return fmt.Errorf("root generation already in progress")
	}
```

Unauthenticated cancel clears progress:

```364:381:vault/generate_root.go
func (c *Core) GenerateRootCancel() error {
	// ...
	c.generateRootConfig = nil
	c.generateRootProgress = nil
	return nil
}
```

Same pattern for rekey (`http/sys_rekey.go` + `vault/rekey.go` `RekeyInit` / `RekeyCancel`).

Unauthenticated GET is exercised in-tree (`http/sys_generate_root_test.go` uses bare `http.Get` against `/v1/sys/generate-root/attempt`).

**Impact:** Availability of privileged recovery workflows (root generation / rekey). Fixed upstream in Vault 2.0.0 by requiring authentication on these endpoints.

---

## Finding 2 — HIGH — AWS Auth client cache missing account ID (CVE-2025-11621 / HCSEC-2025-30)

**Severity:** High (auth bypass under realistic multi-account / wildcard configs)  
**CWE:** CWE-288  

### Preconditions

- AWS auth method enabled.
- Multi-account STS config and/or `bound_iam_principal_arn` using wildcards / colliding role names across accounts.
- A prior successful auth/resolution populated the IAM or EC2 client cache.

### Attack path

1. Legitimate traffic caches an IAM/EC2 client under `(region, stsRole)` with **no account ID** in the key.
2. Attacker authenticates from a different AWS account with a colliding role name (or wildcard match).
3. `clientIAM` / `clientEC2` returns the **cached client for the wrong account** on cache hit (skipping `getClientConfig`’s account check).
4. ARN / unique-ID resolution and EC2 instance validation run against the wrong account, allowing unauthorized login.

### Evidence

Cache maps keyed only by region + STS role:

```76:86:builtin/credential/aws/backend.go
	// Map to hold the EC2 client objects indexed by region and STS role.
	EC2ClientsMap map[string]map[string]*ec2.EC2
	// Map to hold the IAM client objects indexed by region and STS role.
	IAMClientsMap map[string]map[string]*iam.IAM
```

Cache hit returns without validating `accountID`:

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

Account ID is only checked on cache miss inside `getClientConfig` (`defaultAWSAccountID != accountID`), which the hit path never reaches.

Login wildcard path uses this client via `fullArn` → `clientIAM`:

```1880:1891:builtin/credential/aws/path_login.go
func (b *backend) fullArn(ctx context.Context, e *iamEntity, s logical.Storage) (string, error) {
	// ...
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
```

**Impact:** Cross-account authentication bypass → Vault token for policies bound to the trusted principal. Fixed by including AccountID in the client cache key (upstream ~1.21.0 / 1.20.5 / 1.19.11 / 1.16.27).

---

## Finding 3 — MEDIUM — PKI ACME http-01 / tls-alpn-01 SSRF to local targets (CVE-2026-5052 / HCSEC-2026-06)

**Severity:** Medium (HashiCorp 5.3; NVD lists up to 8.6 depending on scoring)  
**CWE:** CWE-918  

### Preconditions

- PKI secrets engine with ACME enabled (`enabled = true`).
- Attacker can create ACME orders (depends on `eab_policy`; `not-required` allows unauthenticated ACME clients).
- Attacker controls DNS for a challenge domain (or supplies a literal IP as the identifier where accepted).

### Attack path

1. Attacker obtains/creates an ACME account and submits an order for a domain they control.
2. DNS for that domain returns loopback / link-local / unspecified / multicast (or other non-global-unicast) addresses.
3. Vault’s validator dials that address for http-01 (`http://{domain}/.well-known/acme-challenge/...`) or tls-alpn-01 (TCP/443).
4. Attacker probes Vault-reachable local services (metadata, admin ports, etc.) via challenge traffic and timing/error side channels.

### Evidence

No destination IP allow/deny filtering in this tree (`IsLoopback` / `IsLinkLocal` / `IsGlobalUnicast` / dial helpers absent under `builtin/logical/pki/`).

```125:170:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	dialer, err := buildDialerConfig(config)
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // redirect limits only; no IP family checks
			return nil
		},
	}

	resp, err := client.Get(path)
```

```471:474:builtin/logical/pki/acme_challenges.go
	address := fmt.Sprintf("%v:"+ALPNPort, domain)
	conn, err := dialer.Dial("tcp", address)
```

Invoked from the challenge engine:

```438:465:builtin/logical/pki/acme_challenge_engine.go
		valid, err = ValidateHTTP01Challenge(...)
		// ...
		valid, err = ValidateTLSALPN01Challenge(...)
```

**Impact:** Server-side request forgery / internal network probing from the Vault host. Upstream fix rejects unsafe validation targets before dialing.

---

## Near-misses (below medium+ / no solid novel exploit path)

| Candidate | Why it fails the bar |
|---|---|
| Agent/Proxy `/agent/v1/cache-clear`, `/agent/v1/metrics`, `/proxy/v1/*` unauthenticated | Documented intentional network-trust model; quit requires `enable_quit`. DoS/cache eviction only if listener is exposed. |
| `require_request_header` not wrapping cache-clear/quit/metrics | Real inconsistency (`command/agent.go` / `command/proxy.go`), but same trust-boundary assumption; residual impact is availability. |
| CVE-2026-4525 Authorization passthrough token leak | This commit always strips `Bearer` when `ClientTokenFromAuthzHeader`; the buggy `!unauth && te == nil` condition from later trees is **not** present here. |
| Raft `/sys/storage/raft/join` unauthenticated outbound | Only meaningful on uninitialized/sealed joining nodes; limited SSRF window, not a general production primary issue. |
| Plugin `Command` path traversal | Blocked by `..` rejection + `EvalSymlinks` directory check in `vault/plugincatalog/plugin_catalog.go`. |
| Agent template/`exec` command injection | Requires local privileged config writer; not a remote attacker path. |
| Identity `entity/merge` | Gated by normal ACL on identity paths; no unauthenticated/bypass path found. |

---

## Summary

| # | Severity | Issue | CVE |
|---|---|---|---|
| 1 | High | Unauthenticated generate-root/rekey DoS | CVE-2026-5807 |
| 2 | High | AWS auth client cache account-ID collision → auth bypass | CVE-2025-11621 |
| 3 | Medium | PKI ACME challenge SSRF to local targets | CVE-2026-5052 |

No additional novel medium+ issues with complete attack paths were validated in the requested focus areas beyond the above.
