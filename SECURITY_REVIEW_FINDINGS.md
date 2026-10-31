# Application Security Review — HashiCorp Vault

**Repo:** tiobagio/vault (fork of hashicorp/vault)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `1.18.0-beta1`  
**Branch:** `cursor/application-security-review-2317`  
**Scope:** MEDIUM+ issues with end-to-end attack paths in authn/authz HTTP handling, ACL, token leakage, CORS/CSRF, webhooks/callbacks, plugin load by non-admins, and auth TOCTOU/races.

## Verdict

Four MEDIUM+ issues validated in this tree with defendable reachability. Several near-misses discarded (by design, below medium, or lacking privilege-escalation path).

---

## Validated findings

### 1. Userpass / LDAP lockout bypass via case-variant AliasLookahead (Medium–High)

- **Category:** Authentication bypass / weak auth check  
- **Known as:** CVE-2025-6004 / HCSEC-2025-16  
- **Attacker:** Unauthenticated client guessing passwords against Userpass (always) or LDAP with `case_sensitive_names=false` (default)  
- **Controlled input:** Username casing on `auth/<mount>/login[/...]`  
- **Reachability:**
  1. Failed-login lockout keys use `aliasNameFromLoginRequest` → `AliasLookaheadOperation`
  2. Userpass `pathLogin` lowercases the username; `pathLoginAliasLookahead` returns the **raw** username
  3. LDAP lookahead likewise returns the raw username
  4. Attacker rotates `Admin` / `ADMIN` / `AdMiN` → each casing gets its own failed-login counter → lockout never trips
- **Impact:** Brute-force lockout defeated; sustained online password guessing  
- **Evidence:**
  - `builtin/credential/userpass/path_login.go` (lookahead raw vs login `ToLower`)
  - `builtin/credential/ldap/path_login.go` (lookahead raw)
  - `vault/request_handling.go` `getLoginUserInfoKey` / `vault/core.go` `aliasNameFromLoginRequest`

### 2. AWS auth — IAM/EC2 client cache keyed without AccountID (High)

- **Category:** Authentication bypass  
- **Known as:** CVE-2025-11621 / HCSEC-2025-30  
- **Attacker:** IAM principal (or EC2 instance) in a **different** AWS account that collides on role/user name or matches a wildcard `bound_iam_principal_arn`  
- **Controlled input:** Valid STS `GetCallerIdentity` proof from the attacker account  
- **Reachability:**
  1. AWS auth configured for multi-account / STS role assumption
  2. `IAMClientsMap` / `EC2ClientsMap` keyed only by `(region, stsRole)` — **AccountID not in the key**
  3. Legitimate login populates cache; attacker login reuses the wrong-account client for ARN / EC2 checks
- **Impact:** Cross-account authentication into Vault roles intended for another AWS account  
- **Evidence:** `builtin/credential/aws/client.go` (`clientIAM` / `clientEC2` cache lookups); maps declared in `builtin/credential/aws/backend.go`

### 3. PKI ACME http-01 / tls-alpn-01 SSRF to internal targets (Medium)

- **Category:** Webhook/callback trusting unverified input  
- **Known as:** CVE-2026-5052 / HCSEC-2026-06  
- **Attacker:** Unauthenticated ACME client when `eab_policy` is `not-required` (default in this tree), or EAB token holder when required  
- **Controlled input:** ACME order identifier / DNS resolution target; redirect destination on http-01  
- **Reachability:**
  1. PKI mount with ACME enabled
  2. Default `EabPolicyName = not-required` leaves challenge paths unauthenticated
  3. `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge` dial resolved hosts with **no** loopback/private/link-local rejection
  4. HTTP-01 follows redirects (up to 10) with only length/count checks
- **Impact:** SSRF from the Vault node into localhost / link-local / internal HTTP(S) (e.g. metadata, admin ports)  
- **Evidence:** `builtin/logical/pki/acme_challenges.go`, `builtin/logical/pki/path_config_acme.go`, `builtin/logical/pki/acme_wrappers.go`

### 4. Raft bootstrap challenge — unauthenticated unbounded pending-peer map (High, availability)

- **Category:** Unauthenticated privileged/sensitive endpoint (DoS)  
- **Known as:** CVE-2024-8185 / HCSEC-2024-26  
- **Attacker:** Unauthenticated client reaching API on a raft-storage cluster  
- **Controlled input:** Unique `server_id` values on `POST /v1/sys/storage/raft/bootstrap/challenge`  
- **Reachability:**
  1. Path registered in `PathsSpecial.Unauthenticated`
  2. Each new `server_id` allocates into `pendingRaftPeers` and runs seal crypto
  3. No map bound / rate limit in this tree
- **Impact:** Memory/CPU exhaustion → Vault/host crash  
- **Evidence:** `vault/logical_system.go` (unauth registration); `vault/logical_system_raft.go` `handleRaftBootstrapChallengeWrite`  
- **Note:** Fixed upstream in 1.18.1; this tree is `1.18.0-beta1`.

---

## Discarded near-misses

| Candidate | Why discarded |
|-----------|----------------|
| CORS `allowed_origins=["*"]` reflects `Origin` | No `Access-Control-Allow-Credentials`; Vault auth is header-based (`X-Vault-Token` / Bearer), not cookies → no browser credential theft CSRF path |
| `decode-token` unauthenticated | Needs both `encoded_token` and initiator OTP; OTP only returned to generate-root initiator — by design |
| AppRole secret_id use-count burned before CIDR check | Use-count DoS from wrong IP, not privilege escalation / auth bypass |
| Duo MFA validate uses validate-request IP, not stored login IP | Requires stolen `mfa_request_id`; same class as known Duo Trusted-Networks issue; incomplete binding only |
| `plugins/reload` not in sudo Root list | Reload alone cannot load untrusted new code; catalog register/update remains sudo (`plugins/catalog/*`) |
| Audit file → plugin_directory RCE | Requires sudo on `sys/audit` (admin); not reachable by non-admins |
| Authorization Bearer passthrough (`deniedPassthrough` only blocks `X-Vault-Token`) | CheckToken strips Bearer when used as Vault auth before route; identity Authorization passthrough is intentional; no clear medium+ E2E theft path validated here |
| `handleSysRaftBootstrap` missing `return` after sealed error | Barrier ops fail when sealed; bug / confusing double-write, not privilege gain |
| XFF client-cert inject missing `return` when `r.TLS == nil` | Continues without injecting certs; no cert-auth bypass |
| Cert OCSP/CRL `http.Get` | Admin-configured URLs or known AIA SSRF class; not newly validated beyond known |
| `internal/ui/mounts` unauthenticated | Intentional UI bootstrap surface; limited mount metadata, not secret material |
| ACL path escaping (`../`, `%2e%2e`) | Request path taken from cleaned URL path; no escaping bypass validated in ACL matcher |
| Userpass bcrypt timing username oracle | Medium enumeration (CVE-2025-6011) — useful with #1 but weaker standalone than lockout bypass; omitted from primary list as secondary to finding 1 |

---

## Surfaces reviewed (no additional MEDIUM+ in scope)

- HTTP registration in `http/handler.go` (init/unseal/seal/health/raft join/bootstrap, unauth metrics/pprof/in-flight)
- `http/cors.go` + `vault/cors.go`
- Logical routing / `CheckToken` / login vs sudo Root paths in `vault/request_handling.go`, `vault/router.go`, `vault/acl.go`
- System unauthenticated paths in `vault/logical_system.go`
- Credential backends: `approle`, `aws`, `cert`, `github`, `ldap`, `okta`, `radius`, `token`, `userpass`
- Plugin catalog/reload (`vault/plugincatalog/`, `vault/plugin_reload.go`)
- MFA validate queue (`vault/login_mfa.go`, `vault/mfa_auth_resp_priority_queue.go`)
