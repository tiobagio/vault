# Application Security Review — Candidates

**Repo:** github.com/tiobagio/vault  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version:** `1.18.0-beta1`  
**Method:** Static reachability review (entry-point mapping + dangerous-pattern grep + call-chain tracing). No exploit PoC execution.

## Fork / upstream notes

This tree is a near-stock Hashicorp Vault OSS snapshot (`1.18.0-beta1`). Recent history is HashiCorp/PR traffic; no fork-local security-relevant custom auth methods, HTTP handlers, or plugin trust changes were identified beyond the upstream codebase at this commit. Prefer findings with clear local exploit paths in this tree (several match later upstream advisories).

## Entry-point map (high level)

| Area | Role |
|------|------|
| `http/` | Listener mux: seal/health/raft bootstrap, metrics/pprof (optionally unauth), `/v1/*` → logical |
| `vault/` | Core request handling, authz, MFA, system backend, raft, plugin catalog, identity/OIDC |
| `builtin/credential/` | Auth methods: approle, aws, cert, github, ldap, okta, radius, token, userpass |
| `builtin/logical/` | Secrets engines: pki (ACME), database, ssh, transit, kv, consul, rabbitmq, nomad, … |
| `plugins/database/` | DB plugins (SQL statement templates / revoke paths) |
| `command/`, `api/` | CLI / client — lower remote-attacker relevance |
| `audit/` | Audit sinks (arbitrary `file_path`) |

---

## Ranked candidates

### 1. File audit device → plugin directory host RCE

- **Severity:** Critical / High
- **Attacker model:** Privileged operator in root namespace with `sys/audit` write (and ability to register/use plugins), when `plugin_directory` is configured
- **Controlled input:** Audit `file_path` (any FS path Vault can write); optional `prefix`; plugin catalog registration
- **Attack path:**
  1. Enable file audit with `file_path` under the configured plugin directory — **no path restriction** in this tree
  2. Use `prefix` / audit content to shape on-disk bytes; sink opens with create/append
  3. Register plugin pointing at that path (SHA-256 of crafted content) and mount/execute → code execution as Vault process user
- **Impact:** Escape from Vault ACL domain to OS-level RCE on the Vault host
- **Primary location:** `audit/backend_file.go`
- **Evidence:** Arbitrary `file_path` accepted (`audit/backend_file.go` ~48–84, 127–130); `os.OpenFile` create/append in `internal/observability/event/sink_file.go`; attacker-controlled line `prefix` in `audit/entry_formatter.go` ~185–187. Plugin catalog joins command under `plugin_directory` (`vault/plugincatalog/plugin_catalog.go`).
- **Confidence:** High
- **Why it might be FP:** Requires already-powerful `sys/audit` (+ plugin register) privileges; some deployments treat that as full trust. Still a documented Vault→host trust-boundary break (CVE-2025-6000 / HCSEC-2025-14 class). Upstream later restricted audit paths overlapping plugin dirs.

---

### 2. Redshift secrets engine — SQL injection on default revoke

- **Severity:** High
- **Attacker model:** Principal who can generate (and later revoke/expire) dynamic Redshift credentials for a role using **default** revoke statements; username influenced by auth `DisplayName` (e.g. LDAP/Okta `O'Brien`) or custom `username_template`
- **Controlled input:** Characters in generated username (notably `'`) via DisplayName / template
- **Attack path:**
  1. Login sets `DisplayName` from username without Vault token `displayNameSanitize`
  2. `database/creds/<role>` → Redshift `NewUser` embeds DisplayName (`truncate 8` still preserves `'`)
  3. Lease revoke with empty custom `revocation_statements` → `call terminateloop('%s')` with **raw** username
- **Impact:** Arbitrary SQL as the Vault Redshift connection user on revoke (session kill / further DML/DDL per grants)
- **Primary location:** `plugins/database/redshift/redshift.go`
- **Evidence:**
  ```go
  // plugins/database/redshift/redshift.go:~451
  revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
  ```
  Nearby `DROP USER` correctly uses `dbutil.QuoteIdentifier`; this call does not. DisplayName flows from `builtin/logical/database/path_creds_create.go` → `UsernameConfig.DisplayName`. LDAP login pattern `login/(?P<username>.+)` sets `DisplayName: username`.
- **Confidence:** High
- **Why it might be FP:** Needs Redshift backend + default revoke path; DisplayName must carry `'`. Not “admin wrote malicious creation_statements” — creds **readers** trigger it. Upstream later quoted literals (VAULT-43691).

---

### 3. HANA secrets engine — SQL injection on default revoke

- **Severity:** High
- **Attacker model:** Same class as #2 against a HANA-backed database role
- **Controlled input:** Generated username with SQL identifier breakouts (`'`, etc.). HANA only replaces `-`→`_` and uppercases — does **not** strip quotes/semicolons
- **Attack path:** Creds create → lease revoke with empty custom statements → `revokeUserDefault` interpolates raw `req.Username` into `ALTER USER` / `DROP USER`
- **Impact:** SQL injection as Vault HANA connection user on revoke
- **Primary location:** `plugins/database/hana/hana.go`
- **Evidence:**
  ```go
  // ~348-359
  fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username)
  fmt.Sprintf("DROP USER %s RESTRICT", req.Username)
  ```
- **Confidence:** High
- **Why it might be FP:** Same environmental prerequisites as #2; custom revoke statements may avoid the default path. Upstream adds `QuoteIdentifier`.

---

### 4. AWS auth — cross-account client cache missing AccountID

- **Severity:** High
- **Attacker model:** IAM principal / EC2 identity in a **different** AWS account that collides on role/user name or matches wildcard `bound_iam_principal_arn`, against a multi-account STS-configured AWS auth mount
- **Controlled input:** Valid STS GetCallerIdentity (or EC2) proof from attacker account; cache key collision on `(region, stsRole)` **without** AccountID
- **Attack path:**
  1. Legitimate login populates `IAMClientsMap` / `EC2ClientsMap` keyed by region + STS role only
  2. Attacker login reuses cached client for the **wrong** account
  3. `fullArn` / EC2 validation against wrong-account client can satisfy wildcard or name-colliding binds
- **Impact:** Authentication bypass / cross-account privilege into Vault roles intended for another AWS account
- **Primary location:** `builtin/credential/aws/client.go`
- **Evidence:** Maps in `builtin/credential/aws/backend.go` ~76–86; cache lookup `clientEC2` / `clientIAM` ~227–231, 284–289 keyed by `region` + `stsRole` only; `fullArn` uses `clientIAM(..., e.AccountNumber)` but still hits that cache (`path_login.go` ~1888+). Login path is unauthenticated (`auth/aws/login`).
- **Confidence:** High (realistic multi-account + wildcard configs)
- **Why it might be FP:** Single-account / non-wildcard deployments may not be exploitable; needs STS role map configuration that creates collision conditions. Matches CVE-2025-11621 / HCSEC-2025-30 class.

---

### 5. Raft bootstrap challenge — unauthenticated memory/CPU DoS

- **Severity:** High (availability)
- **Attacker model:** Unauthenticated client that can reach the API on a raft-storage cluster (leader unsealed)
- **Controlled input:** Distinct `server_id` values on `POST /v1/sys/storage/raft/bootstrap/challenge`
- **Attack path:** Path is in `PathsSpecial.Unauthenticated`; each new `server_id` stores into unbounded `pendingRaftPeers` and runs `sealer.Seal()` crypto
- **Impact:** Memory/CPU exhaustion → Vault / host DoS
- **Primary location:** `vault/logical_system_raft.go`
- **Evidence:** Unauth registration in `vault/logical_system.go` ~165–166; handler ~269–296 stores without map bound/rate limit. Fixed upstream in 1.18.1; this tree is `1.18.0-beta1` (vulnerable). CVE-2024-8185 / HCSEC-2024-26.
- **Confidence:** High
- **Why it might be FP:** Only applies when Integrated Storage (raft) is in use; network ACLs may limit exposure.

---

### 6. PKI ACME http-01 / tls-alpn-01 SSRF to internal targets

- **Severity:** Medium
- **Attacker model:** Unauthenticated ACME client when `eab_policy` is `not-required` (default in this tree) **after** ACME is enabled; or EAB token holder if EAB required
- **Controlled input:** ACME order identifier / DNS resolution / HTTP redirect destination
- **Attack path:**
  1. PKI mount ACME `enabled=true` (admin prerequisite)
  2. Default `EabPolicyName: eabPolicyNotRequired` (`path_config_acme.go` defaultAcmeConfig)
  3. Unauth paths include `new-order`, `challenge/+/+` (`acme_wrappers.go` ~65–77)
  4. `ValidateHTTP01Challenge` dials resolved host via default dialer — **no** private/loopback filter; follows redirects (count/length only); TLS verify skipped
- **Impact:** SSRF from Vault node to localhost / link-local / internal HTTP(S) (metadata, admin ports); limited response oracle
- **Primary location:** `builtin/logical/pki/acme_challenges.go`
- **Evidence:** `buildDialerConfig` ~108–118 (plain `net.Dialer`); HTTP-01 client ~125–168 with `InsecureSkipVerify: true` and redirect allow; no IP safety checks.
- **Confidence:** High (when ACME enabled)
- **Why it might be FP:** ACME defaults to **disabled**; operator must enable. Response body limited (~512B) and used for challenge match — stronger as reachability/oracle than full response exfil. Upstream later added private-IP blocks (CVE-2026-5052 / HCSEC-2026-06 class).

---

### 7. Userpass / LDAP lockout bypass via case-variant alias lookahead

- **Severity:** Medium–High
- **Attacker model:** Unauthenticated password guesser against Userpass (always) or LDAP with `case_sensitive_names=false` (default)
- **Controlled input:** Username casing on login
- **Attack path:** Lockout keys use `AliasLookaheadOperation` alias name; Userpass login lowercases username but `pathLoginAliasLookahead` returns **raw** casing → each casing gets its own failed-login counter
- **Impact:** Bypass of user lockout; sustained online guessing
- **Primary location:** `builtin/credential/userpass/path_login.go`
- **Evidence:** Lookahead ~50–62 returns raw `username`; login ~66 does `strings.ToLower`. Lockout keying via `vault/request_handling.go` `getLoginUserInfoKey` → `aliasNameFromLoginRequest`. LDAP lookahead similarly raw (`builtin/credential/ldap/path_login.go`). CVE-2025-6004 / HCSEC-2025-16 class.
- **Confidence:** High
- **Why it might be FP:** Lockout must be enabled; LDAP with case-sensitive names may differ. Does not by itself grant auth without a valid password.

---

### 8. Userpass timing side-channel — username enumeration

- **Severity:** Medium
- **Attacker model:** Unauthenticated client hitting `auth/userpass/login/:username`
- **Controlled input:** Username (existence oracle via response timing)
- **Attack path:** Missing user sets `userPassword = []byte("dummy")` (invalid bcrypt); existing users run full bcrypt compare → measurable timing gap
- **Impact:** Username enumeration to focus credential attacks (pairs with #7)
- **Primary location:** `builtin/credential/userpass/path_login.go`
- **Evidence:** ~82–93 dummy path; bcrypt compare follows. CVE-2025-6011 / HCSEC-2025-15 class.
- **Confidence:** High (practical with enough samples)
- **Why it might be FP:** Network jitter; some argue “dummy” was intended to equalize (comment claims bcrypt still slow) but invalid hash short-circuits.

---

### 9. Authorization Bearer passthrough to plugins (X-Vault-Token auth)

- **Severity:** Medium (conditional High if plugin trusts Bearer)
- **Attacker model:** Authenticated client to a mount with `passthrough_request_headers` including `Authorization`, where the plugin/backend trusts `Authorization: Bearer`
- **Controlled input:** Extra `Authorization` header alongside `X-Vault-Token`
- **Attack path:**
  1. Client authenticates to Vault via `X-Vault-Token`
  2. Stripping logic only removes Bearer when token source was Authz header (`request_handling.go` ~400–413)
  3. `deniedPassthroughRequestHeaders` only blocks `X-Vault-Token` (`vault/router.go` ~25–27)
  4. Attacker-supplied Bearer is forwarded to plugin
- **Impact:** Confused-deputy / credential injection into plugins that honor Authorization (e.g. some custom/HTTP backends)
- **Primary location:** `vault/router.go` (deny list) / `vault/request_handling.go` (strip logic)
- **Evidence:** As above; default identity mount config can include Authorization passthrough (`vault/mount.go` ~1907).
- **Confidence:** Medium
- **Why it might be FP:** Stock OSS builtins may not consume Authorization; exploitability depends on mounted plugin behavior. CVE-2026-4525 class.

---

## Areas reviewed — no additional medium+ with defendable path here

| Area | Outcome |
|------|---------|
| CORS `*` | Admin-configured only; reflects configured origins when enabled (`vault/cors.go`) |
| Cert CRL/OCSP `http.Get` / AIA | Admin-configured URLs or CA-controlled AIA; not low-priv unauth SSRF without trusted chain |
| LDAP `text/template` filters | Username passed through `ldap.EscapeFilter`; admin owns filter template |
| DB creation_statements SQLi | Intentional privileged role SQL — not escalated beyond role writers |
| Agent/proxy file sink chown | Local config attacker model; not remote Vault API |
| External token helper `/bin/sh -c` | Local CLI helper; BinaryPath from user config |
| Plugin catalog `..` | Rejects `..` and validates symlink under plugin dir |
| Raft snapshot restore | ACL-gated |
| UI custom messages | Admin content; not traced to unauth XSS sink in this pass |
| JWT/OIDC/Kerberos auth servers | Not present as server backends in this OSS tree |

---

## Summary table

| # | Title | Severity | Attacker | Primary file | Confidence |
|---|-------|----------|----------|--------------|------------|
| 1 | File audit → plugin dir RCE | Critical/High | Privileged `sys/audit` | `audit/backend_file.go` | High |
| 2 | Redshift default revoke SQLi | High | Creds reader + crafted DisplayName | `plugins/database/redshift/redshift.go` | High |
| 3 | HANA default revoke SQLi | High | Creds reader + crafted DisplayName | `plugins/database/hana/hana.go` | High |
| 4 | AWS auth client cache AccountID bypass | High | Cross-account AWS login | `builtin/credential/aws/client.go` | High |
| 5 | Raft bootstrap challenge DoS | High | Unauthenticated | `vault/logical_system_raft.go` | High |
| 6 | PKI ACME challenge SSRF | Medium | Unauth ACME (if enabled) | `builtin/logical/pki/acme_challenges.go` | High |
| 7 | Userpass/LDAP lockout case bypass | Medium–High | Unauthenticated | `builtin/credential/userpass/path_login.go` | High |
| 8 | Userpass bcrypt dummy timing enum | Medium | Unauthenticated | `builtin/credential/userpass/path_login.go` | High |
| 9 | Authorization Bearer plugin passthrough | Medium | Authenticated + passthrough mount | `vault/router.go` | Medium |
