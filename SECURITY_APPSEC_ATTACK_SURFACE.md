# Application Security Review — HashiCorp Vault (`0513545dd`)

**Repo:** `tiobagio/vault` (snapshot of upstream Vault)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Version:** `1.18.0-beta1` (tip dated 2024-06-06)  
**Branch:** `cursor/application-security-review-aa41`  
**Method:** Static code review of reachable attack surfaces; independent verification of prior CVE/candidate locations on this tree.

---

## Fork / intentional-vuln assessment

**No CTF-style intentional vulnerable additions found in product code.**

- Working tree matches HashiCorp Vault OSS layout and history through `0513545dd`.
- `main` tip is the same commit; no custom backdoors, challenge flags, or planted vuln modules under `builtin/`, `vault/`, `http/`, or `plugins/`.
- Prior agent branches only added/removed markdown findings docs (then deleted). Those are review artifacts, not product forks.
- This tree is simply an **older, pre-patch** Vault release: multiple later HCSEC/CVE fixes are absent (confirmed via repo-wide search).

---

## Top directories and entry points

| Area | Path | Why high value |
|------|------|----------------|
| HTTP API mux | `http/handler.go`, `http/logical.go`, `http/util.go` | All client traffic; unauth endpoints; forwarding |
| Core request/ACL | `vault/request_handling.go`, `vault/acl.go`, `vault/router.go` | Authz gate for every logical op |
| Token / policy | `vault/token_store.go`, `vault/policy_store.go`, `sdk/helper/policyutil` | Privilege boundaries |
| Identity | `vault/identity_store_*.go`, `vault/identity_store_oidc_provider.go` | Entity/group policies, OIDC redirects |
| Auth methods | `builtin/credential/{aws,cert,ldap,github,approle,userpass,okta,radius}` | Login → token issuance |
| Secrets engines | `builtin/logical/{ssh,pki,database,transit,aws,...}` | Privileged crypto / credential minting |
| DB plugins | `plugins/database/{redshift,hana,mssql,postgresql,mysql,...}` | SQL construction with usernames |
| Audit | `audit/backend_file.go`, `audit/entry_formatter*.go` | Privileged write to filesystem |
| Plugins/RPC | `vault/plugincatalog/`, `sdk/helper/pluginutil/`, `sdk/plugin/` | Binary load + go-plugin RPC |
| Physical storage | `physical/`, `sdk/physical/file` | Path joins, SQL backends |
| Agent/Proxy | `command/agent*`, `command/agentproxyshared/` | Local listeners, auto-auth, SSRF headers |
| Client API | `api/` | Outbound Vault client (SSRF header helpers) |

### Unauthenticated / weakly gated HTTP surfaces (`http/handler.go`)

Always registered without token (by design): `/v1/sys/init`, `/v1/sys/seal-status`, `/v1/sys/unseal`, `/v1/sys/leader`, `/v1/sys/health`, `/v1/sys/generate-root/*`, `/v1/sys/rekey*`, raft bootstrap/join, `/v1/sys/internal/ui/feature-flags`.

**Config-gated unauth (high risk if enabled):**
- `UnauthenticatedMetricsAccess` → `/v1/sys/metrics`
- `UnauthenticatedPProfAccess` → `/v1/sys/pprof/*` (memory/CPU disclosure)
- `UnauthenticatedInFlightAccess` → `/v1/sys/in-flight-req`

Recovery mode exposes `/v1/sys/raw/` with recovery token.

---

## Highest-value candidate vulnerabilities (verified on this tree)

### 1. CVE-2025-6000 — Audit file backend → plugin-dir RCE (Critical)

| | |
|--|--|
| **Files** | `audit/backend_file.go` L48–57, L80–84; `audit/entry_formatter_config.go` L95–97; `audit/entry_formatter.go` L185–187 |
| **Why** | `file_path` and `prefix` accepted with no `AllowAuditLogPrefixing` gate and no block of writes under `plugin_directory`. Prefix prepended raw to every audit line. |
| **Attacker** | Principal with `sys/audit` write |
| **Path** | Enable file audit → `file_path` under plugin dir + executable `prefix` → register plugin → host RCE |
| **Status** | **STILL_VULNERABLE** (`AllowAuditLogPrefixing` absent repo-wide) |

### 2. CVE-2025-5999 — Identity entity `ROOT` / whitespace → root policy (High)

| | |
|--|--|
| **Files** | `vault/identity_store_entities.go` L355–363; `sdk/helper/policyutil/policyutil.go` `SanitizePolicies`; `vault/request_handling.go` (~L300) |
| **Why** | Entity write blocks only exact `"root"` after `RemoveDuplicates(..., false)` (no lower/trim). Request path later sanitizes → `"ROOT"` / `" root"` becomes real root. |
| **Note** | Groups use `RemoveDuplicatesStable(..., true)` before the check — entity path is the bypass. |
| **Status** | **STILL_VULNERABLE** |

### 3. CVE-2025-6037 — Cert auth non-CA CN impersonation (Medium–High)

| | |
|--|--|
| **Files** | `builtin/credential/cert/path_login.go` L160–169, L276–308, `matchesCommonName` |
| **Why** | Non-CA trust matches serial + AKID + pubkey only; alias `Name` = presented cert CN. Forged leaf with same key/serial/AKID but attacker CN impersonates another entity when `allowed_common_names` unset. |
| **Status** | **STILL_VULNERABLE** |

### 4. CVE-2024-7594 — SSH empty `ValidPrincipals` (High)

| | |
|--|--|
| **Files** | `builtin/logical/ssh/path_issue_sign.go` L192–195, L506–513 |
| **Why** | Empty principals returns `nil, nil` (success). OpenSSH treats empty principals as “any user/host”. No `allow_empty_principals` / `AllowEmptyPrincipals` in tree. |
| **Attacker** | Token with `ssh/sign` or `ssh/issue` on role with empty `default_user` |
| **Status** | **STILL_VULNERABLE** |

### 5. CVE-2025-11621 — AWS auth IAM/EC2 client cache cross-account (High)

| | |
|--|--|
| **Files** | `builtin/credential/aws/client.go` `stsRoleForAccount` L208–218, `clientIAM`/`clientEC2` cache; `backend.go` maps keyed by region+stsRole only; `path_login.go` `fullArn` |
| **Why** | Cache hit ignores `accountID`. Missing per-account STS config returns `""` (default account). Wildcard binds + name collision → wrong-account ARN resolution. |
| **Status** | **STILL_VULNERABLE** (no `clientKey{AccountID,...}`) |

### 6. CVE-2025-6013 — LDAP `username_as_alias` MFA bypass (Medium–High)

| | |
|--|--|
| **Files** | `builtin/credential/ldap/backend.go` L157–159; `path_login.go` L82–103 |
| **Why** | With `username_as_alias=true`, alias is raw request username (whitespace variants) not directory-canonical attr → MFA keyed to canonical entity missed. |
| **Status** | **STILL_VULNERABLE** |

### 7. Redshift `terminateloop` SQL injection (High)

| | |
|--|--|
| **Files** | `plugins/database/redshift/redshift.go` L435–451 |
| **Why** | `fmt.Sprintf(\`call terminateloop('%s');\`, username)` — unescaped string literal; nearby statements use `QuoteIdentifier`. Executed via `ExecuteDBQueryDirect`. |
| **Reachability** | Controllable username (LDAP DisplayName / custom template / static role) + revoke |
| **Status** | **STILL_VULNERABLE** |

### 8. HANA `DeleteUser` identifier SQLi (High)

| | |
|--|--|
| **Files** | `plugins/database/hana/hana.go` L347–359 (`revokeUserDefault`) |
| **Why** | `ALTER USER %s` / `DROP USER %s` with raw `req.Username`; no `QuoteIdentifier`. |
| **Status** | **STILL_VULNERABLE** |

### 9. MSSQL `dropUserSQL` catalog/username interpolation (Medium–High)

| | |
|--|--|
| **Files** | `plugins/database/mssql/mssql.go` L301, L412–421 |
| **Why** | `fmt.Sprintf(dropUserSQL, dbName.String, username, username)` into `USE [%s]` and `N'%s'` / `DROP USER [%s]`. Login drop path uses `QuoteName` correctly; user-drop path does not. |
| **Status** | Candidate / confused-deputy SQLi when DB name or username carries metacharacters |

### 10. PKI ACME HTTP-01 / TLS-ALPN SSRF (Medium) — CVE-2026-5052 class

| | |
|--|--|
| **Files** | `builtin/logical/pki/acme_challenges.go` `ValidateHTTP01Challenge` L125–168 |
| **Why** | `client.Get("http://" + domain + ...)` with plain dialer; redirects allowed; `InsecureSkipVerify`; **no** loopback/private/link-local rejection (`DialACME` / `IsLoopback` absent). |
| **Attacker** | ACME client controlling DNS for ordered identifier |
| **Status** | **STILL_VULNERABLE** |

### 11. GitHub auth Name/Slug dual-map privilege escalation (Medium)

| | |
|--|--|
| **Files** | `builtin/credential/github/path_login.go` ~L266–279 |
| **Why** | Both `team.Name` and `team.Slug` fed to `TeamMap.Policies` / group aliases. Display Name of team A can equal Slug of team B → cross-team policy/group escalation without joining privileged team. |
| **Attacker** | Org member who can create teams + GitHub auth login (not Vault admin) |
| **Status** | Validated design/authz bug relative to docs (“map by slug”) |

---

## Pattern search results (dangerous sinks)

### `os/exec` / `exec.Command`
Mostly CLI/test/plugin runner:
- `sdk/helper/pluginutil/run_config.go` — plugin binary spawn (SHA256 `SecureConfig`)
- `command/ssh.go` — client SSH wrapper
- `command/agent/exec/` — agent exec sink
- `api/tokenhelper/helper_external.go` — external token helper shell

No unauthenticated server-side shell of user HTTP body found in core HTTP path.

### Outbound HTTP / SSRF-class
| Location | Notes |
|----------|--------|
| `builtin/logical/pki/acme_challenges.go` | User/DNS-controlled domain → **SSRF** (above) |
| `builtin/credential/cert/backend.go` `fetchCRL` | `http.Get(crl.CDP.Url)` — admin-gated URL |
| `builtin/credential/aws/path_login.go` | STS endpoint / signed request submission |
| `builtin/credential/github|okta` | Admin-configured base URL |
| `api/client.go` | Adds Vault SSRF protection request header |

### SQL string concatenation
| Location | Risk |
|----------|------|
| `plugins/database/redshift/redshift.go` | **High** — `'%s'` username |
| `plugins/database/hana/hana.go` | **High** — unquoted identifier |
| `plugins/database/mssql/mssql.go` | **Medium+** — `dropUserSQL` |
| `plugins/database/postgresql/postgresql.go` | Uses quoting helpers more carefully — lower priority |
| `physical/{mysql,mssql,postgresql,cassandra,...}` | Table name from config (admin) |

### Path traversal / file
| Location | Notes |
|----------|--------|
| `sdk/physical/file/file.go` | `filepath.Join(base, key)` — tests reject `../` |
| `audit/backend_file.go` | Arbitrary `file_path` (intentional sink for CVE-2025-6000) |
| `vault/plugincatalog` | Symlink eval at register; SHA256 at run |

### Templates
| Location | Notes |
|----------|--------|
| `sdk/helper/ldaputil` | `text/template` for filters; FuncMap restricted; username usually `EscapeFilter` |
| `sdk/helper/template`, `sdk/framework/template.go` | Identity/role templating |
| SSH `allowed_users_template` | Template + comma-injection class (prior near-miss / separate reports) |

### Deserialization
Widespread `json.Unmarshal` / `mapstructure.Decode` into typed structs — normal for Vault. No high-confidence `yaml.Unmarshal` authz bypass in core request path. Plugin RPC uses go-plugin protobuf/netrpc with TLS handshake.

### XSS / CSRF / open redirect
- UI is Ember SPA under `/ui/` — classic CSRF less relevant for token-header API; cookie-less Vault API is primary.
- OIDC provider validates `redirect_uri` against registered client list (`vault/identity_store_oidc_provider.go`).
- HTTP leader redirect builds URL from configured redirect addr (`http/handler.go` ~L1120).

---

## Plugin / RPC boundary notes

- Catalog: `vault/plugincatalog/plugin_catalog.go` — register needs `sys/plugins` (admin); `SecureConfig` checksum in `sdk/helper/pluginutil/run_config.go`.
- Amplification: CVE-2025-6000 turns audit write into plugin binary write under `plugin_directory`.
- Container plugins / gRPC broker: multiplexed RPC — trust model is “plugin is untrusted code with Vault-issued wrapping token”; mis-registered plugins are RCE by design for admins.

---

## Near-misses / lower priority (still worth awareness)

1. **Cert CRL `http.Get`** — admin SSRF (`builtin/credential/cert/backend.go`).
2. **Cert SAN glob `*`** — `ryanuber/go-glob` multi-segment match; needs attacker-controlled leaf from trusted CA.
3. **`.well-known` `ResolveReference`** (`vault/well_known_redirect.go`) — path reshape; still ACL-gated.
4. **Unauth pprof/metrics** — info leak if listener flags enabled.
5. **Physical SQL backends** — config table names concatenated (admin-only).
6. **LDAP filter templates** — admin-configured; not classic unauthenticated SSTI.

---

## Suggested verification order (exploitability)

1. Audit file prefix → plugin dir (critical, privileged)
2. Identity entity `policies=["ROOT"]` (high, identity write)
3. SSH sign with empty principals (high, role ACL)
4. AWS IAM login cache/account mixup (high, multi-account)
5. Redshift/HANA revoke with malicious username (high, DB engine)
6. Cert non-CA CN forgery (medium–high)
7. LDAP username_as_alias + MFA (medium–high)
8. ACME DNS → loopback/metadata (medium)
9. GitHub team Name/Slug collision (medium, non-admin)

---

## Bottom line

This is **stock Vault 1.18.0-beta1**, not a CTF fork with planted bugs. Highest ROI surfaces are **audit→RCE**, **identity root policy case bypass**, **SSH empty principals**, **AWS auth cache**, **DB plugin SQL construction**, **cert non-CA CN**, **LDAP alias MFA**, **ACME SSRF**, and **GitHub team dual-key mapping** — all still present and reachable under realistic configs on this commit.
