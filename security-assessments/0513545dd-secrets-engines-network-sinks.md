# Vault AppSec — secrets engines / network sinks @ 0513545dd (1.18.0-beta1)

Scope: `builtin/logical/{aws,consul,nomad,rabbitmq,ssh,pki,transit,totp}`, physical backends (runtime-attacker identifiers only), agent templates/exec sink, HTTP custom response headers/CORS, template injection beyond SSH CA comma injection.

Skipped (per brief): SSH CA comma injection, ACME SSRF, audit file RCE, database SQLi family.

## Finding 1 — MEDIUM: TOTP secrets engine one-time code reuse via whitespace (builtin/logical/totp)

**Related class:** same root cause as Login MFA CVE-2025-6015 / HCSEC-2025-19, but **different sink** (`builtin/logical/totp`, not `vault/login_mfa.go`).

### Attacker
Principal with `update` on `totp/code/<key>` (validate), who can observe or obtain one valid TOTP (phish, shoulder-surf, compromised app log, or first validation they themselves performed).

### Controlled input
`code` field on `POST/PUT totp/code/:name`.

### Path
1. Store key via `totp/keys/:name`.
2. Submit valid code `N` → `pathValidateCode` caches under `usedName = fmt.Sprintf("%s_%s", name, code)` using the **raw** string (`builtin/logical/totp/path_code.go`).
3. Identical replay of `N` is rejected (`code already used`).
4. Resubmit whitespace variant (` N`, `N `, `\tN`, `N\n`).
5. Cache key differs → miss; `totplib.ValidateCustom` → `hotp.ValidateCustom` does `passcode = strings.TrimSpace(passcode)` then accepts.

### Impact
Breaks the one-time guarantee of the TOTP secrets engine. Any application that relies on Vault TOTP validate for replay protection can accept the same OTP twice within the validity window. Medium.

### Files
- `builtin/logical/totp/path_code.go` (`pathValidateCode`, usedCodes keying)
- `builtin/logical/totp/backend.go` (in-memory `usedCodes` cache)
- Dependency: `github.com/pquerna/otp/.../hotp.ValidateCustom` TrimSpace

### Proof
Standalone against pquerna/otp@v1.2.1 (Vault’s pin): raw + space/tab padded variants all `valid=true`; simulating Vault’s `name_code` map shows padded form misses the cache while still validating.

---

## Finding 2 — HIGH: SSH CA signs empty ValidPrincipals (any-user cert) — CVE-2024-7594 class

**Not** the skipped SSH CA comma-injection theme. Empty `ValidPrincipals` means OpenSSH treats the cert as valid for **any** principal.

### Attacker
Token with permission to `ssh/sign/<role>` (or `ssh/issue/<role>`) on a CA role with `allow_user_certificates=true`.

### Controlled input
Omit `valid_principals`, or send `valid_principals=""`. Role may omit `default_user`.

### Path
1. Admin creates CA role without requiring principals, e.g. `key_type=ca`, `allow_user_certificates=true` (optional `allowed_users=ubuntu`). `createCARole` does **not** require `default_user` (`builtin/logical/ssh/path_roles.go`).
2. Attacker signs with no/`""` principals.
3. `calculateValidPrincipals` (`builtin/logical/ssh/path_issue_sign.go`):

```go
case len(parsedPrincipals) == 0:
    return nil, nil  // empty ValidPrincipals on cert
```

4. Early return happens **before** `allowed_users` enforcement.
5. Resulting cert has empty principals → accepted as any user (including root) on hosts trusting the Vault SSH CA.

Stronger variant: even when `default_user` is set, explicit `valid_principals=""` takes the GetOk branch and still yields empty principals, bypassing the default.

### Impact
Privilege escalation on SSH hosts that trust the Vault CA and authorize by certificate principals. High (CVE-2024-7594).

### Files
- `builtin/logical/ssh/path_issue_sign.go` (`calculateValidPrincipals`)
- `builtin/logical/ssh/path_roles.go` (`createCARole` — no empty-principal guard)
- `builtin/logical/ssh/path_sign.go` / `path_issue.go`

Note: `allow_empty_principals` fix (post-1.17.6) is **absent** on this tree.

---

## Discarded near-misses

| Area | Why discarded |
|------|----------------|
| SSH CA comma injection via identity templates | Explicitly skipped |
| PKI ACME HTTP-01/DNS SSRF | Explicitly skipped |
| AWS/RabbitMQ username `text/template` | Admin-configured templates; DisplayName sanitized on token create; AWS auth `/` in DisplayName PathEscaped by rabbit-hole |
| AWS `policy_document` / Consul ACL policy “template injection” | Static role config; no identity templating at creds issuance; role writers are privileged |
| Consul/Nomad token Description/`Name` with DisplayName | Cosmetic metadata only |
| RabbitMQ `Tags: []string{role.Tags}` | Marshals to comma-joined string; role-admin only |
| Physical Cassandra/MySQL/Cockroach table names in `fmt.Sprintf` SQL | Configured only at storage backend init (storage admin), not runtime API attacker |
| Agent exec sink / env_template `command` | Local agent config; env_template forbids `command`/`exec`; no untrusted remote template |
| Agent file sink path | Config attacker = host admin |
| Custom response headers (incl. potential CORS/Set-Cookie) | Listener HCL; server admin. Blocks `X-Vault-*` only; no runtime attacker |
| CORS `allowed_origins=*` reflecting Origin | Operator misconfig; no `Allow-Credentials`; token not cookie-based |
| Transit user nonce without convergent | Fixed earlier (`EncryptWithFactory` rejects nonce when not allowed) |
| TOTP invalid-code cache poisoning / in-memory HA | Low: DoS/nuisance; single active node |
| Login MFA TOTP whitespace | Out of this brief’s engine focus (already tracked as CVE-2025-6015 elsewhere) |

## Verdict

Two validated medium+ findings in scope: **TOTP secrets-engine whitespace reuse (Medium)** and **SSH empty ValidPrincipals (High / CVE-2024-7594)**.
