# Application Security Review — Vault @ 0513545dd

**Tree:** HashiCorp Vault OSS (`version/VERSION` = `1.18.0-beta1`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-ee95`

Scope: validated medium/high/critical findings with end-to-end attack paths. Speculative issues, admin-only SSRF without escalation, and DoS-only bugs were excluded.

---

## Validated findings

### 1. HIGH — PKI ACME http-01 / tls-alpn-01 SSRF to private/link-local targets

**CWE:** CWE-918  
**Public ID (later disclosure):** CVE-2026-5052 / HCSEC-2026-06 (affects 1.14.0–1.21.4; this tree is unfixed)

#### Attack path

1. **Attacker role:** Unauthenticated remote client (when ACME is enabled and EAB is not required — the default `eab_policy` is `not-required`), or any holder of a valid EAB token.
2. **Controlled input:** ACME `new-order` identifiers — DNS names under attacker DNS control, and/or literal IP identifiers (including RFC1918 / loopback / link-local / cloud metadata).
3. **Vulnerable sinks:**
   - `ValidateHTTP01Challenge` in `builtin/logical/pki/acme_challenges.go` — builds `http://` + attacker domain/IP and calls `client.Get`, following redirects (up to 10) with **no** private/loopback/link-local destination checks.
   - `ValidateTLSALPN01Challenge` in the same file — dials attacker host:443 with `InsecureSkipVerify: true`.
   - Challenge dispatch in `ACMEChallengeEngine` (`builtin/logical/pki/acme_challenge_engine.go`) allows http-01 for both DNS and IP identifiers.
4. **Impact:** Vault server initiates outbound HTTP/TLS connections to attacker-chosen internal addresses (metadata services, admin panels, localhost services). Response body is not fully returned to the client, but timing/error differentials and redirect behavior enable internal network discovery / limited information disclosure. Matches the later CVE description.

#### Evidence

- Default ACME config (`builtin/logical/pki/path_config_acme.go`): `Enabled: false` but when enabled, `EabPolicyName: eabPolicyNotRequired`, `DefaultDirectoryPolicy: "sign-verbatim"`.
- `SignVerbatimRole` (`builtin/logical/pki/issuing/roles.go`): `AllowAnyName: true`, `AllowIPSANs: true` — private IPs are accepted as order identifiers.
- `ValidateHTTP01Challenge`: no `IsLoopback` / `IsPrivate` / `IsLinkLocal` / `IsGlobalUnicast` checks; redirects only limited by count and URL length.
- Tests in `path_acme_order_test.go` explicitly exercise identifiers like `127.0.0.1` and `192.168.0.1`.

#### Prerequisites

PKI mount with ACME enabled (`config/acme` `enabled=true`) and cluster path configured. Default directory policy `sign-verbatim` (default) maximizes impact; role-restricted directories still allow SSRF via attacker-controlled DNS A/AAAA records for allowed names, and via http-01 redirects to internal IPs.

---

### 2. MEDIUM — Redshift database plugin: SQL injection in default revoke path

**CWE:** CWE-89

#### Attack path

1. **Attacker role:** Authenticated Vault user who can generate dynamic Redshift credentials (`database/creds/<role>`), with a display name / username containing SQL metacharacters (e.g. LDAP `login/(?P<username>.+)` or JWT `user_claim` → `Auth.DisplayName`), **or** an operator who configured a custom `username_template` that embeds unsanitized `{{.DisplayName}}`.
2. **Controlled input:** Token `DisplayName` flows into `dbplugin.UsernameMetadata.DisplayName` via `builtin/logical/database/path_creds_create.go`, then into the Redshift username template.
3. **Vulnerable sink:** `(*RedShift).defaultDeleteUser` in `plugins/database/redshift/redshift.go`:

```go
revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Unlike neighboring statements that use `dbutil.QuoteIdentifier(username)`, this interpolates `username` into a **string literal** with no escaping. On lease revoke/expiry Vault executes that statement as the configured DB root user.

4. **Impact:** Breakout from the string literal → arbitrary SQL as the Vault Redshift connection user (typically highly privileged). Credential creation often uses `"{{name}}"`-quoted identifiers (single quotes inside the name are legal), so create can succeed while revoke is injectable.

#### Evidence

- Sink: `plugins/database/redshift/redshift.go` (`defaultDeleteUser`, `call terminateloop('%s')`).
- Contrast: same function correctly uses `dbutil.QuoteIdentifier` for `REVOKE` / `DROP USER`.
- DisplayName source: LDAP allows unrestricted path usernames (`builtin/credential/ldap/path_login.go`); JWT sets `DisplayName: alias.Name` from claims (`vault-plugin-auth-jwt`).
- Default template truncates DisplayName to 8 characters (limits payload shape); **custom `username_template`** (supported config) removes that limitation and makes exploitation straightforward.

---

### 3. MEDIUM — HANA database plugin: unsanitized username in default revoke SQL

**CWE:** CWE-89

#### Attack path

1. **Attacker role:** Same as finding 2 — dynamic creds consumer whose `DisplayName` can carry spaces / quotes / SQL tokens (LDAP/JWT), especially with a permissive custom `username_template`.
2. **Controlled input:** Generated username from `usernameProducer.Generate(req.UsernameConfig)`.
3. **Vulnerable sinks:** `(*HANA).revokeUserDefault` in `plugins/database/hana/hana.go`:

```go
fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username)
fmt.Sprintf("DROP USER %s RESTRICT", req.Username)
```

Usernames are interpolated as bare SQL identifiers with no quoting/validation. Default template uppercases and replaces `-` but **preserves spaces and quotes**, enabling multi-token SQL (e.g. injected `PASSWORD "..."` clauses) when DisplayName is attacker-influenced.

4. **Impact:** Privilege escalation to arbitrary SQL on the HANA instance via Vault’s configured root DB credentials during lease revocation.

#### Evidence

- Sinks: `plugins/database/hana/hana.go` `revokeUserDefault`.
- Default template: `plugins/database/hana/hana.go` `defaultUserNameTemplate` (truncate/replace/`uppercase` only).
- DisplayName pipeline identical to finding 2.

---

## Top near-misses (investigated, below reporting bar)

1. **Cert auth CRL URL SSRF (`builtin/credential/cert/backend.go` `fetchCRL` → `http.Get(crl.CDP.Url)`)**  
   URL is set only via authenticated write to `crls/:name` (auth method admin). No privilege escalation beyond intended admin network reachability.

2. **JWT/OIDC `oidc_discovery_url` / `jwks_url` SSRF (`vault-plugin-auth-jwt`)**  
   Fetches occur on admin config write / key refresh. Same admin-trust model; no unauthenticated or low-priv trigger found.

3. **AWS IAM auth STS request construction (`builtin/credential/aws/path_login.go`)**  
   Client supplies `iam_request_url`, but outbound host is admin `STSEndpoint` (default `sts.amazonaws.com`). `validateLoginIamRequestUrl` constrains Action; not a client-controlled open proxy.

4. **Agent/Proxy static secret cache (`command/agentproxyshared/cache/lease_cache.go`)**  
   Cache key ignores token by design, but `checkCacheForRequest` requires the requesting token to be recorded in `index.Tokens` after a successful prior fetch; capability renewal via `sys/capabilities-self`. No cross-token secret disclosure found.

5. **File physical backend path traversal (`sdk/physical/file/file.go`)**  
   `validatePath` rejects any path containing `..` (`consts.ErrPathContainsParentReferences`). Keys are not a realistic unauthenticated input surface anyway (barrier-encrypted storage API).

Additional near-misses: identity ACL templating is substitution-only (no SSTI/RCE); CORS `*` requires admin enablement; OIDC provider `validRedirect` enforces allowlists (loopback port-agnostic per RFC 8252 only).

---

## Summary

| # | Severity | Issue | Exploitable by |
|---|----------|--------|----------------|
| 1 | High | ACME challenge SSRF | Unauth (ACME on, EAB off) / EAB holder |
| 2 | Medium | Redshift revoke SQLi | Low-priv dynamic-creds user + special DisplayName / custom username_template |
| 3 | Medium | HANA revoke SQLi | Same as #2 |
