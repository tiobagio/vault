# Authn/Authz Bypass Review — HashiCorp Vault

**Branch:** `cursor/application-security-review-959f`  
**Scope:** CRITICAL/HIGH authentication/authorization bypasses that do not require admin misconfiguration beyond normal feature enablement  
**Focus areas:** unauthenticated secret/token exposure & priv-esc, ACL/sudo/namespace/raw escapes, MFA bypass, identity policy attachment escalation, request-forwarding/header trust, UI token leaks  
**Method:** Static path validation with end-to-end attack-chain scrutiny. Prefer false negatives over weak findings.

---

## Validated findings

**None.**

No CRITICAL/HIGH authn/authz bypass with a concrete low-privilege (or unauthenticated) attacker → input → reachable code → privilege/secret impact chain was validated under the stated bar.

---

## Near-misses (failed the bar)

### 1. `.well-known` `ResolveReference` path rewrite
**Where:** `vault/well_known_redirect.go` `Destination()`; HTTP entry in `http/handler.go`  
**What:** Absolute or `../` `remaining` can rewrite the internal `/v1/...` target outside the registering mount (including across namespace path prefixes).  
**Why not a finding:** The rewritten request is re-dispatched through the normal handler (`hf`) and still subject to auth/ACL. No CE builtin unauthenticated target yields private keys/tokens via this rewrite alone.

### 2. X-Forwarded-For client certificate injection
**Where:** `http/handler.go` `WrapForwardedForHandler` prepends decoded header PEMs onto `r.TLS.PeerCertificates`; cert auth uses index `[0]` (`builtin/credential/cert/path_login.go`).  
**What:** When `x_forwarded_for_authorized_addrs` + `x_forwarded_for_client_cert_header` are enabled, a party that can speak from an authorized address (or a proxy that blindly forwards the client-cert header) can make Vault treat an attacker-supplied cert as the TLS peer cert.  
**Why not a finding:** Requires explicit proxy-trust configuration; treating a mis-set `authorized_addrs` or a non-stripping trusted proxy as “normal feature enablement” would be admin misconfiguration.

### 3. ACL identity templating + LDAP-style alias names
**Where:** `sdk/helper/identitytpl` injects values verbatim in ACL mode; `vault/policy.go` treats path segments with `/+` or leading `+/` as segment wildcards; LDAP login uses `login/(?P<username>.+)`.  
**What:** An admin policy of the form `path "kv/data/{{identity.entity.aliases.<accessor>.name}}/*"` combined with an alias name of `+` (or a name embedding `/+`) can widen the compiled ACL beyond the intended single-user prefix.  
**Why not a finding:** Depends on a specific templated policy design (docs emphasize `entity.id`); userpass `GenericNameRegex` cannot create such names. Not a default/low-priv bypass.

### 4. Identity alias reassignment / upsert merge with `mergePolicies=true`
**Where:** `handleAliasCreate` / `handleAliasUpdate` (`vault/identity_store_aliases.go`); `mergeEntityAsPartOfUpsert` → `mergeEntity(..., mergePolicies=true)` (`vault/identity_store_entities.go`).  
**What:** Write on `identity/entity-alias` can attach a caller’s auth alias to an existing high-policy entity; conflicting-alias upsert merges policies into the surviving entity.  
**Why not a finding:** Requires identity-admin ACL on entity-alias (or entity) write — not low-priv / default-policy. Extending “attach alias” into “attach arbitrary policies” is powerful but is the intended trust boundary for identity operators.

### 5. Unauthenticated ceremony / helper endpoints
**Where:** `sys/mfa/validate`, `sys/wrapping/lookup`, `sys/decode-token`, generate-root, raft join/bootstrap (`vault/logical_system.go` `PathsSpecial.Unauthenticated`).  
**What:** These skip ACL via the login-path path (`handleLoginRequest` / `CheckToken(..., unauth=true)`).  
**Why not a finding:** Each still requires a high-entropy secret (MFA request UUID, wrapping token, OTP+encoded root token, shamir shares, or join credentials). No path was found that turns enablement alone into token/secret disclosure or privilege gain.

### 6. UI token storage / static UI serving
**Where:** `ui/app/services/auth.js` + `ui/app/lib/local-storage.js`; `http/handler.go` `handleUI` / `UIAssetWrapper`.  
**What:** Session tokens live in `localStorage`; UI is static assets with SPA `index.html` fallback.  
**Why not a finding:** No server-side UI response path that embeds or reflects live client tokens was identified. XSS→localStorage theft is out of scope for “UI serving that leaks tokens” without a concrete XSS sink that meets the CRITICAL/HIGH bar here.

### 7. Prior Medium: OIDC `prompt=none` open redirect
**Where:** `ui/app/routes/vault/cluster/oidc-provider.js` (already noted in `APPSEC_REVIEW.md`).  
**Why not in this report:** Open redirect / phishing aid, not an authn/authz bypass that yields Vault privileges or secrets.
