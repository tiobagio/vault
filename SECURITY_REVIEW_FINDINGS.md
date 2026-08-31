# Application Security Review — HashiCorp Vault (tiobagio/vault)

Branch: `cursor/application-security-review-0b73`  
Scope: auth methods under `builtin/credential/`, MFA (`vault/login_mfa.go`, `helper/identity/mfa`), plugin boundaries, SQL/shell/URL sinks.

## Verdict

**No new validated medium/high/critical vulnerabilities** with end-to-end attack paths were confirmed outside the provided known list.

This OSS fork only ships these credential backends server-side: `approle`, `aws`, `cert`, `github`, `ldap`, `okta`, `radius`, `token`, `userpass`. JWT/OIDC/Kerberos/Azure/GCP/CF/AliCloud auth *servers* are absent (agent client stubs / UI / docs only).

## Surfaces traced (code-backed)

| Area | Paths reviewed |
|------|----------------|
| Auth | `builtin/credential/{approle,aws,cert,github,ldap,okta,radius,userpass}/` |
| MFA | `vault/login_mfa.go`, `vault/request_handling.go` (login MFA cache/validate), `vault/mfa_auth_resp_priority_queue.go` |
| Plugins / headers | `vault/router.go` (passthrough), `vault/request_handling.go` (Bearer strip), `vault/plugincatalog/` |
| DB / SQL sinks | `plugins/database/{postgresql,mysql,mssql,hana,redshift,cassandra,mongodb,influxdb}/`, `builtin/logical/database/` |
| SSH / PKI / secrets | `builtin/logical/{ssh,pki,consul,nomad,rabbitmq}/` |
| UI OIDC | `ui/app/routes/vault/cluster/oidc-provider.js` |

## Near-misses (rejected)

1. **Duo two-phase MFA uses validate-request IP, not stored login IP**  
   - Evidence: `RequestConnRemoteAddr` is stored with comment “needed for the DUO method” in `vault/request_handling.go`, but never read; `handleMFALoginValidate` passes `req.Connection.RemoteAddr` into `validateLoginMFA` / `validateDuo`.  
   - Rejected as **known**: “Duo Trusted-Networks MFA bypass” — same class (Duo Preauth `allow` on trusted IP skips MFA). The unused field is the incomplete binding for two-phase flows.

2. **MFA validate does not re-check `entity.Disabled` before `LoginMFACreateToken`**  
   - `handleMFALoginValidate` fetches the entity but never checks `Disabled`; `LoginCreateToken` also skips it.  
   - Rejected as **below medium**: subsequent authenticated requests deny disabled entities (`request_handling.go`), so a token minted in the ~300s MFA cache window is effectively unusable.

3. **Okta `verify/{nonce}` is unauthenticated and returns `correct_answer`**  
   - By design for CLI number-challenge UX (`builtin/credential/okta/path_login.go`). Requires password + social engineering; not a standalone auth bypass.

4. **Cert renewal identity binding uses `SKID != X && AKID != Y`**  
   - Rejected as **known**: “cert renewal AND/OR”.

5. **AppRole secret_id use-count burn before CIDR; ExpirationTime only in tidy**  
   - Rejected as **known**.

6. **DB plugins string-format usernames into SQL / DisplayName templates**  
   - Rejected as **known** DisplayName / default-revoke / static-role SQLi family.

7. **Authorization Bearer passthrough to plugins**  
   - Rejected as **known** CVE-2026-4525 class (`deniedPassthroughRequestHeaders` only blocks `X-Vault-Token`).

8. **UI OIDC `prompt=none` redirects to `redirect_uri` before client allow-list checks**  
   - Rejected as **known** open redirect.

9. **LDAP `AliasLookahead` returns raw username (not LDAP attr)**  
   - Used for lockout keying via `aliasNameFromLoginRequest`; MFA/entity binding for `username_as_alias` is **known** CVE-2025-6013.

10. **RADIUS policy lookup case vs storage `ToLower`**  
    - Rejected as **known** RADIUS case mismatch.

11. **Cert CRL/OCSP `http.Get` to configured/AIA URLs**  
    - Rejected as **known** OCSP/CRL SSRF.

12. **SSH CA allowed_users template comma-split / empty ValidPrincipals**  
    - Rejected as **known**.

## Notes for follow-up reviews

- Re-check Duo Trusted-Networks with an explicit fix that uses `cachedResponseAuth.RequestConnRemoteAddr` in `handleMFALoginValidate` if product intent is to bind Duo IP policy to the *login* client.
- External plugin auth methods (JWT/OIDC, cloud IAM) need a separate review against the enterprise/plugin trees not present in this fork.
