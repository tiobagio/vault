# Application Security Review — Vault UI / Auth / Identity / sys / Audit

**Tree:** HashiCorp Vault OSS (`version/VERSION` = `1.18.0-beta1`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-56b2`

Scope: NEW validated medium+ findings with end-to-end attack paths on:

1. `ui/` — XSS, open redirects, CSRF, auth token leakage to third parties, dangerous Handlebars/HTML injection  
2. `builtin/credential/{userpass,radius,token}` — auth bypass, timing, privilege issues  
3. `vault/` identity — entity merge / group / alias privilege escalation for a low-priv token  
4. `http/sys_*` — unauthenticated endpoints that leak sensitive data or allow incorrect state change  
5. `audit/` — secrets into logs without HMAC when a low-priv user can force it  

**Excluded (not re-reported):** CVE-2025-\*, CVE-2026-\*, Duo IP, GitHub slug, cert renew, LIST trailing slash, ACL `+/*`, MySQL DisplayName SQLi, UI OIDC `prompt=none` open redirect in `ui/app/routes/vault/cluster/oidc-provider.js`.

---

## Verdict

**0 validated medium+ findings** with a defendable, non-excluded end-to-end attack path in the scoped surfaces.

---

## Areas checked

### 1. UI (`ui/`)

| Surface | Evidence | Outcome |
|--------|----------|---------|
| Triple-stash HTML | `ui/app/templates/components/console/log-error-with-html.hbs` (`{{{@content}}}`) fed by `control-group.js` `logFromError` | Wrap token/accessor are base62; `creation_path` is `req.Path`. HTML in path is self-XSS / social-engineering only — below medium+ |
| `sanitized-html` | DOMPurify + `htmlSafe`; catch fallback returns raw string | Fallback not realistically triggerable; KV visualDiff / static help text only |
| Custom message links | `vault/ui_custom_messages/message.go` — no `Href` scheme validation; templates bind `@href={{href}}` | Ent + `sys/config/ui/custom-messages` write + click. `isHrefExternal` / new-tab behavior weakens reliable same-origin token theft; admin trust boundary — not defended as medium+ |
| Open redirect | `vault/cluster/redirect.js` `replaceWith(redirect_to)` | Ember route names/paths only; not an external open redirect |
| OIDC provider redirects | `oidc-provider.js` `_handleError` / `_redirect` | Server validates `redirect_uri` before most errors; `invalid_client_id` / `invalid_redirect_uri` stay on-error UI. `prompt=none` path excluded |
| CSRF | Token in `localStorage`, sent as `X-Vault-Token` header; no cookies | Cross-site form CSRF not applicable |
| Token → third party | Service worker MessageChannel for raft snapshot; OIDC `postMessage(..., window.origin)`; JWT popup origin/`isTrusted`/`source` checks | Same-origin SW / origin-checked postMessage; no third-party sink |
| Production CSP | `ui/config/content-security-policy.js` `enabled: environment !== 'production'` | CSP off in prod builds noted; no standalone XSS sink elevated to medium+ |

### 2. Credential backends

| Backend | Checks | Outcome |
|---------|--------|---------|
| **userpass** | bcrypt vs `[]byte("dummy")` for missing users; `ErrInvalidCredentials` only for existing users (lockout path) | Timing / lockout username enumeration — Low / known class, not medium+ auth bypass |
| **userpass** | CIDR bound check after password verify; renew policy equivalence | No bypass |
| **radius** | Password in `Auth.InternalData` for renew; stripped from client responses (`request_handling.go` clears `InternalData`) | Not returned to clients; not placed in audit Auth struct |
| **token** (`vault/token_store.go`) | Root/orphan/period/sudo gates; cannot mint root without root parent; batch cannot be root | No low-priv privilege escalation |

### 3. Identity merge / group / alias

| Path | Notes | Outcome |
|------|-------|---------|
| Explicit merge | `pathEntityMergeID` → `mergeEntity(..., mergePolicies=false)` still moves group memberships to `to_entity` | Privileged `identity/entity/merge` capability; intentional identity-admin behavior, not low-priv |
| Upsert merge | `mergeEntityAsPartOfUpsert` sets `mergePolicies=true` on alias conflict | Requires identity entity write |
| Alias move | `handleAliasUpdate` can reassign `canonical_id` | Same identity-admin ACL boundary |
| External groups | `refreshExternalGroupMembershipsByEntityID` only applies aliases that already exist in MemDB for the mount | userpass/radius do not emit attacker-controlled group aliases |
| Case-variant `root` on entity/group policies | Present (`StrListContains(..., "root")` without case-fold) | **Excluded** as CVE-2025-5999 |

### 4. Unauthenticated `sys_*` / `http/`

| Endpoint | Behavior | Outcome |
|----------|----------|---------|
| `internal/ui/mounts` | Unauth sees only `listing_visibility=unauth` truncated info | Intentional |
| `internal/ui/authenticated-messages` | Listed unauth but handler returns empty list without valid token | No leak |
| `internal/ui/unauthenticated-messages` | Active pre-login messages only | Intentional |
| `internal/specs/openapi` | Filtered through UI mounts visibility | No unexpected secret leak |
| `wrapping/lookup` | Metadata only (`creation_ttl/time/path`); needs wrapping token | Intentional |
| `generate-root` / `rekey` unauth DoS | Present | **Excluded** (CVE-2026-\* / prior) |
| `mfa/validate` | Unauth; pops cache by UUID `mfa_request_id` | UUID not guessable; wrong code re-queues entry |
| Feature flags / health / seal-status | Redaction options; no secret material | OK |
| CORS | Token not in cookies; custom header required | CSRF/CORS token theft not viable |

### 5. Audit HMAC

| Mechanism | Notes | Outcome |
|-----------|-------|---------|
| `HashRequest` / `HashResponse` | HMAC string values in `Data`; `HashAuth` only token+accessor | By design |
| `request_uri` | Copied plaintext when query string present (`entry_formatter.go`) | Secrets in query strings (e.g. fields marked `Query: true`) can appear plaintext while the same values are HMAC’d in `data`. Clients/docs generally use bodies; treated as known URL-logging footgun, not a new medium+ “force someone else’s secret” path |
| Auth `Metadata` / `DisplayName` / `Path` | Never HMAC’d | Usernames/paths by design; no low-priv path to force arbitrary third-party secret values into these fields |
| `log_raw` / `audit_non_hmac_*` | Admin mount/device config | Out of low-priv scope |
| RADIUS password | Request `password` HMAC’d in `data`; renew uses `InternalData` (not audited Auth fields) | No new leak |

---

## Near-misses (below reporting bar)

1. **UI console control-group HTML** (`log-error-with-html.hbs` + `creation_path`) — requires HTML-bearing path + Ent control groups; self-XSS.
2. **Audit `request_uri` vs HMAC’d `data`** — query-string secrets can bypass HMAC in the URI field; not a clean low-priv → third-party secret disclosure without an audit-reader colluder and secret-in-URL client behavior.
3. **Custom message `javascript:` / unsafe `href`** — Ent UI-config privilege + user click; weak reliable exploitation with external-link new-tab behavior.
4. **userpass bcrypt `"dummy"` timing / lockout asymmetry** — username enumeration (Low).

---

## Conclusion

No new medium+ vulnerability with attacker identity → controlled input → reachable sink → concrete impact was validated in the requested focus areas beyond issues already excluded or rejected on this tree.
