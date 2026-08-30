# Application Security Review — Vault @ 0513545dd

**Tree:** HashiCorp Vault OSS (`version/VERSION` = `1.18.0-beta1`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-851f`  
**Scope:** Auth methods / MFA / XFF / identity / transit·cubbyhole·raft / plugin catalog / UI XSS — medium+ with E2E paths only. Known CVEs from the task prompt were not re-reported.

---

## Finding 1 — Okta auth entity alias uses client-supplied username (MFA / identity bypass)

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Location** | `builtin/credential/okta/path_login.go` |
| **Attacker** | Holder of a valid Okta password for a victim user (phished, reused, or sprayed), where Login MFA is enforced by **identity entity ID** (and/or internal identity groups that list that entity), not solely by auth mount type/accessor or Okta external group aliases |
| **Controlled input** | Login path/body `username` (Okta AuthN accepts the user’s login **or** email as `username`) |
| **Impact** | New Vault entity/alias that is not covered by entity-scoped MFA enforcement → Vault token issued **without** satisfying the intended MFA policy; identity entity policies bound to the canonical entity also do not apply |

### Attack path

1. Victim normally authenticates as Okta login `alice` (or whatever canonical `profile.login` is). Vault creates entity `E1` with alias name `alice`. Admin attaches Login MFA enforcement to `E1` (or an internal identity group containing only `E1`).
2. Attacker authenticates with the same password via an **alternate Okta identifier** for the same account, e.g. `POST /v1/auth/okta/login/alice@company.com` with `password=<victim>`. Okta Primary Authentication accepts username **or** email for the same user.
3. Okta returns success and embeds the real user (`result.Embedded.User`, including stable `Id`). Groups are correctly loaded from that user.
4. Vault nevertheless sets the entity alias from the **client-supplied** string:

```118:129:builtin/credential/okta/path_login.go
	auth := &logical.Auth{
		Metadata: map[string]string{
			"username": username,
			"policies": strings.Join(policies, ","),
		},
		InternalData: map[string]interface{}{
			"password": password,
		},
		DisplayName: username,
		Alias: &logical.Alias{
			Name: username,
		},
	}
```

5. `CreateOrFetchEntity` treats `alice@company.com` as a distinct alias from `alice` → new entity `E2`.
6. `buildMFAEnforcementConfigList` does not match entity-ID (or internal-group) enforcement tied to `E1`. Login completes and a token is returned without MFA.
7. Contrast: GitHub auth already uses the IdP-canonical login (`*verifyResp.User.Login`) for the alias; Okta already has the canonical user available (`result.Embedded.User.Id` is used for group listing in `backend.go`) but does not use it for the alias.

Same class as HCSEC-2025-20 / CVE-2025-6013 (LDAP `username_as_alias` + non-normalized client username → MFA miss), but Okta **always** aliases from the client string (no opt-in flag), and the dual identifier is a first-class Okta AuthN feature (login vs email), not only whitespace.

### Evidence

- Alias name is the request `username`, not Okta user id / profile login (`path_login.go` above).
- Canonical user is available and used for groups only:

```321:326:builtin/credential/okta/backend.go
	var allGroups []string
	// Only query the Okta API for group membership if we have a token
	client, oktactx := shim.Client()
	if client != nil {
		oktaGroups, err := b.getOktaGroups(oktactx, client, &result.Embedded.User)
```

- MFA matching keys off entity ID / groups / mount (`vault/login_mfa.go` `buildMFAEnforcementConfigList`); a new entity evades entity-ID-scoped enforcement.
- Local Okta user policy map is also keyed by the raw username (`backend.go` `b.User(..., username)`), so `auth/okta/users/alice` policies are skipped on the alternate identifier (groups from Okta API still apply).

### Remediation

Set `Alias.Name` (and metadata username / display name) from a **canonical** Okta identifier after AuthN succeeds — preferably `result.Embedded.User.Id`, or normalized `profile.login` — never the raw client `username`. Trim/normalize the client string before any residual local user map lookups, or key local user maps by the same canonical id. Re-evaluate existing duplicate aliases (`alice` vs email) and merge or MFA-enroll as needed.

---

## Near-misses (not reported as medium+)

- **X-Forwarded client cert, no proof-of-possession** (`http/handler.go` `WrapForwardedForHandler`): once `x_forwarded_for_authorized_addrs` matches, header certs are prepended to `PeerCertificates` and cert auth trusts them without private-key proof. Documented reverse-proxy trust model; no bypass of the authorized CIDR check found.
- **OIDC `form_post` HTML sink** (`vault-plugin-auth-jwt` `cli_responses.go` `formpostHTML`): `state` interpolated into JS without escaping. Attacker-controlled `namespace` in state is the natural payload, but cache lookup keys the raw state while the IdP returns `state,ns=...`, so the success HTML path does not currently render attacker namespace content (latent sink / broken combo).
- **Radius / Kerberos client username as alias**: same non-canonical alias pattern as Okta in principle; RADIUS/Kerberos identifier duality is less clear than Okta login-vs-email for a clean E2E MFA story on this tree.
- **OCI auth aliases by role name** (`vault-plugin-auth-oci`): all principals on a role share one entity — intentional role-style identity, not an auth bypass.
- **Identity auto-merge `mergePolicies=true`** (`mergeEntityAsPartOfUpsert`): still present; privilege impact overlaps CVE-2025-5999 (out of scope to re-report). No new login-time merge E2E beyond that class.
- **UI `redirect_to`**: Ember `transitionTo` with in-app paths; not a classical open redirect to an external origin.
- **Transit / cubbyhole / raft snapshot / plugin catalog**: no medium+ authorization bypass beyond known CVE-2025-6000 class; snapshot and plugin APIs remain privileged admin operations with path/symlink checks intact for `..`.
