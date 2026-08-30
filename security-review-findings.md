# Application Security Review Findings

**Target:** github.com/tiobagio/vault @ `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version marker:** Vault `1.18.0-beta1` / changelog `1.17.0-rc1` era  
**Scope:** Auth methods, secrets engines, sys/, templates, SSRF/path traversal, plugins — excluding the provided known/deduped set.

---

## Finding 1 — HIGH — Azure auth: client-controlled VM/VMSS/RG bypasses `bound_locations` (and related resource bounds)

**Maps to:** CVE-2025-3879 / HCSEC-2025-07 (not in the provided dedupe list; **unfixed in this tree**)  
**Primary location:** `github.com/hashicorp/vault-plugin-auth-azure@v0.18.0/path_login.go` — `verifyResource`

### Attacker
Any principal who can obtain a valid Azure AD access token for the Vault Azure auth resource (typically a Managed Identity / workload identity already allowed by `bound_service_principal_ids` / `bound_group_ids`, or any MSI when the role only binds resource constraints).

### Controlled input
Login fields: `vm_name`, `vmss_name`, `resource_group_name`, `subscription_id`, `resource_id`, plus `jwt`.

### Reachability
Unauthenticated `auth/<azure-mount>/login` → `pathLogin` → `verifyClaims` → `verifyResource`.

### Root cause
User-supplied `vm_name` / `vmss_name` / `resource_group_name` are **not** checked against Azure token claims (e.g. `xms_mirid`). Vault trusts the client’s resource identifiers, loads that Azure resource’s metadata, and evaluates `bound_locations` / related bounds from **that** metadata.

```266:274:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-auth-azure@v0.18.0/path_login.go
func (b *azureAuthBackend) verifyResource(ctx context.Context, subscriptionID, resourceGroupName, vmName, vmssName, resourceID string, claims *additionalClaims, role *azureRole) error {
	// If not checking anything with the resource id, exit early
	if len(role.BoundResourceGroups) == 0 && len(role.BoundSubscriptionsIDs) == 0 && len(role.BoundLocations) == 0 && len(role.BoundScaleSets) == 0 {
		return nil
	}

	if subscriptionID == "" || resourceGroupName == "" {
		return errors.New("subscription_id and resource_group_name are required")
```

```336:352:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-auth-azure@v0.18.0/path_login.go
	case vmName != "":
		client, err := b.provider.ComputeClient(subscriptionID)
		// ...
		vm, err := client.Get(ctx, resourceGroupName, vmName, &options)
		// ...
		location = vm.Location
```

```501:506:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-auth-azure@v0.18.0/path_login.go
type additionalClaims struct {
	NotBefore jsonTime `json:"nbf"`
	ObjectID  string   `json:"oid"`
	AppID     string   `json:"appid"`
	GroupIDs  []string `json:"groups"`
}
```

No `xms_mirid` / resource-id claim validation exists in this plugin version.

Additionally, the AppID/WIF fallback aggregates **client-provided** `resourceGroupName` with `role.BoundResourceGroups`, then **skips** the bound RG check on match:

```428:464:/home/ubuntu/go/pkg/mod/github.com/hashicorp/vault-plugin-auth-azure@v0.18.0/path_login.go
		rgChecks := []string{resourceGroupName}
		rgChecks = append(rgChecks, role.BoundResourceGroups...)
		// ... list UAIs, match claims.AppID ...
		wifMatch = true
	}
	// ...
	if !wifMatch && len(role.BoundResourceGroups) > 0 && !strListContains(role.BoundResourceGroups, resourceGroupName) {
		return errors.New("resource group not authorized")
	}
```

### End-to-end attack path (bound_locations)
1. Role configured with `bound_locations=["eastus"]` (and identity bounds the attacker already satisfies).
2. Attacker’s identity actually runs in a disallowed region (or uses shared UAI / AppID path).
3. Attacker supplies `vm_name` / `resource_group_name` of **any** VM in `eastus` that satisfies identity matching (shared UAI on that VM, or AppID list match via WIF path).
4. Vault reads that VM’s `Location=eastus` and allows login → **geographic bound bypass** → Vault token with the role’s policies.

### Impact
Authorization bypass of Azure auth resource constraints (`bound_locations`, and via the same trust gap related `bound_*` resource checks). Effective privilege is whatever policies the role grants (often broad machine/workload access).

### Why not deduped
Known set covers AWS auth cache, cert CN, LDAP/TOTP/userpass issues, etc., but **not** CVE-2025-3879 / Azure `bound_locations`.

---

## Finding 2 — MEDIUM — RADIUS auth: non-canonical username becomes entity alias → Vault Login MFA bypass

**Primary location:** `builtin/credential/radius/path_login.go` — `pathLogin` / `pathLoginAliasLookahead`

### Attacker
Someone with valid RADIUS credentials for a user whose Vault Login MFA is enforced on the **entity** or **entity alias** (not solely on the auth mount).

### Controlled input
`username` (body or URL) on `auth/<radius>/login` / `login/<username>`.

### Reachability
Unauthenticated RADIUS login. Many RADIUS backends treat usernames as case-insensitive and/or tolerate whitespace; Vault still accepts the raw string as the alias.

### Root cause
Policy user lookup lowercases the username for storage keys, but the **entity alias is the raw client username** (no `ToLower` / `TrimSpace`):

```85:90:builtin/credential/radius/path_users.go
func (b *backend) user(ctx context.Context, s logical.Storage, username string) (*UserEntry, error) {
	// ...
	entry, err := s.Get(ctx, "user/"+strings.ToLower(username))
```

```120:131:builtin/credential/radius/path_login.go
	auth := &logical.Auth{
		// ...
		DisplayName: username,
		Alias: &logical.Alias{
			Name: username,
		},
	}
```

Alias lookahead likewise returns the raw username (`pathLoginAliasLookahead`).

### End-to-end attack path
1. Admin attaches Login MFA to entity/alias for `alice` (canonical prior login).
2. Attacker authenticates to RADIUS as `Alice` or `alice ` (accepted by RADIUS).
3. Vault creates/fetches a **different** entity alias (`Alice` / `alice `).
4. MFA enforcement keyed to the original entity/alias does not apply → token issued without the second factor.

### Impact
MFA bypass for RADIUS users under entity/alias-scoped Login MFA. Same vulnerability class as LDAP `username_as_alias` whitespace MFA issues, but **RADIUS is not in the dedupe list** and is always username-as-alias.

### Notes
User lockout does **not** apply to RADIUS (`GetSupportedUserLockoutsAuthMethods` = userpass/approle/ldap only), so this is primarily an MFA/identity-binding issue, not a lockout bypass.

---

## Candidates reviewed that did **not** meet the bar (brief)

| Area | Outcome |
|------|---------|
| JWT/OIDC (`vault-plugin-auth-jwt@v0.20.3`) | Audience empty/list checks present (CVE-2024-5798 class fixed); redirect allowlist looks sound |
| Kubernetes auth `@v0.19.0` | TokenReview + bound SA/namespace checks; no new E2E bypass validated |
| GCP auth `@v0.18.0` | Bounds driven from JWT/instance metadata, not client-spoofed resource names |
| AppRole accessor destroy | Role membership check present (CVE-2023-24999 class fixed) |
| SSH empty `ValidPrincipals` | Still vulnerable in-tree but **already reported** (CVE-2024-7594) |
| Identity entity/group `"root"` exact-match only | Still present but **already reported** (CVE-2025-5999) |
| GitHub team Name+Slug | **Already reported** |
| SSH `allowed_users_template` comma-split | **Already reported** |
| RabbitMQ/Nomad/Consul | Role writers can grant strong remote privileges by design; no unintended injection path validated |
| Okta `verify/<nonce>` | Unauthenticated by design; nonce from CLI is 20-char base62 — not a practical unauth MFA break without nonce leak |
| DB engines | Known SQLi set excluded; no additional solid SQLi E2E beyond that set |
| Templated ACL slash injection | **Already reported** (CVE-2026-5006) |

---

## Summary

**2 validated findings** outside the dedupe set:

1. **HIGH** — Azure auth resource-bound bypass via unvalidated client `vm_name`/`vmss_name`/`resource_group_name` (CVE-2025-3879 present).
2. **MEDIUM** — RADIUS raw username → divergent entity alias → Login MFA bypass.
