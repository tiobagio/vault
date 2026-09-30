# Application Security Review — Vault `0513545dd`

**Tree:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`version/VERSION` = `1.18.0-beta1`)  
**Method:** Code tracing + in-tree proof tests for the nominated candidates. Skip-list issues were not re-reported.

---

## Finding 1 — ACL privilege escalation via `+` / `*` injection in identity-templated policy paths

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Authenticated principal who can influence an identity value referenced by a templated ACL path (not Vault root/admin) |
| **Controlled input** | `identity.entity.metadata.*`, `identity.entity.aliases.<accessor>.name`, `identity.entity.aliases.<accessor>.metadata.*` / `custom_metadata.*` (via JWT `claim_mappings` / `user_claim`, Kubernetes `vault.hashicorp.com/alias-metadata-*` annotations when enabled, AppRole `secret_id` metadata, LDAP/Okta login username matching `.+`) |
| **Primary location** | `vault/policy.go` |
| **CWE** | CWE-639 (authorization bypass via attacker-controlled key in policy paths) |

### Attack path

1. Operator publishes a templated ACL that scopes access by an identity field the principal can influence, e.g.:
   ```hcl
   path "kv/data/{{identity.entity.metadata.department}}/*" {
     capabilities = ["read"]
   }
   ```
   or `{{identity.entity.aliases.<accessor>.name}}` / `...metadata.<key>}}`.
2. Attacker authenticates through an auth method that places attacker-influenced data into that field (JWT claim, K8s annotation, AppRole secret_id metadata, LDAP/Okta username, etc.).
3. Attacker sets the value to `+` (segment wildcard) or a string ending in `*` (prefix glob).
4. On request, `parseACLPolicyWithTemplating` renders the path, then derives `HasSegmentWildcards` / `IsPrefix` from the rendered string with **no sanitization** of `+`/`*`.
5. ACL matching grants the policy capabilities far beyond the intended single segment (any department via `+`; arbitrary child paths via trailing `*`).

### Impact

Privilege escalation within templated ACL scope: read/write/list secrets (and any other capabilities on the rule) outside the intended tenancy/segment.

### Evidence

Templated substitution then wildcard flag derivation (no rejection of `+`/`*` in template output on this commit):

```349:427:vault/policy.go
		if performTemplating {
			_, templated, err := identitytpl.PopulateString(identitytpl.PopulateStringInput{
				Mode:        identitytpl.ACLTemplating,
				String:      key,
				Entity:      identity.ToSDKEntity(entity),
				Groups:      identity.ToSDKGroups(groups),
				NamespaceID: result.namespace.ID,
			})
			if err != nil {
				continue
			}
			key = templated
		}
        // ...
		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}

		if strings.HasSuffix(pc.Path, "*") {
			if !pc.HasSegmentWildcards {
				pc.Path = strings.TrimSuffix(pc.Path, "*")
				pc.IsPrefix = true
			}
		}
```

ACL templating emits metadata/alias strings verbatim:

```54:60:sdk/helper/identitytpl/templating.go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", ErrTemplateValueNotFound
		}
		return t, nil
```

Upstream later rejects `*`/`+` in template results via `ErrTemplatedWildcard` in `sdk/helper/identitytpl/templating.go`; **this commit has no such check**.

**Proof tests** (`go test ./vault/ -run TestACLTemplatedPolicy_ -count=1` → ok):
- `department=+` → `kv/data/+/*` with `HasSegmentWildcards` → read allowed on `kv/data/{engineering,finance,admin}/secret`
- alias name `team-a*` → prefix rule → read allowed on `kv/data/team-a/admin-secret`
- AppRole-style alias metadata `team=+` → segment wildcard across `secret/data/*/...`

### Why not duplicate

Distinct from **CVE-2026-5006** (slash `/` injection only; fixed/gated via `deny_slash_in_templated_paths`). This finding weaponizes ACL **wildcard operators** (`+` segment wildcard and trailing `*` prefix glob), which slash-injection does not create.

---

## Finding 2 — SSH host certificate takeover via `allowed_domains_template` comma injection

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Authenticated user who can sign against an SSH CA role with `allowed_domains_template=true` and who controls the identity value used in `allowed_domains` |
| **Controlled input** | Same identity surfaces as Finding 1 (entity/alias metadata, alias name, JWT claims, K8s annotations, AppRole secret_id metadata) embedded in `allowed_domains` |
| **Primary location** | `builtin/logical/ssh/path_issue_sign.go` |

### Attack path

1. Operator configures an SSH CA host role, e.g.:
   - `allow_host_certificates=true`
   - `allow_subdomains=true`
   - `allowed_domains_template=true`
   - `allowed_domains="{{identity.entity.metadata.ssh_username}}.corp.example.com"`  
   Intent: each team may only mint host certs under `<team>.corp.example.com`.
2. Attacker sets the templated identity field to a comma-containing value such as `corp.example.com,x` or `com,x`.
3. `renderPrincipal` expands the template; `calculateValidPrincipals` then **comma-splits** the rendered string into multiple allowed domains.
4. `validateValidPrincipalForHosts` treats each entry as an `AllowSubdomains` base (`strings.HasSuffix(validPrincipal, "."+allowedPrincipal)`).
5. Attacker requests `valid_principals=prod.corp.example.com` (or any `*.example.com` after TLD injection) and receives a signed **host** certificate for that name.

### Impact

Host principal takeover: mint SSH host certificates for unintended hostnames (parent domain / TLD), enabling SSH host impersonation / MITM against clients that trust the Vault SSH CA.

### Evidence

Host certs share `calculateValidPrincipals` with user certs; domains are split on commas **after** templating; subdomain matching amplifies a single injected parent:

```70:74:builtin/logical/ssh/path_issue_sign.go
	if certificateType == ssh.HostCert {
		parsedPrincipals, err = b.calculateValidPrincipals(data, req, role, "", role.AllowedDomains, role.AllowedDomainsTemplate, validateValidPrincipalForHosts(role))
```

```182:187:builtin/logical/ssh/path_issue_sign.go
	if enableTemplating {
		rendered, err := b.renderPrincipal(principalsAllowedByRole, req)
		// ...
		allowedPrincipals = strutil.RemoveDuplicates(strutil.ParseStringSlice(rendered, ","), false)
```

```215:224:builtin/logical/ssh/path_issue_sign.go
func validateValidPrincipalForHosts(role *sshRole) func([]string, string) bool {
	return func(allowedPrincipals []string, validPrincipal string) bool {
		for _, allowedPrincipal := range allowedPrincipals {
			if allowedPrincipal == validPrincipal && role.AllowBareDomains {
				return true
			}
			if role.AllowSubdomains && strings.HasSuffix(validPrincipal, "."+allowedPrincipal) {
				return true
			}
		}
```

In-tree `TestBackend_MultipleAllowedUsersTemplate` already shows identity metadata may contain commas that expand the allow-list (`testMultiUserName = "vaultssh,otherssh"`).

**Proof tests** (`go test ./builtin/logical/ssh/ -run TestHostDomainsTemplate_ -count=1` → ok):
- Rendered `corp.example.com,x.corp.example.com` + `AllowSubdomains` allows `prod.corp.example.com` (denied under baseline `eng.corp.example.com`)
- Rendered `com,x.example.com` allows arbitrary `*.example.com` host principals

### Why not duplicate

Same comma-split mechanism as the already-covered **`allowed_users_template` comma** issue, but **impact is materially distinct**: user-principal expansion vs **SSH host certificate** issuance. With `AllowSubdomains`, comma injection into domains enables parent-domain/TLD takeover and host impersonation, which the user-cert finding does not cover. (PKI `allowed_domains_template` is **not** affected the same way: domains are a `[]string` templated per-element without post-template comma splitting.)

---

## Candidates evaluated and not reported

| Candidate | Outcome |
| --- | --- |
| **PingID MFA `IDPURL` SSRF** | Confirmed: `settings_file_base64` → `idp_url` → `validatePingID` builds `pingConfig.IDPURL + reqPath` and `DefaultClient().Do` with no URL allow-list (`vault/login_mfa.go`). **Skipped as duplicate class** of already-reported Okta/Duo MFA method-write SSRF: same `identity/mfa/method/<type>` update privilege, no sudo gate (`makeMFAMethodPaths`). |
| **Other novel Medium+ outside skip list** | No additional validated Medium+ E2E paths found in this pass beyond the skip list and the two findings above. Cert CRL `http.Get` is admin-configured URL fetch (prior reviews treat as known OCSP/CRL SSRF class). |

---

## Proof artifacts

- `vault/policy_template_injection_test.go`
- `builtin/logical/ssh/domains_template_injection_test.go`
