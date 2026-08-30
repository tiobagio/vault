# Application Security Review — AUTH / MFA / IDENTITY

**Target:** HashiCorp Vault `@0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Scope:** AUTH / MFA / IDENTITY (JWT/OIDC, K8s, GCP/OCI/AliCloud/Kerberos, tokens, identity, MFA beyond Duo/TOTP, policy templating, header/cert forwarding)  
**Method:** Code-path tracing with concrete attacker/input/reachability/impact; known issues from the skip list were not re-reported.

## Findings

### 1. Medium — ACL privilege escalation via `+` / `*` injection in identity-templated policy paths

**Severity:** Medium (authenticated privilege escalation within templated ACL scope)  
**CWE:** CWE-94 / CWE-639 (authorization bypass via attacker-controlled key material in policy paths)  
**Related but distinct from:** CVE-2026-5006 (slash `/` injection only). Upstream later added unconditional rejection of `*`/`+` in rendered templates (`ErrTemplatedWildcard`); **this commit has no such check**.

#### Attack path

1. Operator publishes a templated ACL that scopes access by an identity value the principal can influence, e.g.:
   ```hcl
   path "kv/data/{{identity.entity.metadata.department}}/*" {
     capabilities = ["read"]
   }
   ```
   or `{{identity.entity.aliases.<accessor>.name}}` / `custom_metadata.*` / JWT `claim_mappings` targets.
2. Attacker authenticates through an auth method that places attacker-influenced data into that identity field, for example:
   - JWT/OIDC `user_claim` / `claim_mappings` from a user-editable IdP claim
   - Kubernetes `use_annotations_as_alias_metadata` annotations (`vault.hashicorp.com/alias-metadata-*`)
   - Entity/alias metadata the principal can write
3. Attacker sets the value to `+` (or a string ending in `*`).
4. On policy render, Vault treats the result as a segment wildcard / prefix glob and grants capabilities far beyond the intended single segment.

#### Evidence

Templated paths are substituted **after** HCL parse, then wildcard flags are derived from the rendered string with **no sanitization** of `+`/`*`:

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

ACL templating returns metadata/alias values verbatim (`sdk/helper/identitytpl/templating.go` `aclTemplateHandler`).

**Proof:** `vault/policy_template_injection_test.go`
- `department=+` → path `kv/data/+/*` with `HasSegmentWildcards` → read allowed on `kv/data/{engineering,finance,admin}/secret`
- alias name `team-a*` → prefix rule → read allowed on `kv/data/team-a/admin-secret`

```text
go test ./vault/ -run TestACLTemplatedPolicy_ -count=1
ok
```

#### Impact

Any principal who can influence a templated identity field used in ACL paths can broaden path matching (all departments via `+`, or arbitrary prefix via trailing `*`), reading/writing secrets outside their intended tenancy.

#### Notes

- Slash-only injection at this commit is **CVE-2026-5006** (not reported as new).
- Duo Trusted Networks, LDAP `username_as_alias` MFA bypass, TOTP whitespace, etc. were skipped per the known-issue list.

## Areas reviewed without new medium+ findings

JWT/OIDC bound claims & JWKS (admin SSRF only), Kubernetes TokenReview/alias metadata reserved-key checks, GCP/OCI/AliCloud/Kerberos/CF login constraints, Okta Verify & PingID MFA username formatting (no new bypass beyond known dual-ID/Duo IP issues), token store batch/orphan/wrapping, forwarded client-cert header handling (depends on trusted-proxy misconfiguration), identity merge conflict handling.
