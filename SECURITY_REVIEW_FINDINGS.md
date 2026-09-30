# Application Security Review — HashiCorp Vault

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Scope:** Path traversal, command injection/RCE, ACL/Go template injection, secrets leakage, UI XSS  
**Criterion:** Only validated medium+ findings with end-to-end attack paths where a lower-privileged authenticated client escalates or affects other tenants.

---

## Finding 1 — ACL policy template segment-wildcard injection via identity metadata

| Field | Detail |
| --- | --- |
| **Severity** | **High** |
| **Location** | `sdk/helper/identitytpl/templating.go` (`aclTemplateHandler`, lines 54–74) |
| **Attacker** | Authenticated client who can set identity values used in templated ACL paths (e.g. AppRole secret-id `metadata`, or LDAP alias names matching `login/(?P<username>.+)`) |
| **Input** | Identity string containing `+` (ACL segment wildcard), e.g. AppRole secret-id metadata `project=+` |
| **Path** | See below |
| **Impact** | Cross-tenant privilege escalation: a policy meant to confine a client to one path segment becomes a segment-wildcard rule matching **all** tenants at that level |

### Attack path

1. Operator deploys a common multi-tenant templated policy:

```hcl
path "secret/data/{{identity.entity.aliases.auth_approle_XXXX.metadata.project}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

2. Attacker with permission to create a secret-id for their role (often delegated to app/CI owners) writes:

```text
vault write auth/approle/role/attacker-role/secret-id metadata=project=+
```

3. On login, AppRole copies secret-id metadata onto `Auth.Alias.Metadata` (`builtin/credential/approle/path_login.go` ~332–376). Identity store persists it (`validateMetadata` only restricts **keys**, not values containing `+` — `vault/identity_store_util.go` 1703–1734).

4. On each request, `PolicyStore.ACL` re-parses templated policies (`vault/policy_store.go` 863–874) via `identitytpl.PopulateString` in `ACLTemplating` mode.

5. `aclTemplateHandler` returns the metadata value **verbatim** with no escaping of `+`, `/`, or `*`:

```54:74:sdk/helper/identitytpl/templating.go
func aclTemplateHandler(v interface{}, keys ...string) (string, error) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", ErrTemplateValueNotFound
		}
		return t, nil
	// ...
```

6. `parsePaths` then treats the rendered path as a segment-wildcard rule (`vault/policy.go` 415–417):

```415:417:vault/policy.go
		if pc.Path == "+" || strings.Count(pc.Path, "/+") > 0 || strings.HasPrefix(pc.Path, "+/") {
			pc.HasSegmentWildcards = true
		}
```

Rendered path: `secret/data/+/*` — matches `secret/data/<any-tenant>/...`.

### Evidence (validated)

Unit PoC against this commit (parse + `NewACL` + `AllowOperation`):

- Templated path became `secret/data/+/*` with `HasSegmentWildcards=true`
- Reads to `secret/data/victim-tenant/creds`, `secret/data/other-org/keys`, `secret/data/prod/database` were **allowed**
- Benign metadata `project=attacker-project` correctly denied cross-tenant paths

### Notes

- Same root cause later addressed in part by HCSEC-2026-32 / CVE-2026-5006 (slash injection) and `deny_slash_in_templated_paths`; **`+` wildcard injection is a distinct, typically more severe escalation** and is not sanitized here.
- LDAP login pattern `login/(?P<username>.+)` also permits `+` / `/` in alias names if such identities exist in the directory.

---

## Finding 2 — ACL policy template slash / path-segment injection via identity metadata

| Field | Detail |
| --- | --- |
| **Severity** | **Medium** |
| **Location** | `sdk/helper/identitytpl/templating.go` (`aclTemplateHandler`, lines 54–74) |
| **Attacker** | Same as Finding 1 (controls templated identity field) |
| **Input** | Identity string containing `/`, e.g. metadata `department=admin/super-secret` |
| **Path** | Same pipeline as Finding 1 |
| **Impact** | Access to unintended deeper (or alternate) Vault paths than the policy author intended for a single path segment |

### Attack path

Policy:

```hcl
path "kv/data/{{identity.entity.aliases.auth_approle_XXXX.metadata.department}}" {
  capabilities = ["read"]
}
```

Attacker sets `metadata=department=admin/super-secret`. Rendered ACL path becomes `kv/data/admin/super-secret`, granting read on that path.

### Evidence (validated)

PoC: templated path rendered as `kv/data/admin/super-secret`; `AllowOperation` for read on that path returned allowed.

This matches the class later disclosed as **CVE-2026-5006 / HCSEC-2026-32**. This commit has **no** `deny_slash_in_templated_paths` mitigation.

---

## Areas reviewed without validated medium+ remote/tenant findings

| Area | Result |
| --- | --- |
| Audit file path config | Requires privileged audit enable; self-configured path is expected |
| Plugin catalog command paths | `..` rejected; symlink escape checked against plugin directory (`plugincatalog/plugin_catalog.go` Set/setInternal) |
| Plugin exec / agent exec | Expected privileged config; argv passed without shell |
| `api/tokenhelper/helper_external.go` | Shell `-c` concatenation is unsafe if BinaryPath has metacharacters, but path comes from **local CLI** config — not a Vault-server tenant escalation |
| `command/ssh.go` | `exec.Command` with separate args; username/ip used in temp filenames / SSH args from local CLI user |
| Transit / SSH / PKI secret engines | No attacker-controlled server-side arbitrary file R/W found in CE paths reviewed |
| Agent/proxy template destinations | Local agent config (operator host), not Vault API tenant input |
| Physical storage backends | Paths from server config |
| `well_known_redirect.Destination` | `url.ResolveReference` allows `../` and absolute remaining paths to rewrite to other `/v1/...` routes (`vault/well_known_redirect.go` 138–166 + `GetWellKnownRedirect`), but **no builtin registers** redirects in this tree; needs a plugin calling `RequestWellKnownRedirect` — not counted as a standalone tenant attack without that prerequisite |
| Secrets in errors/audit | Default audit HMAC; DB connection read redacts URL passwords |
| UI XSS (`ui/app`) | KV diff uses DOMPurify via `sanitized-html`; custom-message body is escaped; custom-message `link.href` lacks scheme allowlisting but requires privileged `sys/config/ui/custom-messages` write — not lower-priv stored XSS |

---

## Summary

Two validated findings share one root cause: **ACL identity templating inserts attacker-influenced strings into policy paths without neutralizing ACL metacharacters (`+`, `/`)**. The highest-impact variant is injecting `+` to obtain segment-wildcard access across tenants when policies template on AppRole (or similarly controllable) metadata.
