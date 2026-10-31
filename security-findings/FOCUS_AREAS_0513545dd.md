# AppSec findings — focus areas (Vault 1.18.0-beta1 / 0513545dd)

Skip list (not re-reported): DisplayName→DB username SQLi; ACME HTTP-01 SSRF.

Method: static end-to-end path validation. Only medium+ with a real non-root attacker path.

---

## Finding 1 — SSH CA signs certificates with empty ValidPrincipals (CVE-2024-7594)

| Field | Value |
| --- | --- |
| **Severity** | High |
| **Attacker** | Any principal with `update` on `ssh/sign/<role>` or `ssh/issue/<role>` for a CA role whose `default_user` / `allowed_users` (or host `allowed_domains`) leave principals empty |
| **Input** | Omit `valid_principals` (or pass empty) on sign/issue |
| **Path** | `pathSignIssueCertificateHelper` → `calculateValidPrincipals` returns `nil` when parsed list is empty → `creationBundle.sign()` emits cert with `ValidPrincipals: []` |
| **Impact** | OpenSSH treats empty principals as “any principal”: user cert authenticates as any account the CA is trusted for; host cert matches any hostname |
| **Location** | `builtin/logical/ssh/path_issue_sign.go` |

### Evidence

```193:195:builtin/logical/ssh/path_issue_sign.go
	case len(parsedPrincipals) == 0:
		// There is nothing to process
		return nil, nil
```

```506:512:builtin/logical/ssh/path_issue_sign.go
	certificate := &ssh.Certificate{
		// ...
		ValidPrincipals: b.ValidPrincipals,
```

No `allow_empty_principals` gate exists in this tree (added upstream in 1.17.6+).

---

## Finding 2 — SSH CA `allowed_*_template` comma-split allowlist expansion

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Authenticated user who can sign the role and who controls an identity value referenced by `allowed_users` / `allowed_domains` while `*_template=true` |
| **Input** | Identity field containing `,` (JWT `claim_mappings`, AppRole `secret_id` metadata, alias metadata, etc.), e.g. `alice,root` or `corp.example.com,x` |
| **Path** | `renderPrincipal` → full-string comma split in `calculateValidPrincipals` → membership check against expanded list; host path + `allow_subdomains` treats injected parents as subdomain bases |
| **Impact** | User: mint principals beyond the intended single account (e.g. `root`). Host: parent-domain / TLD takeover for host certificates |
| **Location** | `builtin/logical/ssh/path_issue_sign.go` (`renderPrincipal`, `calculateValidPrincipals`, `validateValidPrincipalForHosts`) |

### Evidence

```182:187:builtin/logical/ssh/path_issue_sign.go
	if enableTemplating {
		rendered, err := b.renderPrincipal(principalsAllowedByRole, req)
		// ...
		allowedPrincipals = strutil.RemoveDuplicates(strutil.ParseStringSlice(rendered, ","), false)
```

```221:223:builtin/logical/ssh/path_issue_sign.go
			if role.AllowSubdomains && strings.HasSuffix(validPrincipal, "."+allowedPrincipal) {
				return true
			}
```

---

## Finding 3 — Cert auth non-CA leaf CN impersonation after CVE-2024-2048 (CVE-2025-6037)

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Holder of a trusted non-CA client cert + private key registered in cert auth |
| **Input** | Forged twin leaf: same serial, AKID, and public key; different Subject CN |
| **Path** | `verifyCredentials` non-CA match (serial+AKID+pubkey only) → login alias `Name` = presented CN → entity takeover |
| **Impact** | Impersonate another cert-auth identity / its policies and group memberships |
| **Location** | `builtin/credential/cert/path_login.go` |

### Evidence

CVE-2024-2048 added the pubkey check; full cert equality is still missing:

```283:308:builtin/credential/cert/path_login.go
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

```167:169:builtin/credential/cert/path_login.go
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
```

---

## Finding 4 — Cert auth renew binding uses SKID/AKID logical AND

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | Holder of a stolen cert-auth token plus any other leaf from the same CA that still satisfies the cert role (`disable_binding` default false) |
| **Input** | Different client cert on `auth/token/renew` / `renew-self` |
| **Path** | `pathLoginRenew` denies only when **both** SKID and AKID differ; same-CA leaf keeps AKID equal → renew succeeds without original key |
| **Impact** | Extend stolen cert-auth token lifetime without the victim private key |
| **Location** | `builtin/credential/cert/path_login.go` |

### Evidence

```213:216:builtin/credential/cert/path_login.go
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Correct binding requires SKID match **and** AKID match (separate checks).

---

## Finding 5 — GitHub auth maps both team Name and Slug into PolicyMap / GroupAliases

| Field | Value |
| --- | --- |
| **Severity** | Medium |
| **Attacker** | GitHub org member of a team whose **display Name** equals another team’s **slug** that is mapped to higher Vault policies (collision via team create / existing naming) |
| **Input** | Org team naming: Team A `Name="Platform Engineering"`, `Slug="platform-engineering"` mapped in Vault; Team B `Name="platform-engineering"` (slug auto-suffixed) |
| **Path** | Login `verifyCredentials` appends both `*t.Name` and `*t.Slug` to `teamNames` → `TeamMap.Policies` / `GroupAliases` |
| **Impact** | Cross-team Vault policy / identity-group escalation without membership in the mapped team |
| **Location** | `builtin/credential/github/path_login.go` |

### Evidence

```266:276:builtin/credential/github/path_login.go
	for _, t := range allTeams {
		if *t.Organization.ID != *org.ID {
			continue
		}
		teamNames = append(teamNames, *t.Name)
		if *t.Name != *t.Slug {
			teamNames = append(teamNames, *t.Slug)
		}
	}
```

Org-ID pinning is present (rename confusion mitigated). This finding is Name↔Slug key aliasing, not org rename.

---

## No validated medium+ in these focus areas

| Area | Result |
| --- | --- |
| **AWS secrets** (privilege beyond role policy) | `role_arn` must be in role allow-list; request cannot supply `policy_document`; session name only. No lesser-priv escalation beyond configured role. |
| **Transit** (decrypt/export/batch authz) | Export/backup require `exportable` / `allow_plaintext_backup`; user nonces rejected unless convergent v1; batch items cannot retarget key name (path-bound). |
| **Token store** (orphan/parent policy bypass) | Non-sudo create still enforces policy subset; `no_parent` requires sudo; `create-orphan` is an intentional separate ACL path; root token creation still requires root parent. No residual bypass validated. |
| **RabbitMQ / Consul / Nomad** | Connection/`address`/`connection_uri` are admin config. Creds paths do not take attacker URLs; DisplayName lands in token/user **names**, not query/SQL. |
| **sys/raw, sys/pprof defaults** | `raw_storage_endpoint` default false; raw paths not registered otherwise; raw is sudo. `unauthenticated_pprof_access` default false; default policy has no `sys/pprof`. |
| **Cross-namespace (OSS)** | CE has only root namespace; no child-NS mount surface to abuse in OSS paths. |
| **X-Forwarded-For without config** | `WrapForwardedForHandler` applied only when `x_forwarded_for_authorized_addrs` is non-empty (`command/server.go`). Empty allow-list → XFF ignored. |
