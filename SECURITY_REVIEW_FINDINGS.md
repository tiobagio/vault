# Application Security Review — HashiCorp Vault (`tiobagio/vault`)

**Commit:** `0513545dd` (matches `main`)  
**Version:** `1.18.0-beta1`  
**Method:** Static end-to-end tracing of attacker-controlled inputs through HTTP → authz → backends/plugins. Focus on concrete medium+ paths, not generic Vault design.

---

## 1. Top-level structure (relevant packages)

| Path | Role |
|------|------|
| `http/` | HTTP mux (`handler.go`), unauthenticated sys endpoints (init/unseal/health/raft), logical request builder, forwarding |
| `api/` | Client SDK + auth helpers (not the server trust boundary) |
| `vault/` | Core: `CheckToken` / ACL, identity store, MFA, system backend, plugin catalog, audit enablement, request handling |
| `builtin/credential/` | Auth methods (token, userpass, approle, ldap, aws, cert, okta, github, radius) |
| `builtin/logical/` | Secrets engines (pki/ACME, ssh, database, transit, aws, …) |
| `command/` | CLI, server, agent/proxy (local exec/env templating) |
| `helper/` | Shared helpers (forwarding, namespaces, plugins registry) |
| `internal/` | Observability events only (thin) |
| `plugins/database/` | DB secrets plugins (SQLi surface) |
| `sdk/` | Framework, logical types, `pluginutil` (go-plugin RPC), LDAP/DB helpers |

---

## 2. AuthN / AuthZ entry points (high level)

- **Token + ACL:** `vault/request_handling.go` → `CheckToken` → `fetchACLTokenEntryAndEntity` → `performPolicyChecks` / `ACL.AllowOperation`.
- **Unauthenticated HTTP (no token required):** registered in `http/handler.go` — `/v1/sys/init`, `seal-status`, `unseal`, `leader`, `health`, `generate-root/*`, `rekey/*`, `storage/raft/bootstrap|join`, `internal/ui/feature-flags`; optional unauth metrics/pprof/in-flight via listener config.
- **Unauthenticated logical paths:** backends declare `PathsSpecial.Unauthenticated` (login paths, ACME directory/challenge, etc.); core treats matching paths as unauth (`HandleRequest` → `CheckToken(..., true)`).
- **Root-restricted paths:** `PathsSpecial.Root` + root ACL short-circuit (`vault/acl.go`).

---

## 3. Prioritized candidate findings

### F1 — Identity entity/group `ROOT` policy → root ACL (CVE-2025-5999) — **HIGH**

| | |
|---|---|
| **Where** | `vault/identity_store_entities.go` (`handleEntityUpdateCommon`), `vault/identity_store_groups.go` |
| **Attacker** | Non-root token with write on root-namespace identity APIs |
| **Needs** | Ability to write entity/group `policies`; a live token already bound to that entity (or member of that group) |
| **Why exploitable** | Write path only rejects exact `"root"`; `"ROOT"` / `"Root"` persist. Request-time `SanitizePolicies` lowercases → built-in root ACL |

```355:363:vault/identity_store_entities.go
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

```249:257:vault/identity_store_groups.go
	policiesRaw, ok := d.GetOk("policies")
	if ok {
		group.Policies = strutil.RemoveDuplicatesStable(policiesRaw.([]string), true)
	}

	if strutil.StrListContains(group.Policies, "root") {
		return logical.ErrorResponse("policies cannot contain root"), nil
	}
```

```51:64:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	// ...
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		if policies[i] == "root" {
			policies = []string{"root"}
```

**E2E:** login (normal policies) → `POST /v1/identity/entity` with `"policies":["ROOT"]` on that entity → subsequent requests as that token get `a.root = true`.

---

### F2 — Redshift default revoke SQL injection — **HIGH**

| | |
|---|---|
| **Where** | `plugins/database/redshift/redshift.go` (`DeleteUser` / default revoke) |
| **Attacker** | Principal who can mint Redshift dynamic creds whose `DisplayName` can contain `'` (e.g. LDAP `login/(?P<username>.+)`) |
| **Needs** | Database secrets role on Redshift with **empty** `revocation_statements` (default path) |
| **Why** | Username from DisplayName is interpolated into `call terminateloop('%s')` without quoting; executed via `ExecuteDBQueryDirect` |

```451:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Adjacent revoke statements use `QuoteIdentifier`; this call does not. Default username template truncates DisplayName to 8 chars but still preserves `'`.

---

### F3 — HANA default revoke SQL injection — **HIGH**

| | |
|---|---|
| **Where** | `plugins/database/hana/hana.go` (`revokeUserDefault`) |
| **Attacker / needs** | Same class as F2 against a HANA-backed role with empty custom revoke statements |
| **Why** | `ALTER USER %s` / `DROP USER %s` use raw `req.Username`; create-time sanitization only replaces `-` and uppercases |

```348:359:plugins/database/hana/hana.go
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

---

### F4 — MSSQL default DeleteUser SQL injection — **HIGH**

| | |
|---|---|
| **Where** | `plugins/database/mssql/mssql.go` (`revokeUserDefault` + `dropUserSQL`) |
| **Attacker** | (A) Creds reader with quote-bearing DisplayName, or (B) actor who can create a SQL Server DB whose name breaks `USE [%s]` (confused deputy) |
| **Needs** | Dynamic MSSQL role with empty `revocation_statements` |
| **Why** | `fmt.Sprintf(dropUserSQL, dbName, username, username)` → raw batch via `ExecuteDBQueryDirect`. Login drop path correctly uses `QuoteName`; user-drop path does not |

```301:301:plugins/database/mssql/mssql.go
		revokeStmts = append(revokeStmts, fmt.Sprintf(dropUserSQL, dbName.String, username, username))
```

```412:421:plugins/database/mssql/mssql.go
const dropUserSQL = `
USE [%s]
IF EXISTS
  (SELECT name
   FROM sys.database_principals
   WHERE name = N'%s')
BEGIN
  DROP USER [%s]
END
`
```

---

### F5 — AWS auth IAM/EC2 client cache missing AccountID (CVE-2025-11621) — **HIGH**

| | |
|---|---|
| **Where** | `builtin/credential/aws/client.go` (`clientIAM`, `clientEC2`), maps in `backend.go` |
| **Attacker** | AWS principal in a **different** account that can still satisfy login (wildcard / name-colliding `bound_iam_principal_arn`) |
| **Needs** | Multi-account AWS auth config using STS roles; cache populated for same `(region, stsRole)` under a different account |
| **Why** | Clients cached by `region` + `stsRole` only — AccountID not in key → wrong-account client reused for ARN/instance checks |

```227:231:builtin/credential/aws/client.go
	if b.EC2ClientsMap[region] != nil && b.EC2ClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		return b.EC2ClientsMap[region][stsRole], nil
	}
```

```284:289:builtin/credential/aws/client.go
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		return b.IAMClientsMap[region][stsRole], nil
	}
```

Login path is unauthenticated (`auth/aws/login`).

---

### F6 — SSH CA empty `valid_principals` → any-user cert (CVE-2024-7594) — **HIGH**

| | |
|---|---|
| **Where** | `builtin/logical/ssh/path_issue_sign.go` (`calculateValidPrincipals`) |
| **Attacker** | Principal with `create`/`update` on `ssh/sign/<role>` (or issue) |
| **Needs** | CA role with `allow_user_certificates`, empty `default_user`, and empty/omitted request `valid_principals`; **no** `allow_empty_principals` gate in this tree |
| **Why** | Empty principal list returns success; OpenSSH treats empty `ValidPrincipals` as valid for any username |

```192:196:builtin/logical/ssh/path_issue_sign.go
	case len(parsedPrincipals) == 0:
		// There is nothing to process
		return nil, nil
```

Repo search: no `AllowEmptyPrincipals` / `allow_empty_principals` on this commit.

---

### F7 — PKI ACME http-01 / tls-alpn-01 SSRF (CVE-2026-5052) — **MEDIUM** (High confidentiality if Vault reaches metadata/admin ports)

| | |
|---|---|
| **Where** | `builtin/logical/pki/acme_challenges.go`; unauth registration in `acme_wrappers.go` |
| **Attacker** | Unauthenticated ACME client once ACME is enabled (default `eab_policy=not-required`) |
| **Needs** | `pki/config/acme` `enabled=true`; attacker-controlled DNS/IP identifier and/or HTTP redirect |
| **Why** | Challenge client dials resolved host with **no** private/loopback/link-local filter; redirects only limited by count/length; TLS uses `InsecureSkipVerify: true` |

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(...) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// count + URL length only
			return nil
		},
	}
	resp, err := client.Get(path)
```

```41:49:builtin/logical/pki/path_config_acme.go
var defaultAcmeConfig = acmeConfigEntry{
	Enabled:       false,
	EabPolicyName: eabPolicyNotRequired,
```

---

### F8 — Cert auth non-CA leaf CN impersonation (CVE-2025-6037) — **MEDIUM**

| | |
|---|---|
| **Where** | `builtin/credential/cert/path_login.go` |
| **Attacker** | Holder of a registered **non-CA** client cert **and** its private key |
| **Needs** | Non-CA leaf registered under `auth/cert/certs/:name`; empty `allowed_common_names` (default allow-all) |
| **Why** | Trust match is serial + AKID + pubkey only; alias uses **presented** CN → impersonate other CN-mapped identities |

```279:308:builtin/credential/cert/path_login.go
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

```160:169:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

---

### F9 — PostgreSQL default revoke unquoted schema (CVE-2026-39946 class) — **MEDIUM**

| | |
|---|---|
| **Where** | `plugins/database/postgresql/postgresql.go` |
| **Attacker** | Actor who can create a schema name with SQL metacharacters on a Vault-managed DB (confused deputy), or influence schema listing used at revoke |
| **Needs** | Postgres dynamic role using default revoke path |
| **Why** | One revoke statement interpolates `schema` **without** `QuoteIdentifier` while the next statement correctly quotes it |

```445:453:plugins/database/postgresql/postgresql.go
		revocationStmts = append(revocationStmts, fmt.Sprintf(
			`REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %s FROM %s;`,
			(schema),
			dbutil.QuoteIdentifier(username)))

		revocationStmts = append(revocationStmts, fmt.Sprintf(
			`REVOKE USAGE ON SCHEMA %s FROM %s;`,
			dbutil.QuoteIdentifier(schema),
			dbutil.QuoteIdentifier(username)))
```

---

## 4. Dangerous-pattern scan notes (non-findings / lower signal)

| Pattern | Result |
|---------|--------|
| `exec.Command` | Plugin runner (`sdk/helper/pluginutil`), agent exec (admin config), CLI `ssh` — no new remote argv-injection sink beyond known plugin-admin trust |
| Hardcoded credentials | Only test fixtures |
| `InsecureSkipVerify` | Mostly admin/CLI/opt-in; **exception:** ACME challenge transport (F7) |
| LDAP filters | User/group values escaped via `ldap.EscapeFilter`; filter **templates** are admin-configured |
| Raw SQL concat | High-signal instances are F2–F4/F9; admin-authored `creation_statements` are intentional privileged SQL templates |
| Plugin catalog | Rejects `..` in name/command; binds binaries under plugin directory; go-plugin `SecureConfig` checksum when not containerized |
| Raft join/bootstrap | Intentionally unauthenticated cluster bootstrap — by design when storage not yet joined |

---

## 5. Plugin / RPC / webhook boundaries

- **Plugin RPC:** `sdk/helper/pluginutil` launches via `go-plugin` with handshake + TLS/AutoMTLS; external plugins declare `PathsSpecial.Unauthenticated` / `Root` over gRPC (`sdk/plugin/grpc_backend_*`) — a malicious registered plugin can expand unauth surface (requires plugin-catalog write + SHA256 registration privilege).
- **Database plugins:** username/password substituted with `QueryHelper` / `dbtxn.parseQuery` (string replace of `{{name}}` etc.) — privilege model assumes trusted statement authors; F2–F4 break that for **default** revoke paths fed by login DisplayName.
- **Callbacks / outbound HTTP:** ACME challenges (F7); cert CRL `http.Get(crl.CDP.Url)` (admin-configured only); MFA Okta/Duo/PingID use admin-configured endpoints (`vault/login_mfa.go`); OIDC provider validates `redirect_uri` against registered client list.
- **Agent exec:** `command/agent/exec` runs admin-configured command with rendered env — local host trust model, not remote Vault API RCE.

---

## 6. Fork-specific observations

- Checkout `main` / this branch tip is **HashiCorp Vault OSS 1.18.0-beta1** content; no intentional backdoor/hardcoded auth bypass found in the tip tree.
- Separate branch `origin/cursor/shamir-tools-api-d782` adds `sys/tools/shamir` split/combine (operator-gated like hash/random tools) — **not present** on `0513545dd`. Not scored as a vulnerability in this review tree.
- Prior Cursor AppSec branches exist with overlapping CVE validations; findings above were re-verified against this tree’s source.

---

## Remediation pointers (upstream)

| Finding | Upstream |
|---------|----------|
| F1 | CVE-2025-5999 / HCSEC-2025-13 (normalize before root deny) |
| F5 | CVE-2025-11621 / HCSEC-2025-30 (accountID in client cache key) |
| F6 | CVE-2024-7594 / HCSEC-2024-20 (`allow_empty_principals`) |
| F7 | CVE-2026-5052 / HCSEC-2026-06 (challenge IP allow/deny) |
| F8 | CVE-2025-6037 / HCSEC-2025-18 (full leaf equality / CN pin) |
| F2–F4, F9 | Quote identifiers/literals on all default revoke paths (e.g. VAULT-43691 class) |
