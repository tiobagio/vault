# Application Security Review — DB SQLi / SSRF / Exec

**Repo:** `tiobagio/vault`  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`1.18.0-beta1`)  
**Scope:** (1) Database secrets engine SQL injection, (2) SSRF (ACME / auth URL fetches / webhooks / OCSP), (3) shell/exec/path traversal in agent, plugins, physical backends.

**Reporting bar:** Admin-configured SQL statements are intentional capability, not findings, unless a lower-privileged attacker (unauthenticated, auth DisplayName/claim, or ACL-constrained role writer who cannot set statement fields) can inject.

---

## Validated findings

### 1. PKI ACME http-01 / tls-alpn-01 SSRF (CVE-2026-5052) — High

| Field | Value |
| --- | --- |
| **Severity** | High (CVSS 8.6 upstream; network SSRF + internal info disclosure) |
| **Primary location** | `builtin/logical/pki/acme_challenges.go` — `ValidateHTTP01Challenge`, `ValidateTLSALPN01Challenge` |
| **Also** | `builtin/logical/pki/acme_challenge_engine.go`, `path_acme_order.go` (`generateAuthorization`), `acme_wrappers.go` (unauth paths) |
| **Attacker** | Unauthenticated ACME client once ACME is enabled and `eab_policy` is `not-required` (this tree’s `defaultAcmeConfig`); or any holder of an EAB token if EAB is required |
| **Input** | ACME order identifiers (`dns` / `ip`); HTTP-01 redirect `Location`; DNS resolution of challenge hosts |
| **Impact** | Vault originates HTTP/TLS connections to attacker-chosen or attacker-influenced destinations (loopback, RFC1918, link-local/cloud metadata). Error text can act as a reachability oracle. |

#### Attack path

1. Operator enables ACME (`pki/config/acme` `enabled=true`). Default directory policy is `sign-verbatim` with `AllowIPSANs: true`.
2. ACME paths are registered unauthenticated (`acme_wrappers.go`).
3. Attacker creates an account/order for:
   - an **IP identifier** such as `169.254.169.254` / `127.0.0.1` (HTTP-01 only for IPs), or
   - a DNS name they control that resolves (or redirects) to an internal address.
4. Challenge validation calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge`.
5. HTTP client fetches `http://{domain}/.well-known/acme-challenge/{token}` with **no** private/loopback/link-local rejection. `CheckRedirect` only limits count and URL length — internal redirects are followed. TLS-ALPN dials `{domain}:443` with the same dialer.

#### Evidence

```125:170:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via)+1 >= maxRedirects {
				return fmt.Errorf("http-01: too many redirects: %v", len(via)+1)
			}
			reqUrlLen := len(req.URL.String())
			if reqUrlLen > urlLength {
				return fmt.Errorf("http-01: redirect url length too long: %v", reqUrlLen)
			}
			return nil
		},
	}
	resp, err := client.Get(path)
```

```857:859:builtin/logical/pki/path_acme_order.go
	if identifier.Type == ACMEIPIdentifier {
		allowedChallenges = []ACMEChallengeType{ACMEHTTPChallenge}
	}
```

```41:49:builtin/logical/pki/path_config_acme.go
var defaultAcmeConfig = acmeConfigEntry{
	Enabled:                false,
	// ...
	DefaultDirectoryPolicy: "sign-verbatim",
	EabPolicyName:          eabPolicyNotRequired,
```

This tree has **no** `challenge_permitted_ip_ranges` / `challenge_excluded_ip_ranges`. Upstream fixed as **CVE-2026-5052 / HCSEC-2026-06** (CE 2.0.0; Ent 1.21.5 / 1.20.10 / 1.19.16).

**Verdict:** Exploitable when ACME is enabled. Not “intended admin SSRF” — challenge validation is meant to reach the certificate subject’s host, not Vault’s internal network / metadata plane.

---

### 2. Database static-role `username` → default rotation SQL injection (MySQL / Postgres / MSSQL) — High

| Field | Value |
| --- | --- |
| **Severity** | High |
| **CWE** | CWE-89 |
| **Primary locations** | `plugins/database/mysql/mysql.go`, `plugins/database/postgresql/postgresql.go`, `plugins/database/mssql/mssql.go`; substitution in `sdk/database/helper/dbutil/dbutil.go` / `sdk/helper/dbtxn/dbtxn.go`; role write in `builtin/logical/database/path_roles.go`; rotation in `builtin/logical/database/rotation.go` |
| **Attacker** | Authenticated principal with `create`/`update` on `database/static-roles/*` who **cannot** supply custom SQL — e.g. ACL `denied_parameters = ["rotation_statements"]` or `allowed_parameters` limited to `username` / `db_name` / `rotation_period`. Username is an identifier field, not an intentional SQL statement. |
| **Input** | Static-role `username` (`framework.TypeString`, no identifier validation) |
| **Impact** | Arbitrary SQL / password takeover as the Vault DB management principal when default rotation statements are used |

Shared sink: unescaped `strings.ReplaceAll` of `{{username}}` / `{{name}}` / `{{password}}` into statement text, then `ExecContext` on the fully interpolated string.

```21:28:sdk/database/helper/dbutil/dbutil.go
func QueryHelper(tpl string, data map[string]string) string {
	for k, v := range data {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

```77:85:sdk/helper/dbtxn/dbtxn.go
func parseQuery(m map[string]string, tpl string) string {
	// ...
	for k, v := range m {
		tpl = strings.ReplaceAll(tpl, fmt.Sprintf("{{%s}}", k), v)
	}
	return tpl
}
```

Static-role create accepts any username and immediately rotates (`setStaticAccount` → `UpdateUser`):

```555:563:builtin/logical/database/path_roles.go
	username := data.Get("username").(string)
	// ...
	role.StaticAccount.Username = username
```

#### 2a — MySQL (single-statement; no `multiStatements` required)

Default when `rotation_statements` empty:

```26:28:plugins/database/mysql/mysql.go
	defaultMySQLRotateCredentialsSQL = `
		ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';
	`
```

**Payload username:** `victim'@'%' IDENTIFIED BY 'pwned';#`  

**Rendered:**  
`ALTER USER 'victim'@'%' IDENTIFIED BY 'pwned';#'@'%' IDENTIFIED BY '<vault-password>';`  

MySQL applies attacker-chosen password to `victim`; `#...` line-comments the rest. Vault’s rotated secret is never applied. Works with `go-sql-driver/mysql` default `MultiStatements=false`.

#### 2b — PostgreSQL

```30:32:plugins/database/postgresql/postgresql.go
	defaultChangePasswordStatement = `
ALTER ROLE "{{username}}" WITH PASSWORD '{{password}}';
`
```

**Payload username:** `victim" WITH SUPERUSER;--`  

**Rendered:** `ALTER ROLE "victim" WITH SUPERUSER;--" WITH PASSWORD '...';`  

`ExecuteTxQueryDirect` uses `tx.ExecContext` on the interpolated string (simple-query multi-statement batch as the Vault PG role).

#### 2c — MSSQL

```431:433:plugins/database/mssql/mssql.go
const alterLoginSQL = `
ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'
`
```

**Payload username:** `a] WITH PASSWORD = 'x'; <T-SQL>;--`  

Breaks out of `[...]` quoting (no `]` → `]]` escaping; contrast `QuoteName` used elsewhere in the same file for `dropLoginSQL`).

**Why this is not “admin intentional SQL”:** Custom `rotation_statements` *are* intentional. The `username` field is documented as the existing DB account name. Constrained operators who are barred from statement fields can still smuggle SQL through username into **defaults**.

---

### 3. Caller-controlled `DisplayName` → dynamic DB username → SQL interpolation — Medium

| Field | Value |
| --- | --- |
| **Severity** | Medium (High when custom `username_template` embeds unbounded `.DisplayName`) |
| **Primary locations** | `builtin/logical/database/path_creds_create.go` (passes `req.DisplayName`); auth methods that set unsanitized `Auth.DisplayName` (e.g. LDAP/Okta/Radius `login/(?P<username>.+)`); plugin `NewUser` / `UpdateUser` / `DeleteUser` defaults using `QueryHelper` / `parseQuery` |
| **Attacker** | Authenticated principal who can obtain dynamic DB creds (`database/creds/:role`) and who controls auth DisplayName (IdP/LDAP username or JWT/OIDC name claim). Login path does **not** apply `displayNameSanitize` (that regex is only used on token-create `display_name`). |
| **Input** | Characters in `DisplayName` flowing into generated usernames, then into `{{name}}` / `{{username}}` in creation/rotation/revocation SQL |
| **Impact** | SQL injection as the Vault DB management user on create/rotate/revoke for dynamic roles |

#### Attack path

1. Attacker authenticates via LDAP/Okta/Radius (or JWT/OIDC) with a username/claim containing SQL metacharacters (`'`, `"`, `]`, etc.). `LoginCreateToken` only prepends the mount path — no charset sanitize.
2. Attacker reads `database/creds/<role>`. Backend passes `req.DisplayName` into `UsernameConfig`.
3. Plugin `username_template` includes `.DisplayName` (defaults truncate it; **custom templates often do not** — documented pattern; later Vault 2.1.0 sanitizes DisplayName specifically to prevent this class).
4. Generated username is substituted into statements via unescaped `ReplaceAll` → breakout.

```126:128:builtin/logical/database/path_creds_create.go
			UsernameConfig: v5.UsernameMetadata{
				DisplayName: req.DisplayName,
				RoleName:    name,
```

```2016:2016:vault/request_handling.go
	auth.DisplayName = strings.TrimSuffix(source+auth.DisplayName, "-")
```

Default templates truncate DisplayName (Postgres 8 / MySQL 10), which limits payload size after the mount prefix, so **default-only** exploitation is constrained. Custom `username_template` values that reference `.DisplayName` without hashing/strict charset filtering are fully exploitable. Upstream later sanitized “caller-controlled DisplayName before it is used in generated usernames” (Vault CE 2.1.0 / Ent 1.21.10, 1.20.15, 1.19.21).

**Verdict:** Real lower-privilege → DB management SQL path. Distinct from admin-authored `creation_statements`.

---

## Scope areas reviewed — no medium+ validated

### SSRF outside ACME

| Surface | Verdict |
| --- | --- |
| Cert auth CRL fetch (`builtin/credential/cert/backend.go` `fetchCRL`) | Admin-configured CDP URL only |
| Cert auth OCSP (`sdk/helper/ocsp/client.go`) | Fetches cert AIA / admin `ocsp_servers_override`; AIA requires a chain trusted by Vault → not a clean low-priv SSRF without CA-level control |
| AWS/GitHub/Okta auth HTTP clients | Hit configured IdP/AWS/GitHub endpoints; not attacker-chosen URLs on the login path in this tree |
| Webhook/callback fetches | No general webhook outbound fetch sink identified in OSS auth/secrets for this commit |
| PKI OCSP path | Vault **serves** OCSP; does not fetch attacker URLs |

### Shell / exec / path traversal

| Surface | Verdict |
| --- | --- |
| Plugin catalog (`vault/plugincatalog/plugin_catalog.go`) | Rejects `..` in name/command; `EvalSymlinks` confines command under `plugin_directory` |
| Agent `exec` (`command/agent/exec/exec.go`) | Runs operator-configured local command from agent HCL — local trust boundary, not remote injection |
| Physical backends | MSSQL storage validates identifiers (`isInvalidIdentifier`); no remote path-traversal RCE path found in scoped backends |
| DB plugins | No `os/exec` usage |

### DB SQLi false positives / non-findings

| Candidate | Why excluded |
| --- | --- |
| Admin-set `creation_statements` / `rotation_statements` / `root_rotation_statements` | Intentional privileged SQL capability |
| Static-role username SQLi when the same principal can freely set `rotation_statements` | Redundant with intentional statement control (still reportable under constrained ACL — Finding 2) |
| Password interpolation with default Vault password generator charset | Not attacker-controlled |
| Physical MSSQL backend config SQLi (CVE-2023-0620 class) | This tree validates schema/table/database identifiers |

---

## Summary

| # | Finding | Severity | Exploitable? |
| --- | --- | --- | --- |
| 1 | ACME http-01 / tls-alpn-01 SSRF | High | Yes, when ACME enabled (CVE-2026-5052) |
| 2 | Static-role username → default rotation SQLi (MySQL/PG/MSSQL) | High | Yes, for ACL-constrained static-role writers |
| 3 | DisplayName → dynamic username → SQL interpolation | Medium | Yes with attacker-controlled DisplayName + template embedding DisplayName (fully with custom templates; later fixed in 2.1) |
