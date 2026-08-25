# Application Security Review — Vault @ 0513545dd

**Tree:** HashiCorp Vault OSS (`version/VERSION` = `1.18.0-beta1`)  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-756e`

Scope: injection, SSRF, RCE, path traversal, unsafe deserialization, CORS — only validated medium+ findings with end-to-end attack paths. Admin-only configuration of their own SQL/LDAP/templates is out of scope unless user-controlled data (not admin config) reaches a sink.

---

## Validated findings

### 1. HIGH — PKI ACME http-01 / tls-alpn-01 SSRF (private / loopback / link-local)

**CWE:** CWE-918  
**Later public ID:** CVE-2026-5052 / HCSEC-2026-06 (this tree is unfixed)

#### Attacker

- **Unauthenticated** remote client when ACME is enabled and EAB is not required.
- Default in-memory/storage bootstrap config uses `EabPolicyName: eabPolicyNotRequired` (`path_config_acme.go` `defaultAcmeConfig`). Enabling ACME with only `enabled=true` uses `GetOk("eab_policy")`, so the schema’s documented default `"always-required"` is **not** applied and EAB stays `not-required`.
- With `eab_policy=always-required`, any holder of a valid EAB token.

#### Controlled input

ACME `newOrder` identifiers:

- IP identifiers (`type=ip`), including `127.0.0.1`, RFC1918, link-local, cloud metadata IPs — accepted when the issuing role has `allow_ip_sans` (default **true** for normal roles; always true for `sign-verbatim`).
- DNS identifiers under attacker DNS (or any allowed name) whose A/AAAA points at an internal target, **or** whose HTTP response redirects there.

#### Sink / code path

1. `acmeNewOrderHandler` → `validateIdentifiersAgainstRole` → for IP only checks `role.AllowIPSANs` (no private-IP deny).
2. Challenge engine calls `ValidateHTTP01Challenge` / `ValidateTLSALPN01Challenge` (`builtin/logical/pki/acme_challenges.go`).
3. HTTP-01 builds `http://` + attacker host + `/.well-known/acme-challenge/` + token and `client.Get`s it.
4. Redirects allowed (up to 10); **no** `IsLoopback` / `IsPrivate` / `IsLinkLocal` / metadata filtering.
5. TLS-ALPN dials attacker host:443 with `InsecureSkipVerify: true`.

Default directory policy is `sign-verbatim` (`AllowAnyName` + `AllowIPSANs`), so `/pki/acme/` accepts arbitrary DNS and IP identifiers once ACME is on.

#### Impact

Server-side request forgery from the Vault node to localhost, link-local (e.g. `169.254.169.254`), and internal services. Body is not fully reflected (challenge key-auth check), but connection success/failure and timing provide a network oracle; highest impact when Vault has privileged network adjacency.

#### Evidence anchors

- `builtin/logical/pki/path_config_acme.go` — `defaultAcmeConfig` (`eabPolicyNotRequired`, `sign-verbatim`).
- `builtin/logical/pki/issuing/roles.go` — `SignVerbatimRoleWithOpts` / role field `allow_ip_sans` Default `true`.
- `builtin/logical/pki/acme_challenges.go` — `ValidateHTTP01Challenge` (no destination allowlist).
- `builtin/logical/pki/path_acme_order_test.go` — `127.0.0.1` / `192.168.0.1` accepted against default/sign-verbatim roles.

#### Prerequisites

PKI mount with `config/acme` `enabled=true` and cluster path set. ACME is off by default; impact begins when operators enable it (common).

---

### 2. HIGH — Redshift plugin: SQL injection in default revoke (`terminateloop`)

**CWE:** CWE-89  
**Upstream fix class:** VAULT-43691 (quote literal) — **not present** in this tree.

#### Attacker

Authenticated principal who can read `database/creds/<redshift-role>` and whose token `DisplayName` can contain SQL metacharacters (notably `'`):

- LDAP auth: `login/(?P<username>.+)` accepts arbitrary path usernames; `Auth.DisplayName = username` (`builtin/credential/ldap/path_login.go`), then mount prefix is prepended (`vault/request_handling.go` `LoginCreateToken`).
- Other auth methods that place attacker-influenced strings in `DisplayName` (e.g. JWT `user_claim` via external plugin).

#### Controlled input → sink

1. `pathCredsCreateRead` passes `req.DisplayName` into `UsernameMetadata` (`builtin/logical/database/path_creds_create.go`).
2. Redshift `usernameProducer.Generate` embeds DisplayName (default template truncates to 8 chars; **custom `username_template`** can embed far more).
3. Creation statements typically quote `"{{name}}"` as an identifier, so usernames containing `'` can be created successfully.
4. On lease revoke, `secretCredsRevoke` → `DeleteUser` with empty revocation statements → `defaultDeleteUser`.
5. Vulnerable line (`plugins/database/redshift/redshift.go`):

```go
revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Neighboring `REVOKE`/`DROP USER` correctly use `dbutil.QuoteIdentifier`; this call site does not. Executed via `dbtxn.ExecuteDBQueryDirect` (string exec, not bound parameters).

#### Impact

SQL injection as the Vault Redshift connection user during revoke (often highly privileged): manipulate `terminateloop` argument (session termination of other DB users), and with sufficient username control / multi-statement support, broader DDL/DML.

#### Notes on exploitability

Default template’s 8-char DisplayName window is constrained by the auth mount prefix (e.g. `ldap-` leaves ~3 attacker chars). Practical exploitation is strongest with a short auth mount path and/or a custom `username_template` that includes more of `DisplayName` (supported first-class config). The defect in Vault’s shipped default revoke path is unambiguous.

---

### 3. HIGH — HANA plugin: unsanitized username in default revoke SQL

**CWE:** CWE-89  
**Upstream fix class:** VAULT-43691 (`dbutil.QuoteIdentifier`) — **not present** in this tree.

#### Attacker

Same class as finding 2 (LDAP/JWT-style `DisplayName` + `database/creds/<hana-role>`).

#### Controlled input → sink

1. HANA default username template truncates DisplayName to **32** characters, replaces `-`→`_`, uppercases — **preserves** quotes, spaces, and other SQL tokens (`plugins/database/hana/hana.go` `defaultUserNameTemplate`).
2. Empty revocation statements → `revokeUserDefault`:

```go
fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username)
fmt.Sprintf("DROP USER %s RESTRICT", req.Username)
```

Username is interpolated as a bare identifier with no quoting/validation.

#### Impact

SQL injection / statement breakout as the Vault HANA connection user on revoke (disable/drop unintended users; further statements if the driver accepts batches). 32-character DisplayName window is large enough for realistic payloads after a short mount prefix.

---

### 4. MEDIUM–HIGH — MSSQL plugin: SQL injection in default revoke `dropUserSQL`

**CWE:** CWE-89

#### Attacker

Same DisplayName → dynamic-creds → revoke chain as findings 2–3. Default MSSQL template truncates DisplayName to **20** characters.

#### Sink

`revokeUserDefault` builds per-database drops with (`plugins/database/mssql/mssql.go`):

```go
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
// ...
revokeStmts = append(revokeStmts, fmt.Sprintf(dropUserSQL, dbName.String, username, username))
```

- `N'%s'`: classic string-literal breakout via `'` in username.
- `DROP USER [%s]`: MSSQL bracket identifiers are closed by `]`, so `]` in username breaks quoting.

`dropLoginSQL` correctly uses `QuoteName` with parameters; `dropUserSQL` does not. Contained-DB path also uses parameterized `QuoteName` — only the non-contained mapping loop is affected.

#### Impact

Arbitrary SQL as the Vault MSSQL login during revoke when the dynamic user is mapped into one or more databases (normal after successful create).

---

## Rejected / below-bar candidates

| Candidate | Why rejected |
|-----------|----------------|
| LDAP filter / Go `text/template` in `sdk/helper/ldaputil` | Filters are admin config; username/UserDN passed through `ldap.EscapeFilter`; FuncMap is not attacker-controlled. |
| DB role creation statements / username templates as SSTI | Template **source** is admin config; `DisplayName` is Execute **data**, not re-parsed as template. Limited FuncMap (no `env`/`exec`). |
| QueryHelper `{{password}}` double-substitution via username | Interesting footgun if username contains `{{password}}`, but with default templates + DisplayName sanitization on token create (`[^a-zA-Z0-9-]` → `-`) and LDAP→DB path needing special chars that also survive templates, did not reach clean medium+ unauth/low-priv impact beyond findings 2–4. |
| Agent `exec` / `os/exec` | Local agent config only; not reachable from Vault HTTP API as an untrusted client. |
| `physical/file` path traversal | `validatePath` rejects `..`. |
| Plugin catalog path traversal | Rejects `..` in name/command; symlink checks under plugin directory. |
| Audit file device path | Requires `sys/audit` sudo/admin; intentional privileged file write. |
| Cert auth CRL `http.Get` | Admin writes CRL URL; privileged-config SSRF without authz bypass. |
| JWT/OIDC discovery/JWKS URL | Admin connection config on auth mount (external plugin); same admin-SSRF class. |
| Raft join / identity OIDC discovery endpoints | Join is cluster-operator; identity OIDC **serves** discovery (not client fetch of attacker URL). |
| CORS `allowed_origins=["*"]` | Echoes Origin but **never** sets `Access-Control-Allow-Credentials`; Vault tokens are header-based, not cookie-credential theft via CORS. Configuring `*` is admin choice. |
| YAML/`gob` unsafe decode | Request bodies use JSON/`mapstructure`; no attacker-reachable `yaml.Unmarshal` gadget chain identified. |
| UI static assets traversal | Standard asset serving; no validated breakout. |

---

## Summary

Four validated medium+ issues: one unauthenticated (when ACME enabled) SSRF in PKI ACME challenge validation, and three SQL injections in database secrets plugins’ **default** revoke paths (Redshift, HANA, MSSQL) fed by attacker-influenced `DisplayName` through dynamic credential leases.
