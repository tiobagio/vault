# Application Security Review Candidates — Vault 1.18.0-beta1

Scope: NEW high-value attack surfaces (excludes CVE-2024-9180, PG/MSSQL/HANA/Redshift revoke SQLi, listed known CVEs, ACME SSRF, Azure bound_locations, KVv2 DELETE metadata wipe).

## Entry-point map

| Area | Path | Role |
|------|------|------|
| HTTP API | `http/` | Request plumbing, X-Forwarded-For, size limits, sys routes |
| Core | `vault/` | ACL, tokens, identity, MFA, OIDC provider, plugins, barrier |
| Auth methods | `builtin/credential/{approle,aws,cert,github,ldap,okta,radius,userpass,token}` | Login / identity alias creation |
| Secrets engines | `builtin/logical/{database,pki,ssh,aws,consul,nomad,rabbitmq,transit,totp}` | Credential issuance & lifecycle |
| DB plugins (in-tree) | `plugins/database/{mysql,cassandra,mongodb,influxdb,postgresql,mssql,hana,redshift}` | Create/rotate/revoke DB users |
| DB plugins (module) | `go.mod` → snowflake, elasticsearch, redis, couchbase, mongodbatlas | Same plugin interface |
| Agent/Proxy | `command/agent*`, `command/agentproxyshared/` | Templates, exec, sinks |
| Physical storage | `physical/`, `sdk/physical/file/` | Barrier backends |

---

## Top candidates

### 1. MySQL plugin — username SQLi on revoke/rotate (HIGH)

**Where:** `plugins/database/mysql/mysql.go` (`DeleteUser` ~L170–186; `executePreparedStatementsWithMap` via `dbutil.QueryHelper`)

**Why:** `DeleteUser` does raw `strings.ReplaceAll` of `{{name}}`/`{{username}}` into SQL with **no escaping**. Password rotate / create paths use `dbutil.QueryHelper` the same way. Username can be attacker-influenced via:
- static role `username` (`builtin/logical/database/path_roles.go` `staticAccount.Username`)
- custom `username_template` + `DisplayName` from the calling token (`path_creds_create.go`)

**Attack path:** Actor with `database/static-roles/*` (or ability to mint creds under a permissive username template) sets username containing `'`; on revoke (`RevokeUserOnDelete`) or rotation, breaks out of `DROP USER '{{name}}'@'%'` / `ALTER USER ... IDENTIFIED BY`.

**Read next:** `secret_creds.go` revoke path; `sdk/database/helper/dbutil/dbutil.go` `QueryHelper`; static-role create validation; compare to fixed PG/MSSQL quoting.

---

### 2. Cassandra plugin — CQL injection via QueryHelper (HIGH)

**Where:** `plugins/database/cassandra/cassandra.go` (`NewUser`/`DeleteUser`/`changeUserPassword`)

**Why:** Defaults like `DROP USER '{{username}}';` / `CREATE USER '{{username}}' WITH PASSWORD '{{password}}'` are filled with `dbutil.QueryHelper` (unescaped string replace). Same username control as #1.

**Attack path:** Static-role username or template-derived name with `'`; lease revoke or password rotate executes injected CQL as the configured Cassandra admin.

**Read next:** `connection_producer.go`; role revocation statements; whether gocql treats the full string as one query (multi-statement).

---

### 3. InfluxDB plugin — IFQL injection via QueryHelper (HIGH)

**Where:** `plugins/database/influxdb/influxdb.go` (defaults L20–22; `DeleteUser`/`NewUser`/`changeUserPassword`)

**Why:** Identical `QueryHelper` interpolation into `DROP USER "{{username}}"`, `CREATE USER ... WITH PASSWORD '{{password}}'`. Password field is also unescaped (quote breakout in password rotate).

**Attack path:** Same privilege model as MySQL/Cassandra; revoke or rotate injects IFQL.

**Read next:** `connection_producer.go`; password policy charset (does it allow `'`?).

---

### 4. Snowflake plugin — SQL injection on delete/rotate (HIGH)

**Where:** module `github.com/hashicorp/vault-plugin-database-snowflake@v0.11.0` `snowflake.go` — defaults `drop user if exists {{name}};`, `alter user {{name}} set PASSWORD = '{{password}}';`; `DeleteUser`/`updateUserCredential` via `sdk/helper/dbtxn` `parseQuery` (same ReplaceAll pattern).

**Why:** Sibling of known PG revoke SQLi; no identifier quoting.

**Attack path:** Static username / template → rotate or revoke → arbitrary Snowflake SQL as plugin role.

**Read next:** `sdk/helper/dbtxn/dbtxn.go`; snowflake acceptance tests for malicious usernames.

---

### 5. SSH CA — identity-template principal comma injection (HIGH)

**Where:** `builtin/logical/ssh/path_issue_sign.go` `renderPrincipal` / `calculateValidPrincipals` (~L153–212)

**Why:** When `allowed_users_template` is true, the rendered template string is split on **commas**. Identity template values are not sanitized for commas. AppRole secret-id `metadata` becomes alias metadata on login (`builtin/credential/approle/path_login.go`, `path_role.go` metadata handling).

**Attack path:** Role allows `allowed_users="{{identity.entity.aliases.<accessor>.metadata.user}}"` + templating. Attacker creates secret-id with `metadata=user=alice,root` (or similar). Login updates alias metadata. Sign request for `valid_principals=root` succeeds → SSH principal escalation.

**Read next:** `sdk/framework/identity.go`; `sdk/helper/identitytpl/templating.go` (ACL mode escaping); AppRole metadata → alias persistence; same pattern for `allowed_domains_template` / extensions.

---

### 6. Cert auth OCSP — SSRF via client certificate OCSP URLs (HIGH)

**Where:** `sdk/helper/ocsp/client.go` `GetRevocationStatus` (~L527–560); called from `builtin/credential/cert/path_login.go` `checkForCertInOCSP`

**Why:** With OCSP enabled and no `ocsp_servers_override`, Vault HTTP-GETs **`subject.OCSPServer` from the presented leaf**. No private/link-local allowlist. Transport is `newInsecureOcspTransport` (custom roots, still reaches arbitrary hosts). `QueryAllServers` fans out.

**Attack path:** Auth method with OCSP on; attacker presents a chain Vault trusts whose leaf OCSP URI points at cloud metadata / internal HTTP. Triggered on every login (not only admin CRL config). Distinct from excluded ACME SSRF.

**Read next:** `VerifyLeafCertificate`; fail-open behavior (`OcspFailOpen`); whether PKI-issued certs embed attacker-influenced OCSP URIs; CRL `fetchCRL` admin SSRF (`credential/cert/backend.go` L152) as secondary.

---

### 7. MFA Duo/Okta username format confusion (MEDIUM–HIGH)

**Where:** `vault/login_mfa.go` `formatUsername` (~L1800–1814); `validateDuo` uses formatted username for Preauth/Auth

**Why:** Format substitutes `{{alias.name}}`, `{{entity.name}}`, and **all** alias/entity metadata keys with raw `strings.ReplaceAll` (no escaping). Alias metadata can come from AppRole secret-id metadata.

**Attack path:** `username_format` includes `{{alias.metadata.*}}`; attacker sets metadata so Duo/Okta challenge targets a different enrolled user (or confusing identity), potentially weakening MFA binding.

**Read next:** Okta/PingID paths in same file; enforcement matching; whether empty/malformed usernames short-circuit to allow.

---

### 8. Cert CRL URL + PingID IDP URL — admin-triggered SSRF (MEDIUM–HIGH)

**Where:**
- `builtin/credential/cert/path_crls.go` + `backend.go` `fetchCRL` — `http.Get(crl.CDP.Url)` with only `url.Parse` validation
- `vault/login_mfa.go` `validatePingID` — `url.Parse(pingConfig.IDPURL + reqPath)` then `client.Do`

**Why:** No egress controls / block of link-local/metadata. Refresh of expired CRLs re-fetches periodically.

**Attack path:** Privileged config write → Vault server reaches attacker-chosen URL (metadata SSRF, internal scan). Same class as GitHub `base_url`, Elasticsearch plugin `url`, AWS `sts_endpoint` (admin).

**Read next:** `credential/github/path_config.go`; ES `buildClient` in vault-plugin-database-elasticsearch; AWS `submitCallerIdentityRequest` note about endpoint override.

---

### 9. AWS IAM auth — Host header vs STS endpoint split (MEDIUM–HIGH)

**Where:** `builtin/credential/aws/path_login.go` `buildHttpRequest` (~L1702–1745), `submitCallerIdentityRequest`

**Why:** Request URL is built from **admin** `sts_endpoint`, but `request.Host` is taken from **client** `iam_request_url`. Designed for proxying; misconfigured/malicious STS endpoint + client Host can yield confusing signature validation or SSRF-adjacent behavior. `validateLoginIamRequestUrl` only checks Action/query shape, not host allowlist against endpoint.

**Attack path:** Review whether a client can force Vault to talk to an unexpected host while preserving a valid GetCallerIdentity signature story; renew checks around `canonical_arn` wildcards (~L1200+).

**Read next:** `validateVaultHeaderValue`; `allowed_sts_header_values`; EC2 PKCS7 path separately.

---

### 10. Plugin catalog — Env / Args on registered plugins (MEDIUM)

**Where:** `vault/plugincatalog/plugin_catalog.go` `Set`/`setInternal`; `sdk/helper/pluginutil/run_config.go` (Env layered onto process); `runner.go` `Env`/`Args`

**Why:** `..` blocked in Command/Name, and symlink escape checked — but **Env and Args are largely unconstrained**. Admin registering a plugin can inject `LD_PRELOAD`, `PATH`, etc. into the plugin process Vault execs (especially legacy env layering with `os.Environ()`).

**Attack path:** Compromised plugin-admin capability → code exec in plugin/host context beyond “run this binary.” Review container OCI runtime path too (`plugin_runtime_catalog.go`).

**Read next:** `run_config.go` SkipHostEnv / legacy layering; SHA256 verification enforcement on every start.

---

### 11. Database dynamic username via DisplayName (MEDIUM–HIGH, amplifies 1–4)

**Where:** `builtin/logical/database/path_creds_create.go` passes `req.DisplayName` into `UsernameConfig`; plugins feed templates then revoke with same string.

**Why:** DisplayName often tracks auth alias/username. Custom `username_template` like `{{.DisplayName}}` (or partial) without charset restrictions puts user-controlled bytes into unescaped SQL/CQL/IFQL on create **and** later lease revoke.

**Attack path:** Low-priv token user with weird username/display name + admin-configured unsafe template → injection at revoke time (often automated).

**Read next:** Default templates (truncate/random) vs production custom templates; password policies allowing quotes.

---

### 12. Redis ACL rule JSON + static username edge cases (MEDIUM)

**Where:** `vault-plugin-database-redis@v0.3.0` `redis.go` `newUser` — ACL args = `SETUSER`, username, password, then JSON-unmarshaled creation statement strings.

**Why:** Redis protocol keeps args separate (weaker classic injection), but creation-statement ACL tokens are powerful (`allcommands`, `on`, key patterns). Static-role usernames and password rotation (`RESETPASS`, `>`+password) deserve review for odd ACL parsing / overwrite of other users.

**Read next:** Whether static roles / custom usernames are supported; `ACL DELUSER` on revoke.

---

## Suggested verification order

1. PoC MySQL static-role username `' ; DROP ...` on revoke/rotate  
2. Repeat for Cassandra / Influx / Snowflake  
3. SSH templating + AppRole metadata comma principal  
4. Cert login OCSP URL pointing at local listener / metadata mock  
5. MFA username_format + alias metadata  
6. AWS Host/endpoint matrix tests  

## Explicitly out of scope (already covered / dropped)

CVE-2024-9180 identity MemDB; PG/MSSQL revoke SQLi; HANA/Redshift revoke SQLi; ACME SSRF; Azure bound_locations; KVv2 DELETE metadata; CVE list in task prompt.
