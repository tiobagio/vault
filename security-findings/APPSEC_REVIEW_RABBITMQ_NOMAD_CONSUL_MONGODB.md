# Application Security Review — RabbitMQ / Nomad / Consul / MongoDB

**Tree:** HashiCorp Vault OSS @ `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Branch:** `cursor/application-security-review-56b2`

## Scope

Deep review of credential-generation and related paths for **new validated medium+** findings with full attack paths:

1. `builtin/logical/rabbitmq/`
2. `builtin/logical/nomad/`
3. `builtin/logical/consul/`
4. `plugins/database/mongodb/`
5. Shared username helpers: `sdk/helper/template`, `sdk/database/helper/credsutil`

Focus: injection via DisplayName / role name / username templates reachable by non-admins; AuthZ gaps; path traversal / SSRF from role-level config writable by non-admins; dangerous defaults.

**Excluded (per brief):** DisplayName SQLi already reported for MySQL/HANA/MSSQL/etc.; admin-only connection URL SSRF; issues requiring database/config or roles write (mount admin) unless a lower-priv path exists; DoS-only.

---

## Verdict

**0 validated medium+ vulnerabilities** with a defendable non-excluded end-to-end attack path in this scope.

---

## What was traced

### 1. RabbitMQ (`builtin/logical/rabbitmq/`)

| Path | Attacker surface | Sink | Outcome |
|------|------------------|------|---------|
| `creds/:name` → `pathCredsRead` | Non-admin with `read` on creds; `req.DisplayName` + role name into username template | `client.PutUser` / `UpdatePermissionsIn` / `UpdateTopicPermissionsIn` | No medium+ |
| `roles/:name` | Mount-admin write | Tags, vhosts, topic ACLs | Admin-only (excluded) |
| `config/connection` | Mount-admin write | URI / username_template / password_policy | Admin-only SSRF/template (excluded) |

**Call chain (creds):**  
`pathCredsRead` (`path_role_create.go:48`) → template generate with `UsernameMetadata{DisplayName, RoleName}` (`:78–86`) → `PutUser(username, …)` (`:103`) → rabbit-hole `users/"+url.PathEscape(username)` (`users.go:143`).

**Checked:**

- Default template ``{{ printf "%s-%s" (.DisplayName) (uuid) }}`` (`path_role_create.go:18`) embeds unsanitized DisplayName (LDAP/Okta/JWT can carry rich characters via auth `DisplayName`). Path traversal / HTTP injection blocked by `url.PathEscape` on username and vhost segments in rabbit-hole. UUID suffix prevents predictable overwrite of fixed users (e.g. `guest`).
- Tags come only from role storage (`role.Tags`), not from DisplayName; JSON-marshaled via rabbit-hole `UserTags`.
- No `PathsSpecial.Unauthenticated`; SealWrap only on `config/connection`.
- Config has Update only (no read of password over API).

### 2. Nomad (`builtin/logical/nomad/`)

| Path | Attacker surface | Sink | Outcome |
|------|------------------|------|---------|
| `creds/:name` → `pathTokenRead` | Non-admin creds read; DisplayName in token **Name** only | `ACLTokens().Create` | No medium+ |
| `role/:name` | Mount-admin | Token type / policies / global | Admin-only |
| `config/access` | Mount-admin | Address / token / TLS / bootstrap | Admin-only SSRF (excluded) |

**Call chain:**  
`pathTokenRead` (`path_creds_create.go:43`) → `tokenName := fmt.Sprintf("vault-%s-%s-%d", name, req.DisplayName, …)` (`:76`) → `Create(&api.ACLToken{Name, Type: role.TokenType, Policies: role.Policies, Global})` (`:86–91`).

**Checked:**

- DisplayName only affects Nomad token **name** (metadata), not Type/Policies/Global (those are role-admin).
- Name truncation (`:81–83`) can weaken randomness of the nano suffix when names are long — availability/collision hygiene, not privilege gain.
- Revoke uses `accessor_id` from InternalData only (`secret_token.go:58–66`).
- Config read omits token and client_key.

### 3. Consul (`builtin/logical/consul/`)

| Path | Attacker surface | Sink | Outcome |
|------|------------------|------|---------|
| `creds/:role` → `pathTokenRead` | Non-admin creds read; DisplayName in Description/Name | `ACL().Create` / `TokenCreate` | No medium+ |
| `roles/:name` | Mount-admin | Policy, policies, roles, SIs, namespace, partition | Admin-only |
| `config/access` | Mount-admin | Address / scheme / token / TLS | Admin-only SSRF (excluded) |

**Call chain:**  
`pathTokenRead` (`path_token.go:44`) → `tokenName := fmt.Sprintf("Vault %s %s %d", role, req.DisplayName, …)` (`:73`) → either legacy `ACL().Create` (Name/Type/Rules from role) (`:81–85`) or `TokenCreate` (Policies/Roles/SIs/Namespace/Partition from role) (`:120–129`).

**Checked:**

- DisplayName only in Description/Name; ACL privileges entirely from role config.
- `parseServiceIdentities` / `parseNodeIdentities` (`:152–181`) only consume admin-configured role fields.
- Revoke (`secret_token.go:63–120`) uses accessor/token from InternalData; namespace/partition from **lease Data** (issued secret payload), not caller-controlled revoke input (`expiration.go` → `RevokeRequest(le.Path, le.Secret, le.Data)`). Mis-storing namespace in Data vs InternalData is a cleanup correctness footnote, not a low-priv escalation.
- Config read returns address/scheme only (no token).

### 4. MongoDB plugin (`plugins/database/mongodb/`)

| Op | Non-admin reach | Sink | Outcome |
|----|-----------------|------|---------|
| `NewUser` via DB engine `creds/:name` | DisplayName + RoleName → username template | BSON `createUser` | No medium+ |
| `UpdateUser` / rotate-root / static rotate | Username from config or prior InternalData | BSON `updateUser` | Admin or lease-system |
| `DeleteUser` | Username from lease InternalData | BSON `dropUser` | No injection |

**Call chain (dynamic creds):**  
DB engine `pathCredsCreateRead` (`builtin/logical/database/path_creds_create.go:125–128`) passes `req.DisplayName` → plugin `NewUser` (`mongodb.go:115`) → `usernameProducer.Generate` (`:120`) → `createUserCommand` BSON (`util.go:8–12`) → `RunCommand` (`mongodb.go:251`).

**Checked:**

- Default template truncates DisplayName/RoleName, replaces `.`, adds `random` + `unix_time` (`mongodb.go:27`) — no SQL-style string concat; structured BSON fields only.
- Creation `db` / `roles` come from role `creation_statements` (role write = mount admin; excluded).
- `connection_url` / `username_template` set at Initialize (config write; excluded). `QueryHelper` only substitutes admin root `{{username}}`/`{{password}}` into connection URL (`connection_producer.go:153–158`).
- `changeUserPassword` targets DB from connection string (`:165–188`); mismatch vs creation DB is operational, not a low-priv attack.
- MongoDB does not implement statement templating with `{{name}}` concatenation (unlike excluded SQL plugins).

### 5. Shared username helpers

| Component | Role | Outcome |
|-----------|------|---------|
| `sdk/helper/template` | FuncMap: random, truncate, replace, sha256, base64, time, uuid — **no** `env`/`call`/exec | No RCE via admin templates |
| `sdk/database/helper/credsutil` | `GenerateUsername` truncates DisplayName/RoleName; no char denylist | Used by legacy SQL producers; MongoDB/RabbitMQ use `sdk/helper/template` instead. SQL injection via this helper is the **excluded** DisplayName-SQLi class |
| Username metadata | Only `DisplayName` + `RoleName` — **no** entity metadata map | No entity-metadata template injection on these engines |

Auth DisplayName sources that can be attacker-influenced (after successful login): LDAP/Okta (`.+` username), JWT (`user_claim`), AWS assumed-role (`FriendlyName/SessionInfo`), etc. For these four engines that value only hits: RabbitMQ username (PathEscaped + uuid), Nomad/Consul token labels, MongoDB BSON username (templated/sanitized by default).

Role path segments use `framework.GenericNameRegex` (`\w` / `.` / `-` only) → no storage key traversal via `role/`+name or `policy/`+name.

---

## Near-misses (below bar / excluded)

1. **RabbitMQ default template does not truncate/sanitize DisplayName** (unlike MongoDB). Mitigated by PathEscape + uuid; overwrite of privileged RabbitMQ users not achievable with the default template. Custom `{{.DisplayName}}`-only templates are an admin footgun (excluded).
2. **Consul revoke namespace/partition from lease `Data`** rather than `InternalData` — revocation correctness if Data were missing; not attacker-writable on `sys/leases/revoke`.
3. **Nomad token name truncation** can clip the nano-time entropy — not privilege escalation.
4. **Mount-admin role writers** can mint Consul/Nomad management tokens or RabbitMQ `administrator` tags — intentional trust model (excluded).

---

## Conclusion

No new medium+ finding with attacker → controlled input → reachable sink → concrete impact was validated in rabbitmq, nomad, consul, mongodb, or the shared username template helpers beyond issues already excluded by prior coverage.
