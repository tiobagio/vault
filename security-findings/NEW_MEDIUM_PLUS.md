# Additional MEDIUM+ Findings — HashiCorp Vault

**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Tree version:** `1.18.0-beta1`  
**Scope:** Findings **not** in the excluded known-issue list. Static reachability review.

---

## 1. Raft bootstrap challenge — unauthenticated memory/CPU DoS (CVE-2024-8185 / HCSEC-2024-26)

- **Severity:** High (availability; can crash Vault / host)
- **Attacker:** Unauthenticated client that can reach the Vault API on a raft-storage cluster
- **Controlled input:** `server_id` on `POST /v1/sys/storage/raft/bootstrap/challenge`
- **Reachability path:**
  1. Cluster uses Integrated Storage (`storage "raft"`); leader is unsealed
  2. Path is registered as **unauthenticated**
  3. Each request with a new `server_id` allocates a pending peer entry and runs `sealer.Seal()` (seal crypto) on a random answer
  4. Flood unique `server_id` values → unbounded `pendingRaftPeers` growth + repeated seal crypto → memory/CPU exhaustion → crash
- **Impact:** Denial of service of the Vault cluster / host via unauthenticated raft join challenge endpoint
- **Primary location:** `vault/logical_system_raft.go`, `vault/logical_system.go`

### Evidence

Unauthenticated registration:

```165:166:vault/logical_system.go
				"storage/raft/bootstrap/challenge",
				"storage/raft/bootstrap/answer",
```

Challenge handler: store pending peer + seal crypto per new `server_id` (no rate limit / map bound in this tree):

```269:296:vault/logical_system_raft.go
func (b *SystemBackend) handleRaftBootstrapChallengeWrite(makeSealer func() snapshot.Sealer) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		serverID := d.Get("server_id").(string)
		// ...
		answerRaw, ok := b.Core.pendingRaftPeers.Load(serverID)
		if !ok {
			answer, err = uuid.GenerateRandomBytes(16)
			// ...
			b.Core.pendingRaftPeers.Store(serverID, answer)
		}
		// ...
		protoBlob, err := sealer.Seal(ctx, answer)
```

Fixed upstream in 1.18.1; this tree is `1.18.0-beta1` (vulnerable).

---

## 2. Userpass / LDAP lockout bypass via case-variant alias lookahead (CVE-2025-6004 / HCSEC-2025-16)

- **Severity:** Medium–High (defeats brute-force lockout)
- **Attacker:** Unauthenticated client guessing passwords against Userpass (always) or LDAP when `case_sensitive_names=false` (default)
- **Controlled input:** Username casing on `auth/<mount>/login[/...]`
- **Reachability path:**
  1. Lockout keys are built from `AliasLookaheadOperation` alias name (`aliasNameFromLoginRequest`)
  2. Userpass `pathLogin` lowercases the username for auth, but `pathLoginAliasLookahead` returns the **raw** username (no `ToLower`)
  3. LDAP alias lookahead likewise returns raw username; login may still succeed for the same account under different case
  4. Attacker rotates `Admin` / `ADMIN` / `AdMiN` / … → each casing gets its own failed-login counter → lockout never trips for the real account
- **Impact:** Bypass of user lockout; sustained online password guessing against Userpass/LDAP users
- **Primary location:** `builtin/credential/userpass/path_login.go`, `builtin/credential/ldap/path_login.go`, `vault/request_handling.go` / `vault/core.go`

### Evidence

Userpass: login lowercases, lookahead does not:

```50:66:builtin/credential/userpass/path_login.go
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username,
			},
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
```

LDAP lookahead likewise uses raw username:

```47:57:builtin/credential/ldap/path_login.go
func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	// ...
			Alias: &logical.Alias{
				Name: username,
			},
```

Lockout key uses lookahead alias:

```2155:2168:vault/request_handling.go
func (c *Core) getLoginUserInfoKey(ctx context.Context, mountEntry *MountEntry, req *logical.Request) (FailedLoginUser, error) {
	// ...
	aliasName, err := c.aliasNameFromLoginRequest(ctx, req)
	// ...
	userInfo.aliasName = aliasName
```

```4288:4298:vault/core.go
	resp, err := matchingBackend.HandleRequest(ctx, &logical.Request{
		// ...
		Operation:  logical.AliasLookaheadOperation,
		Data:       req.Data,
```

---

## 3. Userpass timing side-channel — username enumeration (CVE-2025-6011 / HCSEC-2025-15)

- **Severity:** Medium
- **Attacker:** Unauthenticated client hitting `auth/userpass/login/:username`
- **Controlled input:** Username (existence oracle via response timing)
- **Reachability path:**
  1. Missing user sets `userPassword = []byte("dummy")` (not a valid bcrypt hash)
  2. `bcrypt.CompareHashAndPassword` exits early on invalid hash format
  3. Existing users run full bcrypt compare against a real hash
  4. Timing difference enumerates valid Userpass usernames
- **Impact:** Username enumeration to focus credential attacks (pairs with #2)
- **Primary location:** `builtin/credential/userpass/path_login.go`

### Evidence

```82:100:builtin/credential/userpass/path_login.go
	if user != nil && userError == nil {
		// ... real PasswordHash
	} else {
		userPassword = []byte("dummy")
	}
	// ...
	case !legacyPassword:
		if err := bcrypt.CompareHashAndPassword(userPassword, passwordBytes); err != nil {
```

---

## 4. File audit device → plugin directory host code execution (CVE-2025-6000 / HCSEC-2025-14)

- **Severity:** High / Critical (Vault operator → host RCE)
- **Attacker:** Privileged operator in **root** namespace with write on `sys/audit` (and ability to register/use plugins), when `plugin_directory` is configured
- **Controlled input:** Audit `file_path` (any filesystem path Vault can write), optional `prefix`; plugin catalog registration
- **Reachability path:**
  1. Enable file audit with `file_path` under the configured plugin directory — **no path restriction** in this tree
  2. `prefix` prepends attacker-controlled bytes to every audit line; file sink creates/appends arbitrary paths
  3. Craft audit output so the on-disk file is a valid plugin binary (or overwrite one); compute required SHA-256 (optionally with help of `sys/audit-hash` / reproducible content)
  4. Register plugin pointing at that path and mount/execute → host code execution as the Vault process user
- **Impact:** Escape from Vault ACL domain to OS-level code execution
- **Primary location:** `audit/backend_file.go`, `audit/entry_formatter.go`, `internal/observability/event/sink_file.go`

### Evidence

Arbitrary `file_path` accepted and opened with create/append (no plugin-dir deny list):

```48:84:audit/backend_file.go
	if p, ok := conf.Config[optionFilePath]; ok {
		filePath = p
	} else if p, ok = conf.Config["path"]; ok {
		filePath = p
	}
	// ...
	err = b.configureSinkNode(conf.MountPath, filePath, cfg.requiredFormat, opt...)
```

```127:130:audit/backend_file.go
	default:
		sinkName = name
		sinkNode, err = event.NewFileSink(filePath, format.String(), opt...)
```

```158:158:internal/observability/event/sink_file.go
	s.file, err = os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, s.fileMode)
```

Attacker-controlled line prefix:

```185:187:audit/entry_formatter.go
	if f.config.prefix != "" {
		result = append([]byte(f.config.prefix), result...)
	}
```

---

## Areas checked — no additional medium+ with defendable path

| Area | Outcome |
|------|---------|
| GitHub auth org/team | Org membership checked by `organization_id`; rename only warns. No bypass beyond documented PAT/`read:org` trust model |
| Okta auth / number challenge `verify/*` | Unauth `correct_answer` by client-chosen nonce is intentional for Okta Verify number matching; 20-char random nonce in CLI |
| RADIUS | Standard Access-Accept → policies; no case-lockout feature on this method |
| Cubbyhole / response wrapping | JWT wrapping validation and cubbyhole storage path look consistent; no unwrap bypass validated |
| Agent/proxy | `require_request_header` optional; no unauth cache smuggling beyond that hardening gap |
| Cassandra / MySQL / InfluxDB / MongoDB | Username templating uses raw `QueryHelper` replace, but default templates truncate DisplayName and create uses same quoting as revoke — unlike Redshift/HANA create-vs-revoke asymmetry. Mongo uses BSON commands. No High path validated with defaults |
| Transit | No novel authz/crypto break validated |
| Namespace / lease privilege | Identity root-policy issues excluded (CVE-2025-5999); no separate lease cross-NS escalation proven here |
| UI XSS (non-OIDC) | `log-error-with-html` triple-stash appears unused; OIDC redirect excluded |
| Plugin multiplex / gRPC | Catalog requires sha256; multiplex wiring looked routine |
| MFA Duo | Admin-configured Duo API; push path depends on Duo — no Vault-side bypass validated beyond excluded LDAP alias/TOTP issues |
| Raft snapshot restore | Snapshot read/write ACL-gated; no unsafe unauth restore path |

---

## Summary

| # | Title | Severity | CVE / advisory |
|---|-------|----------|----------------|
| 1 | Raft bootstrap challenge DoS | High | CVE-2024-8185 |
| 2 | Userpass/LDAP lockout bypass (alias case) | Medium–High | CVE-2025-6004 |
| 3 | Userpass bcrypt dummy timing enumeration | Medium | CVE-2025-6011 |
| 4 | File audit → plugin dir host RCE | High/Critical | CVE-2025-6000 |
