# Vault OSS AppSec Review — 0513545dd (1.18.0-beta1)

Validated medium/high/critical findings with end-to-end attack paths.
Excluded as instructed: identity ROOT policy case bypass, TOTP whitespace reuse,
userpass lockout casing, MySQL/Postgres static-role SQLi, ACME HTTP-01 SSRF.

Rejected / weak candidates (summary):
- **File audit → plugin_directory RCE**: `audit/backend_file.go` accepts arbitrary
  `file_path`/`path` + `mode` + `prefix` with **no** plugin-directory guard in this
  tree. Enabling audit is a root/sudo-class capability; no privilege escalation
  beyond already-privileged operators. (Later HCSEC-2026-16 guards are absent here.)
- **Snowflake unquoted `{{name}}` defaults**: real footgun in rotate/delete SQL, but
  default username template suffixes make reliable injection hard; class overlaps
  commonly rediscovered DB username SQLi.
- **Cert non-CA CN alias impersonation**: related to later CVE-2025-6037; SKID/AKID
  renew bug below is the cleaner binding failure at this commit.

---

## 1. Unauthenticated Raft bootstrap challenge memory DoS

**Severity:** High (Availability) — CVE-2024-8185 / HCSEC-2024-26  
**Fixed upstream:** 1.18.1 (this tree is 1.18.0-beta1, still vulnerable)

### Evidence
- Unauthenticated paths include bootstrap challenge/answer:

```165:167:vault/logical_system.go
				"storage/raft/bootstrap/challenge",
				"storage/raft/bootstrap/answer",
```

- Challenge handler stores a new 16-byte answer per unique `server_id` in an
  unbounded `sync.Map`, with **no TTL, max size, or rate limit**, and seals a
  challenge blob (crypto cost) every time:

```269:287:vault/logical_system_raft.go
func (b *SystemBackend) handleRaftBootstrapChallengeWrite(makeSealer func() snapshot.Sealer) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
		serverID := d.Get("server_id").(string)
		// ...
		answerRaw, ok := b.Core.pendingRaftPeers.Load(serverID)
		if !ok {
			answer, err = uuid.GenerateRandomBytes(16)
			// ...
			b.Core.pendingRaftPeers.Store(serverID, answer)
```

- Map only cleared on successful answer or seal transition (`vault/raft.go`);
  no pruning of pending entries.

### Attack path
1. **Attacker:** Unauthenticated network client who can reach the Vault API of a
   cluster using Integrated Storage (Raft).
2. **Input:** `PUT /v1/sys/storage/raft/bootstrap/challenge` with unique
   `server_id` values (and/or high volume to force seal operations).
3. **Reachability:** Path is explicitly in `PathsSpecial.Unauthenticated`.
4. **Impact:** Unbounded growth of `pendingRaftPeers` plus per-request seal
   work → memory exhaustion / process or host crash → cluster outage.
5. **Why not speculative:** Later fix (LRU + rate limit + challenge reuse) and
   official CVE confirm the same root cause present in this code.

---

## 2. SSH CA empty ValidPrincipals → certificate valid for any principal

**Severity:** High — CVE-2024-7594 / HCSEC-2024-20  
**Fixed upstream:** 1.17.6 (`allow_empty_principals`); **not present** in this tree.

### Evidence
When the client omits `valid_principals` and the role has empty `default_user`
(and empty/non-matching allowed list handling falls through),
`calculateValidPrincipals` returns an empty slice:

```192:195:builtin/logical/ssh/path_issue_sign.go
	switch {
	case len(parsedPrincipals) == 0:
		// There is nothing to process
		return nil, nil
```

That slice is embedded directly into the signed cert:

```506:511:builtin/logical/ssh/path_issue_sign.go
	certificate := &ssh.Certificate{
		// ...
		ValidPrincipals: b.ValidPrincipals,
```

OpenSSH treats an empty principals list as “valid for any principal” of that
cert type. No `allow_empty_principals` gate exists anywhere in this checkout.

### Attack path
1. **Attacker:** Any Vault principal permitted to `ssh/sign/<role>` or
   `ssh/issue/<role>` on a CA role where `default_user` / requested principals
   can be empty (common misconfig / omitted fields).
2. **Input:** Sign request with empty/omitted `valid_principals`.
3. **Reachability:** Standard secrets-engine API; no extra authz beyond role use.
4. **Impact:** Host cert or user cert accepted by sshd as **any** principal →
   login as `root`/`ubuntu`/etc. on trusting hosts (when CA is trusted).
5. **Severity rationale:** Authenticated low-privilege Vault user → full host
   principal impersonation. Official CVSS 8.8.

---

## 3. Cert auth renewal SKID/AKID binding uses `&&` (same-CA renew bypass)

**Severity:** High (token lifetime / binding bypass)  
**Status at this commit:** Vulnerable. Upstream later requires **both** SKID and
AKID to match (separate checks).

### Evidence
Login stores both key IDs in `Auth.InternalData`. Renewal intended to bind the
renewing client cert to the login identity, but the mismatch check is conjunctive:

```210:217:builtin/credential/cert/path_login.go
		skid := base64.StdEncoding.EncodeToString(clientCerts[0].SubjectKeyId)
		akid := base64.StdEncoding.EncodeToString(clientCerts[0].AuthorityKeyId)

		// Certificate should not only match a registered certificate policy.
		// Also, the identity of the certificate presented should match the identity of the certificate used during login
		if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid {
			return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
		}
```

Renewal fails only if **both** SKID **and** AKID differ. Same issuing CA ⇒ same
AKID ⇒ check passes even when SKID (leaf identity) differs. Empty SKID on both
leaves also collides.

`verifyCredentials` on renew still runs (cert must chain to the saved
`cert_name` entry), so the attacker’s cert must be acceptable to that CA/role
constraint set (broad `allowed_names` / empty allow-lists are common).

### Attack path
1. **Attacker:** Holds a victim token (theft, XSS, CI leak, malicious peer) **and**
   possesses a different client cert issued by the **same CA** that satisfies the
   cert auth role used at login (`cert_name` in token metadata).
2. **Input:** TLS client cert on `auth/token/renew` (or lease renew) while
   presenting the stolen token; `disable_binding=false` (default).
3. **Reachability:** Default cert auth renewal path; no config flag required.
4. **Impact:** Renew victim token **without** victim’s private key after victim
   cert expiry/revocation (within max TTL/period), preserving victim policies /
   entity. Breaks the documented binding guarantee of cert auth renewal.
5. **Why defensible:** Comment says identity must match; operator is `&&`;
   upstream fixed to two independent comparisons.

---

## 4. LDAP `username_as_alias` padded username → MFA enforcement bypass

**Severity:** Medium/High — CVE-2025-6013 / HCSEC-2025-20  
**Fixed upstream:** 1.20.2 / Ent 1.18.13; vulnerable here.

### Evidence
With `username_as_alias=true`, the entity alias is the **raw request username**,
not a normalized DN attribute:

```157:158:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
```

Login path passes API username straight through (no trim):

```82:99:builtin/credential/ldap/path_login.go
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	effectiveUsername, policies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
```

LDAP bind/search may still succeed for whitespace-padded CN variants after
directory-side normalization, while Vault creates a **distinct** alias/entity
for `"alice"` vs `"alice "` / `" alice"`. MFA login enforcements attached to the
canonical entity/alias therefore do not apply to the padded alias.

### Attack path
1. **Attacker:** Valid LDAP user password; MFA enforcement configured on the
   normal entity/alias; `username_as_alias=true`.
2. **Input:** `POST auth/ldap/login/<padded-username>` with leading/trailing
   spaces in the username path/field.
3. **Reachability:** Unauthenticated login endpoint; directory accepts padded
   CN equivalent (environment-dependent but the class HashiCorp documented).
4. **Impact:** Authenticate as the same LDAP principal into a **new** entity
   without MFA → access token with mapped LDAP group policies, bypassing MFA.
5. **Severity:** Official CNA 6.5 / NVD up to 8.1 depending on scoring.

---

## 5. SSH `allowed_*_template` comma-split after render (principal injection)

**Severity:** High (privilege escalation on SSH CA roles using identity templates)

### Evidence
Templates are rendered **first**, then split on commas into the allow-list:

```182:187:builtin/logical/ssh/path_issue_sign.go
	if enableTemplating {
		rendered, err := b.renderPrincipal(principalsAllowedByRole, req)
		// ...
		allowedPrincipals = strutil.RemoveDuplicates(strutil.ParseStringSlice(rendered, ","), false)
```

Same helper serves both `allowed_users_template` and `allowed_domains_template`.
PR history (`changelog/16622.txt`) explicitly notes the security implication:
user-controlled identity metadata with commas expands permitted principals.

### Attack path
1. **Attacker:** Identity that can set/influence a templated field (entity
   metadata, alias metadata, or IdP claim synced into metadata) **and** call
   `ssh/sign/<role>` on a role with
   `allowed_users_template=true` or `allowed_domains_template=true`, e.g.
   `allowed_users="{{identity.entity.metadata.ssh_username}}"`.
2. **Input:** Set metadata to `alice,root,ubuntu` (or
   `app.example.com,*.internal` for host certs with subdomain options).
3. **Reachability:** After render, allow-list becomes multiple principals;
   attacker requests `valid_principals=root` (or extra host name) and passes
   validation.
4. **Impact:** SSH user/host principal privilege escalation beyond the
   administrator’s intended single templated identity.
5. **Why not “admin misconfig only”:** Feature is designed for per-user
   templating; comma is an undocumented control-plane character inside
   user-influenced data. Distinct from empty-principals CVE.

---

## Honorable mention (validated, slightly lower novelty / impact)

### AppRole SecretID use-count burned before CIDR checks
`builtin/credential/approle/path_login.go` (non-zero `SecretIDNumUses` branch):
storage delete/decrement happens **before** SecretID/role CIDR enforcement.
Attacker who learns a one-time SecretID but is outside `secret_id_bound_cidrs`
can still **invalidate** it (login fails, SecretID gone). Medium availability /
credential DoS against AppRole workloads; no token issuance.

### Elasticsearch `path.Join` username path traversal
`vault-plugin-database-elasticsearch` `client.go` builds
`path.Join(securityPath, "user"|"role", name)` and concatenates onto `baseURL`.
Caller-controlled `DisplayName` (e.g. JWT `user_claim`) flows via
`database/path_creds_create.go` → username template. With a custom
`username_template` of `{{.DisplayName}}`, DisplayName `../user/elastic`
resolves to `/_security/user/elastic` and can overwrite privileged ES users.
Default template still allows `../` segments to reshape paths under
`/_security/user/`. Requires DB creds capability + controllable DisplayName;
strong when custom templates are used.

---

## Ranking rationale

| Rank | Finding                         | Attacker bar              | Impact                         |
|------|---------------------------------|---------------------------|--------------------------------|
| 1    | Raft pendingRaftPeers DoS       | Unauthenticated           | Cluster crash                  |
| 2    | SSH empty ValidPrincipals       | SSH role user             | Any OS principal               |
| 3    | Cert SKID/AKID renew `&&`       | Stolen token + peer cert  | Extend foreign token           |
| 4    | LDAP username_as_alias MFA      | LDAP user + MFA deployed  | MFA bypass                     |
| 5    | SSH template comma injection    | Metadata write + SSH role | Extra SSH principals           |
