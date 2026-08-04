# Vulnerability Validation — Vault 1.18.0-beta1 (`0513545dd`)

Independent code review at commit `0513545dd8213ffcbb3406c25cda69cd0a5b0e47` (`VERSION` = `1.18.0-beta1`).

Verdict legend:
- **STILL_VULNERABLE**: defective code present and a defensible end-to-end path exists under realistic config.
- **FIXED**: mitigating control present in this tree.
- **Attack path concrete**: yes only when inputs, privilege, and impact chain can be followed in-tree without speculation.

---

## Summary

| # | ID / Issue | Status | Severity | Attack path concrete |
|---|---|---|---|---|
| 1 | CVE-2025-6000 audit file RCE | STILL_VULNERABLE | critical | yes |
| 2 | CVE-2025-5999 identity root policy case bypass | STILL_VULNERABLE | high | yes |
| 3 | CVE-2025-6037 cert auth non-CA CN impersonation | STILL_VULNERABLE | medium/high | yes |
| 4 | Redshift SQLi `terminateloop` | STILL_VULNERABLE | high | yes (privileged DB operator / controllable username) |
| 5 | HANA SQLi `DeleteUser`/`revokeUserDefault` | STILL_VULNERABLE | high | yes (privileged DB operator / controllable username) |
| 6 | ACME SSRF (CVE-2026-5052) | STILL_VULNERABLE | medium | yes (ACME enabled + attacker DNS) |
| 7 | CVE-2024-7594 SSH empty principals | STILL_VULNERABLE | high | yes |
| 8 | CVE-2025-11621 AWS auth cache/account mixup | STILL_VULNERABLE | high | yes (cross-account / wildcard bind) |
| 9 | CVE-2025-6013 LDAP MFA username_as_alias | STILL_VULNERABLE | medium | yes (entity/group-scoped MFA + whitespace alias) |

No `AllowAuditLogPrefixing`, no audit→plugin-dir block, no `allow_empty_principals`, no ACME dial-target rejection, and no Redshift/HANA quoting fixes appear in this commit.

---

## 1. CVE-2025-6000 — Audit file backend RCE

**Status:** STILL_VULNERABLE  
**Severity:** critical  
**Primary file:** `audit/backend_file.go` (+ `audit/entry_formatter_config.go`, `audit/entry_formatter.go`)

### Evidence

Prefix is accepted unconditionally from audit device options:

```95:97:audit/entry_formatter_config.go
	if prefix, ok := config[optionPrefix]; ok {
		opt = append(opt, WithPrefix(prefix))
	}
```

Prefix bytes are prepended to every audit line:

```185:187:audit/entry_formatter.go
	if f.config.prefix != "" {
		result = append([]byte(f.config.prefix), result...)
	}
```

`file_path` is used as-is; no plugin-directory destination check:

```50:57:audit/backend_file.go
	var filePath string
	if p, ok := conf.Config[optionFilePath]; ok {
		filePath = p
	} else if p, ok = conf.Config["path"]; ok {
		filePath = p
	} else {
		return nil, fmt.Errorf("%q is required: %w", optionFilePath, ErrExternalOptions)
	}
```

File mode is attacker-influenced (`mode` option → `WithFileMode`). Repo-wide search finds **no** `AllowAuditLogPrefixing` / `allow_audit_log_prefixing`.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Privileged operator with `sys/audit` write in root namespace |
| Controlled input | Audit `file_path`, `prefix`, `mode`; later plugin catalog registration |
| Reachability | API `sys/audit/*` enable file device |
| Impact | Write executable payload under `plugin_directory`, register/run as plugin → host RCE |
| Concrete? | **yes** — requires `plugin_directory` configured; matches HCSEC-2025-14 |

---

## 2. CVE-2025-5999 — Identity entity root policy case/normalization bypass

**Status:** STILL_VULNERABLE  
**Severity:** high  
**Primary file:** `vault/identity_store_entities.go`

### Evidence

Entity policy assignment dedupes **without** lowercasing/trimming, then blocks only exact `"root"`:

```355:363:vault/identity_store_entities.go
		// Update the policies if supplied
		entityPoliciesRaw, ok := d.GetOk("policies")
		if ok {
			entity.Policies = strutil.RemoveDuplicates(entityPoliciesRaw.([]string), false)
		}

		if strutil.StrListContains(entity.Policies, "root") {
			return logical.ErrorResponse("policies cannot contain root"), nil
		}
```

At request time, identity policies are sanitized (lower+trim), collapsing `"ROOT"` / `" root"` into real `root`:

```51:64:sdk/helper/policyutil/policyutil.go
func SanitizePolicies(policies []string, addDefault bool) []string {
	defaultFound := false
	for i, p := range policies {
		policies[i] = strings.ToLower(strings.TrimSpace(p))
		// ...
		if policies[i] == "root" {
			policies = []string{"root"}
```

Applied when building auth/ACL:

```300:302:vault/request_handling.go
	for nsID, nsPolicies := range identityPolicies {
		policyNames[nsID] = policyutil.SanitizePolicies(append(policyNames[nsID], nsPolicies...), false)
	}
```

Note: group path uses `RemoveDuplicatesStable(..., true)` before the `"root"` check (`vault/identity_store_groups.go`), so pure case variants like `"ROOT"` are harder there; entity path is the clear bypass.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Operator with write on root-namespace `identity/entity` |
| Controlled input | `policies` = `["ROOT"]` or `[" root"]` |
| Reachability | Identity entity create/update API |
| Impact | Entity-derived tokens gain root policy for token lifetime |
| Concrete? | **yes** |

---

## 3. CVE-2025-6037 — Cert auth non-CA CN impersonation

**Status:** STILL_VULNERABLE  
**Severity:** medium (high when entity/group policies are CN/alias-driven)  
**Primary file:** `builtin/credential/cert/path_login.go`

### Evidence

Non-CA trust matches serial, AKID, and public key — **not** CN:

```276:308:builtin/credential/cert/path_login.go
	if len(trustedNonCAs) != 0 {
		for _, trustedNonCA := range trustedNonCAs {
			tCert := trustedNonCA.Certificates[0]
			// Check for client cert being explicitly listed in the config (and matching other constraints)
			if tCert.SerialNumber.Cmp(clientCert.SerialNumber) == 0 &&
				bytes.Equal(tCert.AuthorityKeyId, clientCert.AuthorityKeyId) {
				pkMatch, err := certutil.ComparePublicKeysAndType(tCert.PublicKey, clientCert.PublicKey)
				// ...
				if matches {
					return trustedNonCA, nil, nil
				}
```

Alias/entity identity is taken from presented cert CN:

```160:169:builtin/credential/cert/path_login.go
	auth := &logical.Auth{
		// ...
		Alias: &logical.Alias{
			Name: clientCerts[0].Subject.CommonName,
		},
	}
```

`matchesCommonName` defaults to allow-all when `allowed_common_names` unset.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Holder of a pinned non-CA cert + private key |
| Controlled input | Forged client cert: same pubkey/serial/AKID, arbitrary CN |
| Reachability | Cert auth login against non-CA trusted cert config |
| Impact | Authenticate as another alias/entity; inherit that entity’s policies/groups |
| Concrete? | **yes** (requires non-CA trusted cert configuration) |

---

## 4. Redshift SQLi — `terminateloop`

**Status:** STILL_VULNERABLE  
**Severity:** high  
**Primary file:** `plugins/database/redshift/redshift.go`

### Evidence

Username interpolated into a SQL string literal with no escaping:

```435:451:plugins/database/redshift/redshift.go
		revocationStmts = append(revocationStmts, `CREATE OR REPLACE PROCEDURE terminateloop(dbusername varchar(100))
LANGUAGE plpgsql
AS $$
DECLARE
  currentpid int;
  loopvar int;
  qtyconns int;
BEGIN
SELECT COUNT(process) INTO qtyconns FROM stv_sessions WHERE user_name=dbusername;
  FOR loopvar IN 1..qtyconns LOOP
    SELECT INTO currentpid process FROM stv_sessions WHERE user_name=dbusername ORDER BY process ASC LIMIT 1;
    SELECT pg_terminate_backend(currentpid);
  END LOOP;
END
$$;`)

		revocationStmts = append(revocationStmts, fmt.Sprintf(`call terminateloop('%s');`, username))
```

Nearby statements use `dbutil.QuoteIdentifier`, but this call site does not. No `QuoteStringLiteral` helper exists in-tree. Upstream changelog later records the fix.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Operator who can set DB static-role username / malicious username template and trigger revoke/delete |
| Controlled input | `username` reaching `DeleteUser` |
| Reachability | Database secrets engine Redshift revoke path |
| Impact | Arbitrary SQL as Vault DB credentials during revocation |
| Concrete? | **yes** for controllable usernames (static roles / unsafe templates). Default dynamic usernames are usually alphanumeric and less practical. |

---

## 5. HANA SQLi — `DeleteUser` / `revokeUserDefault`

**Status:** STILL_VULNERABLE  
**Severity:** high  
**Primary file:** `plugins/database/hana/hana.go`

### Evidence

```347:359:plugins/database/hana/hana.go
	// Disable server login for user
	disableStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("ALTER USER %s DEACTIVATE USER NOW", req.Username))
	// ...
	dropStmt, err := tx.PrepareContext(ctx, fmt.Sprintf("DROP USER %s RESTRICT", req.Username))
```

No identifier quoting. Upstream later fixed by quoting usernames as SQL identifiers.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Same class as #4 |
| Controlled input | `req.Username` |
| Reachability | Default HANA revoke path when no custom revoke statements |
| Impact | SQL/identifier injection as Vault HANA credentials |
| Concrete? | **yes** under controllable usernames |

---

## 6. ACME SSRF — missing loopback/private rejection (CVE-2026-5052)

**Status:** STILL_VULNERABLE  
**Severity:** medium  
**Primary file:** `builtin/logical/pki/acme_challenges.go`

### Evidence

HTTP-01 builds `http://` + domain and dials with a plain `net.Dialer` — no IP class checks:

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	dialer, err := buildDialerConfig(config)
	// ...
		DialContext:           dialer.DialContext,
	// ...
	resp, err := client.Get(path)
```

No `IsLoopback` / `IsPrivate` / `DialACMEValidationTarget` / `challenge_*_ip_ranges` guards in this tree. Fixed much later (HCSEC-2026-06 / CVE-2026-5052); that fix rejects loopback/link-local/etc., not necessarily all RFC1918 by default.

### Attack path

| Field | Detail |
|---|---|
| Attacker | ACME client able to create orders (unauth or EAB, per config) controlling DNS for a name |
| Controlled input | DNS A/AAAA → loopback/link-local/internal target |
| Reachability | PKI ACME http-01 / tls-alpn-01 validation |
| Impact | SSRF from Vault node; information disclosure about local/internal services |
| Concrete? | **yes** when ACME is enabled |

---

## 7. CVE-2024-7594 — SSH empty valid principals

**Status:** STILL_VULNERABLE  
**Severity:** high  
**Primary file:** `builtin/logical/ssh/path_issue_sign.go`

### Evidence

Empty principals short-circuit to `nil` (no error):

```192:196:builtin/logical/ssh/path_issue_sign.go
	switch {
	case len(parsedPrincipals) == 0:
		// There is nothing to process
		return nil, nil
```

Those principals are written into the signed cert:

```506:511:builtin/logical/ssh/path_issue_sign.go
	certificate := &ssh.Certificate{
		// ...
		ValidPrincipals: b.ValidPrincipals,
```

Repo-wide search: **no** `allow_empty_principals` / `AllowEmptyPrincipals` (the 1.17.6+ remediation). This beta predates that guard on this branch.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Any client authorized to sign/issue on an SSH CA role with empty `default_user` and empty/omitted `valid_principals` / `allowed_users` leading to empty principal set |
| Controlled input | Sign/issue request omitting principals when role defaults are empty |
| Reachability | `ssh/sign/*` or `ssh/issue/*` |
| Impact | Cert valid for any principal → authenticate as any user on trusting SSH hosts |
| Concrete? | **yes** for misconfigured/empty-principal roles (the insecure default the CVE describes) |

---

## 8. CVE-2025-11621 — AWS auth cache / account mishandling

**Status:** STILL_VULNERABLE  
**Severity:** high  
**Primary file:** `builtin/credential/aws/client.go` (+ `path_login.go` `fullArn`)

### Evidence

IAM/EC2 clients cached by `region` + `stsRole` only; accounts without STS config share empty `stsRole`:

```208:218:builtin/credential/aws/client.go
func (b *backend) stsRoleForAccount(ctx context.Context, s logical.Storage, accountID string) (string, string, error) {
	sts, err := b.lockedAwsStsEntry(ctx, s, accountID)
	// ...
	// An empty STS role signifies the master account
	if sts != nil {
		return sts.StsRole, sts.ExternalID, nil
	}
	return "", "", nil
}
```

```284:289:builtin/credential/aws/client.go
	if b.IAMClientsMap[region] != nil && b.IAMClientsMap[region][stsRole] != nil {
		defer b.configMutex.RUnlock()
		b.Logger().Debug(fmt.Sprintf("returning cached client for region %s and stsRole %s", region, stsRole))
		return b.IAMClientsMap[region][stsRole], nil
	}
```

Wildcard login path uses that client via `fullArn` → `GetRole`/`GetUser` by **friendly name**:

```1889:1912:builtin/credential/aws/path_login.go
	client, err := b.clientIAM(ctx, s, region.ID(), e.AccountNumber)
	// ...
		input := iam.GetRoleInput{
			RoleName: aws.String(e.FriendlyName),
		}
		resp, err := client.GetRoleWithContext(ctx, &input)
```

If the cached client belongs to another account, role-name collision can yield another account’s ARN, which can then satisfy wildcard `bound_iam_principal_arn` matching.

### Attack path

| Field | Detail |
|---|---|
| Attacker | IAM principal in account B with same role/user name (or wildcard collision) as a bound principal |
| Controlled input | Valid STS-signed IAM login; depends on prior cache population / shared default credentials |
| Reachability | `auth/aws/login` with wildcard or cross-account same-name binds |
| Impact | Auth as Vault role intended for another account’s principal |
| Concrete? | **yes** under cross-account same-name or wildcard `bound_iam_principal_arn` configs described in HCSEC-2025-30 |

---

## 9. CVE-2025-6013 — LDAP MFA bypass via `username_as_alias`

**Status:** STILL_VULNERABLE  
**Severity:** medium  
**Primary file:** `builtin/credential/ldap/backend.go` (+ `path_login.go`)

### Evidence

With `username_as_alias`, the **raw login username** becomes the alias — no trim/normalize:

```157:158:builtin/credential/ldap/backend.go
	if usernameAsAlias {
		return username, policies, ldapResponse, allGroups, nil
```

```82:100:builtin/credential/ldap/path_login.go
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	effectiveUsername, policies, resp, groupNames, err := b.Login(ctx, req, username, password, cfg.UsernameAsAlias)
	// ...
		Alias: &logical.Alias{
			Name: effectiveUsername,
```

MFA enforcement matching is entity/group/mount based (`vault/login_mfa.go` `buildMFAEnforcementConfigList`). A whitespace-variant alias can create a distinct entity that is not bound to entity/group MFA enforcements attached to the canonical identity.

### Attack path

| Field | Detail |
|---|---|
| Attacker | Valid LDAP user when `username_as_alias=true` |
| Controlled input | Username with leading/trailing spaces accepted by LDAP after its own normalization |
| Reachability | LDAP login |
| Impact | Bypass entity/group-scoped Login MFA; obtain token without second factor |
| Concrete? | **yes** for entity/group MFA bindings. Mount-wide MFA enforcements still match by accessor/type and are not bypassed by this bug alone. |

---

## Cross-cutting notes

- Version gate: Community fixes for these land in 1.20.x / 1.21.x (and SSH in 1.17.6). `1.18.0-beta1` is earlier than those remediations on this snapshot.
- Privileged-operator bugs (#1, #2, #4, #5) remain valuable because Vault’s threat model often treats `sys/audit` / identity writers / DB config writers as non-root.
- Skeptical exclusions: none of the nine were marked FIXED; each retains the pre-patch code shape and a reachable chain under the configs named by the vendor advisories.
