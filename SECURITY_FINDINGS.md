# Vault Application Security Review Findings

Commit: `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`

## Validated Finding

### Cert auth OCSP fail-open / servers_override cross-contamination across roles

| Field | Detail |
| --- | --- |
| **Severity** | Medium (High in multi-role OCSP deployments) |
| **Attacker** | Holder of a revoked client cert + private key that still matches a fail-closed (`ocsp_fail_open=false`) cert role; optionally a limited admin who can write a *different* cert role |
| **Controlled input** | TLS client certificate presented at `auth/cert/login` (typically without `name`); optionally content of a weaker cert role (`ocsp_fail_open`, `ocsp_servers_override`) |
| **Impact** | Bypass of per-role OCSP revocation enforcement: revoked certificates can authenticate against a fail-closed role when another OCSP-enabled role contaminates shared OCSP settings |

#### Attack path

1. Mount has two (or more) cert roles with `ocsp_enabled=true`, e.g. `certs/prod` with `ocsp_fail_open=false` and `certs/zzz-lab` with `ocsp_fail_open=true` (and/or `ocsp_servers_override` pointing at unreachable hosts).
2. Client logs in via `auth/cert/login` **without** specifying `name` (documented default: try all trusted certificates).
3. `loadTrustedCerts` builds a **single shared** `ocsp.VerifyConfig` while iterating all roles. `OcspFailureMode` is last-writer-wins; `OcspServersOverride` is appended across roles and, when non-empty, **replaces** AIA OCSP URLs for every check.
4. Client cert matches the fail-closed `prod` role constraints; `matchesConstraints` correctly gates on `config.Entry.OcspEnabled` but passes the **shared** `conf` into OCSP verification.
5. When OCSP is unreachable (outage, DoS, or contaminated override to a dead host), `checkForCertInOCSP` treats the failure as fail-open because `conf.OcspFailureMode == FailOpenTrue` from the other role → login succeeds and issues a token with `prod` policies.

Privilege-escalation variant: ACL allows `create/update` on `auth/cert/certs/zzz-lab` but not on `certs/prod`. Writing a fail-open / override role weakens OCSP for all unnamed logins against other roles on the same mount.

#### Location

`builtin/credential/cert/path_login.go` — `loadTrustedCerts` / `matchesConstraints` / `checkForCertInOCSP`

#### Evidence

Shared config aggregation (last fail-open wins; overrides merged):

```624:671:builtin/credential/cert/path_login.go
	conf = &ocsp.VerifyConfig{}
	for _, name := range names {
		// ...
		if entry.OcspEnabled {
			conf.OcspEnabled = true
			conf.OcspServersOverride = append(conf.OcspServersOverride, entry.OcspServersOverride...)
			if entry.OcspFailOpen {
				conf.OcspFailureMode = ocsp.FailOpenTrue
			} else {
				conf.OcspFailureMode = ocsp.FailOpenFalse
			}
			conf.QueryAllServers = conf.QueryAllServers || entry.OcspQueryAllServers
			conf.OcspThisUpdateMaxAge = entry.OcspThisUpdateMaxAge
			conf.OcspMaxRetries = entry.OcspMaxRetries
		}
	}
```

Per-role enablement, shared config for the actual check:

```373:379:builtin/credential/cert/path_login.go
	if config.Entry.OcspEnabled {
		ocspGood, err := b.checkForCertInOCSP(ctx, clientCert, trustedChain, conf)
		if err != nil {
			return false, err
		}
		soFar = soFar && ocspGood
	}
```

Fail-open honors the shared mode on network errors:

```697:701:builtin/credential/cert/path_login.go
		if conf.OcspFailureMode == ocsp.FailOpenTrue {
			onlyNetworkErrors := b.handleOcspErrorInFailOpen(err)
			if onlyNetworkErrors {
				return true, nil
			}
		}
```

Override list replaces AIA when any role contributed overrides:

```531:534:sdk/helper/ocsp/client.go
	ocspHosts := subject.OCSPServer
	if len(conf.OcspServersOverride) > 0 {
		ocspHosts = conf.OcspServersOverride
	}
```

Empty `certName` (default login) loads all roles:

```612:621:builtin/credential/cert/path_login.go
	var names []string
	if certName != "" {
		names = append(names, certName)
	} else {
		var err error
		names, err = storage.List(ctx, trustedCertPath)
```

#### Remediation

- Build a per-role `ocsp.VerifyConfig` from the matched `ParsedCert.Entry` (fail-open, servers override, query-all, retries, max-age) instead of one mount-wide aggregate.
- Do not merge `OcspServersOverride` across unrelated roles; only apply overrides configured on the role being evaluated.
- Optionally: when `name` is omitted, evaluate OCSP with each candidate role’s own config before accepting a match.
- Add regression tests with two OCSP-enabled roles (`fail_open=false` + `fail_open=true`, and override-only on the second) asserting the fail-closed role still denies on OCSP unavailability.

---

## Areas checked (no additional validated findings)

| Area | Why near-misses failed validation |
| --- | --- |
| AppRole login / secret_id num_uses | CIDR-after-burn already known; locks around num_uses otherwise sound |
| Cert CN / renewal AND-vs-OR, OCSP/CRL SSRF | Explicitly known; CRL upload trusts admin-supplied lists by design |
| SSH CA templates / critical_options / OTP verify | Known template issues skipped; OTP verify unauthenticated by design (UUID OTP) |
| MFA validate / TOTP usedCodes | Unauthenticated validate is intentional; request ID is UUID; whitespace reuse known |
| sys_* unauth paths | generate-root/rekey DoS known; raft remove-peer unauth only on DR secondary + op token |
| Identity merge / groups | Namespace checks present; merge requires identity ACL |
| Cubbyhole / wrapping | `..` rejected by `StorageView.SanityCheck`; wrapping token model is intentional |
| Consul/RabbitMQ/Nomad DisplayName | Known injection class |
| K8s/JWT/GCP/CF/AD/OpenLDAP plugins | No new end-to-end authz/injection path proven beyond known items |
| Namespace chroot / UI routes | No proven escape; OIDC prompt=none known |
| Token/lease races | No concrete exploitable race proven in this pass |
