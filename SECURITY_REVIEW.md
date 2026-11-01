# Application Security Review — HashiCorp Vault

**Target:** fork `tiobagio/vault`, commit `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Scope:** authn/authz (`http/`, `vault/`, `builtin/credential/`), SSRF, command injection, path traversal, SQL injection  
**Date:** 2026-11-01

## Summary

One validated **medium** finding with a concrete end-to-end attack path. No high/critical issues were validated in this pass. Several near-misses were discarded (documented below).

---

## Finding 1 — ACME HTTP-01 SSRF to arbitrary IPs (including private/link-local)

| Field | Detail |
|--------|--------|
| **Title** | PKI ACME http-01 validation fetches attacker-chosen IP/host without private-network restrictions |
| **Severity** | **medium** |
| **Attacker** | Unauthenticated network client (when ACME is enabled and EAB is not required) |
| **Controlled input** | ACME order `identifiers` (`type: ip` or `type: dns`), plus optional HTTP redirects from a host the attacker controls |
| **Reachability** | Enable ACME (`POST /v1/<pki-mount>/config/acme` with `enabled=true`). Defaults leave `eab_policy` as `not-required` and `default_directory_policy` as `sign-verbatim`. Then use unauthenticated ACME API under `/v1/<pki-mount>/acme/` (new-account → new-order → challenge). |
| **Impact** | Blind SSRF from the Vault active node: TCP/HTTP to arbitrary IPs (RFC1918, link-local/`169.254.169.254`, localhost). Enables internal network probing, abuse of GET-side-effect services, and cloud metadata access attempts. Response body is not returned to the attacker (blind), but errors can leak connectivity / response size. |
| **Primary location** | `builtin/logical/pki/acme_challenges.go` |

### Reachability path

1. Operator enables ACME without tightening EAB / directory policy (common “just turn it on” path). Stored defaults keep EAB **not required** and directory policy **sign-verbatim** (allows any DNS name and IP SANs).
2. Attacker creates an ACME account (no Vault token, no EAB).
3. Attacker creates an order with an IP identifier, e.g. `{"type":"ip","value":"169.254.169.254"}` (accepted by sign-verbatim / roles with `allow_ip_sans=true`).
4. Attacker triggers the `http-01` challenge.
5. Vault builds `http://<identifier>/.well-known/acme-challenge/<token>` and performs `client.Get` with redirects allowed and no private-IP checks.

### Evidence

Default ACME config (EAB not required; sign-verbatim; IP SANs allowed via that role):

```41:49:builtin/logical/pki/path_config_acme.go
var defaultAcmeConfig = acmeConfigEntry{
	Enabled:                false,
	AllowedIssuers:         []string{"*"},
	AllowedRoles:           []string{"*"},
	AllowRoleExtKeyUsage:   false,
	DefaultDirectoryPolicy: "sign-verbatim",
	DNSResolver:            "",
	EabPolicyName:          eabPolicyNotRequired,
	MaxTTL:                 defaultAcmeMaxTTL,
}
```

`eab_policy` is only updated when explicitly present in the write (`GetOk`); enabling with `{"enabled":true}` alone leaves `not-required`:

```218:267:builtin/logical/pki/path_config_acme.go
	if enabledRaw, ok := d.GetOk("enabled"); ok {
		config.Enabled = enabledRaw.(bool)
	}
	// ...
	if eabPolicyRaw, ok := d.GetOk("eab_policy"); ok {
		eabPolicy, err := getEabPolicyByString(eabPolicyRaw.(string))
		// ...
		config.EabPolicyName = eabPolicy.Name
	}
```

IP identifiers are accepted under sign-verbatim / `allow_ip_sans`, and http-01 is the only challenge for IPs:

```427:431:builtin/logical/pki/path_acme_order.go
		case ACMEIPIdentifier:
			if !role.AllowIPSANs {
				return fmt.Errorf("%w: role (%s) does not allow IP sans, so cannot issue certificate for %v",
					ErrRejectedIdentifier, role.Name, identifier.OriginalValue)
			}
```

```856:859:builtin/logical/pki/path_acme_order.go
	allowedChallenges := []ACMEChallengeType{ACMEHTTPChallenge, ACMEDNSChallenge, ACMEALPNChallenge}
	if identifier.Type == ACMEIPIdentifier {
		allowedChallenges = []ACMEChallengeType{ACMEHTTPChallenge}
	} else if identifier.IsWildcard {
```

Challenge engine passes the identifier value straight into the HTTP fetch:

```437:438:builtin/logical/pki/acme_challenge_engine.go
		valid, err = ValidateHTTP01Challenge(authz.Identifier.Value, cv.Token, cv.Thumbprint, config)
```

Fetcher builds the URL from that value, follows redirects with no destination host/IP policy, and skips TLS verification on HTTPS hops:

```125:168:builtin/logical/pki/acme_challenges.go
func ValidateHTTP01Challenge(domain string, token string, thumbprint string, config *acmeConfigEntry) (bool, error) {
	path := "http://" + domain + "/.well-known/acme-challenge/" + token
	// ...
	transport := &http.Transport{
		// ...
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	maxRedirects := 10
	urlLength := 2000

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

Sign-verbatim role explicitly allows any name and IP SANs:

```369:373:builtin/logical/pki/issuing/roles.go
	entry := &RoleEntry{
		AllowLocalhost:            true,
		AllowAnyName:              true,
		AllowIPSANs:               true,
```

### Why this is not a false positive

- ACME directory/account/order/challenge endpoints are **unauthenticated by design** once ACME is enabled; EAB is the intended gate and is **not** applied unless configured.
- Unlike admin-configured webhook URLs, the SSRF target is chosen by the unauthenticated ACME client (IP identifier) or via redirect from a client-controlled host.
- There is **no** private/link-local/loopback filtering on the dial or on redirect targets (confirmed by repo-wide search).
- Impact does not require challenge success: the outbound request occurs when validation runs.

### Suggested fix direction

- Reject loopback/link-local/private/ULA addresses for ACME identifiers and for http-01 / tls-alpn-01 dial and redirect targets (allowlist public unicast).
- Prefer requiring EAB when enabling ACME on publicly reachable listeners (align storage default with the field schema’s `always-required` documentation).

---

## Near-misses discarded

1. **Cert auth CRL `url` → `http.Get` (`builtin/credential/cert/`)**  
   Real outbound fetch of operator-supplied URL, but requires write capability on `auth/<cert>/crls/*`. Treated as intentional admin-configured fetch, not an unauthenticated/low-priv attack path.

2. **GitHub / Okta / Ping MFA / AWS STS endpoint URLs**  
   Outbound HTTP uses admin-configured `base_url` / `idp_url` / STS endpoint. Login-time client fields do not redirect the TCP destination away from the configured endpoint (AWS rebuilds URL onto configured STS host). Admin SSRF / misconfig, not attacker-driven.

3. **OCSP fetch of `subject.OCSPServer` (`sdk/helper/ocsp/`)**  
   Only runs when OCSP is enabled and the client presents a cert that chains to a trusted CA (or matches a trusted leaf). AIA URLs are CA-controlled in normal PKI; not a practical unauthenticated SSRF without already having a trusted cert path.

4. **MSSQL/MySQL physical backend identifier concatenation**  
   Historical CVE-2023-0620 class; current code validates identifiers (`isInvalidIdentifier` / `validateDBTable`) before interpolating. Config is also host-admin-only at process start.

5. **Database secrets engine `{{username}}` / `{{password}}` SQL templates**  
   By-design privileged role configuration; not injectable by unprivileged API callers without role-write rights.

6. **`api/tokenhelper` `/bin/sh -c` with `BinaryPath`**  
   Shell metacharacters in the helper path would execute, but the path comes from the local Vault CLI config, not a remote API. Out of server attack surface.

7. **Plugin catalog `Command` with `..`**  
   Explicitly rejected; symlink escape checked against configured plugin directory.

8. **File physical backend path traversal**  
   `validatePath` rejects `..`.

9. **CORS `AllowedOrigins: *`**  
   Reflects request Origin when `*` is configured; no `Access-Control-Allow-Credentials: true`. Vault auth is header-token based. Misconfiguration risk, not a validated credential-theft bug by itself.

10. **`X-Vault-Policy-Override`**  
    Sentinel soft-mandatory override (Enterprise); does not bypass ACL allow/deny in OSS.

11. **AppRole secret-id-accessor destroy across roles**  
    CVE-2023-24999 addressed; destroy path verifies accessor belongs to the role (`invalid secret id accessor` → permission denied).

12. **OIDC provider `redirect_uri`**  
    Exact match against registered URIs (with RFC8252 loopback port relaxation only). No open redirect validated.

---

## Search coverage notes

Patterns exercised: `exec.Command` / `os/exec`, `http.Get` / client `Do` with configurable URLs, `InsecureSkipVerify`, template execution into LDAP filters, SQL string building in physical backends and DB plugins, `filepath.Join` / `ReadFile` with user paths, JWT parse paths, CORS, AppRole/CIDR, MFA enforcement, ACME challenge validation.
