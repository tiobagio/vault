# Application Security Review — HashiCorp Vault

**Repo:** tiobagio/vault  
**Commit:** `0513545dd8213ffcbb3406c25cda69cd0a5b0e47`  
**Scope:** Auth methods (`builtin/credential/`), Identity OIDC provider, HTTP layer, Agent/proxy templates, plugin catalog, PKI ACME, secrets in unauthenticated errors  

**Verdict:** One validated Medium finding with a real end-to-end attack path. No Critical findings meeting the bar. Remaining candidates were dismissed as near-misses (documented below).

---

## Validated findings

### 1. OIDC Provider UI open redirect via `prompt=none` (unvalidated `redirect_uri`)

| Field | Detail |
| --- | --- |
| **Severity** | Medium |
| **CWE** | CWE-601 (URL Redirection to Untrusted Site) |
| **Location** | `ui/app/routes/vault/cluster/oidc-provider.js` |

#### Attack path

1. **Attacker:** Unauthenticated remote attacker who can induce a victim to open a Vault UI link (phishing email, chat, etc.). Vault’s OIDC provider UI must be reachable (default in most deployments).
2. **Controlled input:** Query parameters on the UI authorize route, especially `redirect_uri` and `prompt=none`.
3. **Reach:** Victim visits a crafted URL such as:
   ```
   /ui/vault/identity/oidc/provider/<any>/authorize?prompt=none&redirect_uri=https://evil.example/cb&state=attacker-state
   ```
4. **Vulnerable code:** `beforeModel` redirects immediately when the user has no Vault token and `prompt=none`, using the client-supplied `redirect_uri` **without** calling the backend authorize endpoint (which is what enforces the client allow-list).

```31:40:ui/app/routes/vault/cluster/oidc-provider.js
  beforeModel(transition) {
    const currentToken = this.auth.currentTokenName;
    const qp = transition.to.queryParams;
    // remove redirect_to if carried over from auth
    qp.redirect_to = null;
    if (!currentToken && 'none' === qp.prompt?.toLowerCase()) {
      this._redirect(qp.redirect_uri, {
        state: qp.state,
        error: 'login_required',
      });
```

```22:28:ui/app/routes/vault/cluster/oidc-provider.js
  _redirect(url, params) {
    if (!url) return;
    const redir = this._buildUrl(url, params);
    if (Ember.testing) {
      return redir;
    }
    this.win.location.replace(redir);
  }
```

```79:91:ui/app/routes/vault/cluster/oidc-provider.js
  _buildUrl(urlString, params) {
    try {
      const url = new URL(urlString);
      Object.keys(params).forEach((key) => {
        if (params[key]) {
          url.searchParams.append(key, params[key]);
        }
      });
      return url;
    } catch (e) {
      console.debug('DEBUG: parsing url failed for', urlString); // eslint-disable-line
      throw new Error('Invalid URL');
    }
  }
```

Contrast with the authenticated/model path, which correctly relies on server-side allow-list validation:

```1711:1717:vault/identity_store_oidc_provider.go
	// Validate the redirect URI
	redirectURI := d.Get("redirect_uri").(string)
	if redirectURI == "" {
		return authResponse("", state, ErrAuthInvalidRequest, "redirect_uri parameter is required")
	}
	if !validRedirect(redirectURI, client.RedirectURIs) {
		return authResponse("", state, ErrAuthInvalidRedirectURI, "redirect_uri is not allowed for the client")
```

5. **Impact:** Victim’s browser is navigated to an arbitrary attacker URL with `error=login_required` and attacker-controlled `state`. Enables phishing / trust abuse (Vault origin → attacker site). `_buildUrl` does not restrict URL schemes (`javascript:`, `data:` parse successfully via `new URL()`); depending on browser mitigations for `location.replace`, this may additionally enlarge impact beyond classic open redirect.

#### Notes

- Same class of bug as Pocket-ID CVE-2026-55834 (`prompt=none` client-side redirect bypassing backend allow-list).
- No Vault HCSEC/CVE matching this specific UI path was found in this tree’s changelogs.

---

## Near-misses dismissed (did not meet bar)

### A. PKI ACME http-01 SSRF to internal networks

- **Where:** `builtin/logical/pki/acme_challenges.go` (`ValidateHTTP01Challenge`) — GETs `http://<domain>/.well-known/acme-challenge/<token>` with redirect following; no private/link-local IP blocking.
- **Why dismissed:** Documented as an intentional ACME design/security consideration in `website/content/docs/secrets/pki/considerations.mdx` (“ACME security considerations”). Requires an admin to enable ACME. Impact is largely blind SSRF (response body only checked for key authorization). Fits “insecure by design / known ACME validator behavior” rather than an unintended privilege path.

### B. Plugin catalog unsigned / empty SHA-256 registration

- **Where:** `vault/plugincatalog/plugin_catalog.go` `Set`; `sdk/helper/pluginutil/run_config.go` always attaches `SecureConfig` (empty checksum possible). Path `..` is blocked; symlink escape out of plugin directory is checked.
- **Why dismissed:** Registering plugins requires already-privileged `sys/plugins/catalog` access. No escalation from lower privilege. Unsigned/empty SHA is operator misconfiguration, not an unauthenticated/low-priv attack path.

### C. Agent template destination path traversal / SSTI

- **Where:** `command/agent/template/`, consul-template destinations from agent HCL.
- **Why dismissed:** Template source/destination come from local agent config controlled by the host operator, not by remote Vault API callers. No remote attacker input reaches template parse/destination write without already controlling the agent host/config.

### D. Cert auth OCSP URL SSRF

- **Where:** `sdk/helper/ocsp/client.go` uses `subject.OCSPServer` from the presented certificate when overrides are unset.
- **Why dismissed:** Requires OCSP enabled and a cert that already chains to a trusted CA (or is a registered leaf). Leaf AIA URLs are typically CA-controlled; attacker who can mint trusted certs with arbitrary AIA already has a strong position. Treated as residual risk of OCSP, not a clean low-priv E2E vuln.

### E. Identity OIDC `validRedirect` loopback port-agnostic matching

- **Where:** `vault/identity_store_oidc_provider_util.go`
- **Why dismissed:** Matches RFC 8252 §7.3 for loopback only (`localhost` / `127.0.0.1` / `::1`). Non-loopback URIs require exact string match. No open-redirect beyond intended loopback semantics.

### F. HTTP `X-Forwarded-For` / client-cert header trust

- **Where:** `http/handler.go` `WrapForwardedForHandler`
- **Why dismissed:** Only trusts headers when remote addr is in configured `authorized_addrs` (or intentionally non-rejecting). Admin listener config; spoofing requires already being an authorized proxy hop.

### G. Auth method login error enumeration / secret echo

- **Where:** AppRole/userpass use generic “invalid role or secret ID” / “invalid username or password”; LDAP enumeration previously fixed (CVE-2023-3462). AppRole can echo the submitted `secret_id` in one error path — caller already supplied it.
- **Why dismissed:** No validated leak of *server-side* secrets to unauthenticated callers meeting Medium+.

### H. JWT/OIDC *auth method* gaps

- **Why dismissed:** JWT/OIDC auth backends are external plugins (not in this tree under `builtin/credential/`). In-tree Identity OIDC *provider* was reviewed separately (finding #1 is UI-side).

---

## Summary

| ID | Finding | Severity | Status |
| --- | --- | --- | --- |
| 1 | OIDC UI `prompt=none` open redirect (unvalidated `redirect_uri`) | Medium | **Validated** |

No Critical/High privilege-escalation or auth-bypass findings meeting the stated bar were validated in this pass.
