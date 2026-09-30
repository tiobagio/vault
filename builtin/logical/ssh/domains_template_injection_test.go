// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"testing"

	"github.com/hashicorp/vault/sdk/helper/strutil"
)

// Demonstrates that attacker-controlled identity values rendered into
// allowed_domains (when allowed_domains_template=true) are split on commas
// before host-principal validation — enabling host certificate issuance for
// domains outside the intended template scope when AllowSubdomains is set.
func TestHostDomainsTemplate_CommaInjectionBroadensAllowSubdomains(t *testing.T) {
	// Operator intent: only subdomains of <team>.corp.example.com
	templateRenderedByAttacker := "corp.example.com,x.corp.example.com"
	allowedPrincipals := strutil.RemoveDuplicates(strutil.ParseStringSlice(templateRenderedByAttacker, ","), false)

	role := &sshRole{
		AllowSubdomains:  true,
		AllowBareDomains: false,
	}
	validate := validateValidPrincipalForHosts(role)

	// Attacker requests a host cert for a production hostname under the
	// injected parent domain (not under their intended team prefix).
	target := "prod.corp.example.com"
	if !validate(allowedPrincipals, target) {
		t.Fatalf("expected comma-injected parent domain to allow host principal %q; allowed=%v", target, allowedPrincipals)
	}

	// Baseline without injection: team=eng → eng.corp.example.com only
	baseline := strutil.ParseStringSlice("eng.corp.example.com", ",")
	if validate(baseline, target) {
		t.Fatalf("baseline eng.corp.example.com should NOT allow %q", target)
	}
}

func TestHostDomainsTemplate_CommaInjectionToTLD(t *testing.T) {
	// Template: "{{identity.entity.metadata.ssh_username}}.example.com"
	// Attacker sets metadata to "com,x" → rendered "com,x.example.com"
	rendered := "com,x.example.com"
	allowedPrincipals := strutil.ParseStringSlice(rendered, ",")

	role := &sshRole{AllowSubdomains: true}
	validate := validateValidPrincipalForHosts(role)

	for _, host := range []string{"evil.example.com", "vault.internal.example.com", "a.b.c.example.com"} {
		if !validate(allowedPrincipals, host) {
			t.Fatalf("TLD injection should allow %q via allowed=%v", host, allowedPrincipals)
		}
	}
}
