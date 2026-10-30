package vault

import (
	"testing"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
)

// Proof: identity entity/group writes reject only the exact string "root", while
// request-time SanitizePolicies lowercases/trims and collapses ROOT-like values
// into the real built-in root policy.
func TestProof_IdentityRootPolicyCaseBypass(t *testing.T) {
	// Case variants bypass both entity and group writes (exact "root" check only).
	for _, input := range []string{"ROOT", "Root", "RoOt"} {
		t.Run("case/"+input, func(t *testing.T) {
			storedEntity := strutil.RemoveDuplicates([]string{input}, false)
			if strutil.StrListContains(storedEntity, "root") {
				t.Fatalf("entity write check unexpectedly blocked %q (stored=%v)", input, storedEntity)
			}
			sanitized := policyutil.SanitizePolicies(append([]string{"default"}, storedEntity...), false)
			if len(sanitized) != 1 || sanitized[0] != "root" {
				t.Fatalf("entity path: SanitizePolicies(%v)=%v, want [root]", storedEntity, sanitized)
			}

			storedGroup := strutil.RemoveDuplicatesStable([]string{input}, true)
			if strutil.StrListContains(storedGroup, "root") {
				t.Fatalf("group write check unexpectedly blocked %q (stored=%v)", input, storedGroup)
			}
			sanitized = policyutil.SanitizePolicies(append([]string{"default"}, storedGroup...), false)
			if len(sanitized) != 1 || sanitized[0] != "root" {
				t.Fatalf("group path: SanitizePolicies(%v)=%v, want [root]", storedGroup, sanitized)
			}
		})
	}

	// Whitespace variant: entity RemoveDuplicates trims → becomes exact "root" and IS blocked.
	// Group RemoveDuplicatesStable preserves original spacing → bypasses the exact check.
	t.Run("spaced-root/entity-blocked-group-bypass", func(t *testing.T) {
		storedEntity := strutil.RemoveDuplicates([]string{" root "}, false)
		if !strutil.StrListContains(storedEntity, "root") {
			t.Fatalf("entity path should trim to root and be blocked; stored=%v", storedEntity)
		}

		storedGroup := strutil.RemoveDuplicatesStable([]string{" root "}, true)
		if strutil.StrListContains(storedGroup, "root") {
			t.Fatalf("group path should preserve %q and bypass exact check; stored=%v", " root ", storedGroup)
		}
		sanitized := policyutil.SanitizePolicies(append([]string{"default"}, storedGroup...), false)
		if len(sanitized) != 1 || sanitized[0] != "root" {
			t.Fatalf("group spaced root: SanitizePolicies(%v)=%v, want [root]", storedGroup, sanitized)
		}
	})

	// Exact "root" is correctly rejected by the identity write check.
	if !strutil.StrListContains([]string{"root"}, "root") {
		t.Fatal("control: exact root should match StrListContains")
	}
	if policyutil.SanitizePolicies([]string{"ROOT"}, false)[0] != "root" {
		t.Fatal("control: SanitizePolicies must lowercase ROOT")
	}
}

// Proof: ACL identity templating substitutes attacker-influenced metadata
// verbatim; '+' becomes a segment wildcard and '/' escapes the intended path segment.
func TestProof_ACLTemplateWildcardAndSlashInjection(t *testing.T) {
	plusPolicy, err := parseACLPolicyWithTemplating(namespace.RootNamespace, `
path "kv/data/{{identity.entity.metadata.department}}/*" {
  capabilities = ["read"]
}
`, true, &identity.Entity{
		ID:   "e1",
		Name: "attacker",
		Metadata: map[string]string{
			"department": "+",
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plusPolicy.Paths) != 1 {
		t.Fatalf("expected 1 path, got %+v", plusPolicy.Paths)
	}
	if plusPolicy.Paths[0].Path != "kv/data/+/*" {
		t.Fatalf("rendered path=%q", plusPolicy.Paths[0].Path)
	}
	if !plusPolicy.Paths[0].HasSegmentWildcards {
		t.Fatal("expected HasSegmentWildcards for injected '+'")
	}

	slashPolicy, err := parseACLPolicyWithTemplating(namespace.RootNamespace, `
path "kv/data/{{identity.entity.aliases.approle_abc.metadata.team}}/*" {
  capabilities = ["read"]
}
`, true, &identity.Entity{
		ID:   "e1",
		Name: "attacker",
		Aliases: []*identity.Alias{{
			MountAccessor: "approle_abc",
			Name:          "role-id",
			Metadata: map[string]string{
				"team": "finance/admin",
			},
		}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(slashPolicy.Paths) != 1 {
		t.Fatalf("expected 1 path, got %+v", slashPolicy.Paths)
	}
	// Trailing '*' is consumed as IsPrefix when no '+', leaving a multi-segment
	// prefix under kv/data/ — escaping the intended single metadata segment.
	if slashPolicy.Paths[0].Path != "kv/data/finance/admin/" || !slashPolicy.Paths[0].IsPrefix {
		t.Fatalf("slash-injected path=%q isPrefix=%v", slashPolicy.Paths[0].Path, slashPolicy.Paths[0].IsPrefix)
	}

	// Baseline: normal department stays a single literal segment (no wildcards).
	base, err := parseACLPolicyWithTemplating(namespace.RootNamespace, `
path "kv/data/{{identity.entity.metadata.department}}/*" {
  capabilities = ["read"]
}
`, true, &identity.Entity{
		ID:       "e1",
		Name:     "user",
		Metadata: map[string]string{"department": "engineering"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if base.Paths[0].HasSegmentWildcards || !base.Paths[0].IsPrefix || base.Paths[0].Path != "kv/data/engineering/" {
		t.Fatalf("baseline path unexpected: %+v", base.Paths[0])
	}
}

// Proof: NewACL treats the sanitized built-in root policy name as full root.
func TestProof_NewACLRootFromSanitizedName(t *testing.T) {
	ctx := namespace.RootContext(nil)
	acl, err := NewACL(ctx, []*Policy{{
		Name:      "root",
		Type:      PolicyTypeACL,
		namespace: namespace.RootNamespace,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !acl.root {
		t.Fatal("expected ACL root=true for policy named root")
	}
}
