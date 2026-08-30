// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/logical"
)

// Demonstrates that attacker-controlled identity metadata can inject ACL
// segment wildcards when rendered into templated policy paths.
func TestACLTemplatedPolicy_WildcardInjectionViaMetadata(t *testing.T) {
	ns := namespace.RootNamespace
	ctx := namespace.RootContext(context.Background())
	rules := `
path "kv/data/{{identity.entity.metadata.department}}/*" {
  capabilities = ["read"]
}
`
	// Baseline: department=engineering should only allow kv/data/engineering/*
	entityOK := &identity.Entity{
		ID:          "e1",
		Name:        "user1",
		NamespaceID: namespace.RootNamespaceID,
		Metadata:    map[string]string{"department": "engineering"},
	}
	pOK, err := parseACLPolicyWithTemplating(ns, rules, true, entityOK, nil)
	if err != nil {
		t.Fatal(err)
	}
	aclOK, err := NewACL(ctx, []*Policy{pOK})
	if err != nil {
		t.Fatal(err)
	}
	res := aclOK.AllowOperation(ctx, &logical.Request{Path: "kv/data/engineering/secret", Operation: logical.ReadOperation}, false)
	if !res.Allowed {
		t.Fatal("expected engineering path allowed")
	}
	res = aclOK.AllowOperation(ctx, &logical.Request{Path: "kv/data/finance/secret", Operation: logical.ReadOperation}, false)
	if res.Allowed {
		t.Fatal("expected finance path denied for engineering user")
	}

	// Attack: department="+" injects segment wildcard → matches any department
	entityAtk := &identity.Entity{
		ID:          "e2",
		Name:        "attacker",
		NamespaceID: namespace.RootNamespaceID,
		Metadata:    map[string]string{"department": "+"},
	}
	pAtk, err := parseACLPolicyWithTemplating(ns, rules, true, entityAtk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pAtk.Paths) != 1 || !pAtk.Paths[0].HasSegmentWildcards {
		t.Fatalf("expected segment wildcard path, got %#v", pAtk.Paths)
	}
	aclAtk, err := NewACL(ctx, []*Policy{pAtk})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"kv/data/engineering/secret", "kv/data/finance/secret", "kv/data/admin/secret"} {
		res = aclAtk.AllowOperation(ctx, &logical.Request{Path: path, Operation: logical.ReadOperation}, false)
		if !res.Allowed {
			t.Fatalf("wildcard injection failed to allow path %q", path)
		}
	}
}

func TestACLTemplatedPolicy_PrefixGlobInjectionViaAliasName(t *testing.T) {
	ns := namespace.RootNamespace
	ctx := namespace.RootContext(context.Background())
	// Common pattern: scope secrets to alias name (e.g. JWT user_claim)
	rules := `
path "kv/data/{{identity.entity.aliases.auth_jwt_abc.name}}" {
  capabilities = ["read"]
}
`
	entityAtk := &identity.Entity{
		ID:          "e6",
		Name:        "entity",
		NamespaceID: namespace.RootNamespaceID,
		Aliases: []*identity.Alias{{
			Name:          "team-a*",
			MountAccessor: "auth_jwt_abc",
			NamespaceID:   namespace.RootNamespaceID,
		}},
	}
	pAtk, err := parseACLPolicyWithTemplating(ns, rules, true, entityAtk, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pAtk.Paths) != 1 || !pAtk.Paths[0].IsPrefix {
		t.Fatalf("expected prefix path from alias name ending in *, got %#v", pAtk.Paths)
	}
	aclAtk, err := NewACL(ctx, []*Policy{pAtk})
	if err != nil {
		t.Fatal(err)
	}
	res := aclAtk.AllowOperation(ctx, &logical.Request{Path: "kv/data/team-a/admin-secret", Operation: logical.ReadOperation}, false)
	if !res.Allowed {
		t.Fatal("alias-name prefix glob injection should allow child paths under kv/data/team-a/")
	}
}
