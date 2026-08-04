// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package shamirapi

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
)

func TestHandleSplitAPI(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte("test"))

	resp, err := HandleSplitAPI(&framework.FieldData{
		Raw: map[string]interface{}{
			"input":     input,
			"parts":     5,
			"threshold": 3,
			"format":    "base64",
		},
		Schema: map[string]*framework.FieldSchema{
			"input":     {Type: framework.TypeString},
			"parts":     {Type: framework.TypeInt},
			"threshold": {Type: framework.TypeInt},
			"format":    {Type: framework.TypeString, Default: "base64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsError() {
		t.Fatalf("unexpected error response: %#v", resp)
	}

	shares, ok := resp.Data["shares"].([]string)
	if !ok {
		t.Fatal("expected shares in response")
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	resp, err = HandleSplitAPI(&framework.FieldData{
		Raw: map[string]interface{}{
			"input":     input,
			"parts":     2,
			"threshold": 3,
			"format":    "base64",
		},
		Schema: map[string]*framework.FieldSchema{
			"input":     {Type: framework.TypeString},
			"parts":     {Type: framework.TypeInt},
			"threshold": {Type: framework.TypeInt},
			"format":    {Type: framework.TypeString, Default: "base64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("expected error for invalid parts/threshold")
	}
}

func TestHandleCombineAPI(t *testing.T) {
	input := base64.StdEncoding.EncodeToString([]byte("test"))

	splitResp, err := HandleSplitAPI(&framework.FieldData{
		Raw: map[string]interface{}{
			"input":     input,
			"parts":     5,
			"threshold": 3,
			"format":    "hex",
		},
		Schema: map[string]*framework.FieldSchema{
			"input":     {Type: framework.TypeString},
			"parts":     {Type: framework.TypeInt},
			"threshold": {Type: framework.TypeInt},
			"format":    {Type: framework.TypeString, Default: "base64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if splitResp.IsError() {
		t.Fatalf("unexpected split error: %#v", splitResp)
	}

	shares := splitResp.Data["shares"].([]string)
	combineResp, err := HandleCombineAPI(&framework.FieldData{
		Raw: map[string]interface{}{
			"parts":  []string{shares[0], shares[2], shares[4]},
			"format": "hex",
		},
		Schema: map[string]*framework.FieldSchema{
			"parts":  {Type: framework.TypeStringSlice},
			"format": {Type: framework.TypeString, Default: "base64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if combineResp.IsError() {
		t.Fatalf("unexpected combine error: %#v", combineResp)
	}

	secretHex := combineResp.Data["secret"].(string)
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "test" {
		t.Fatalf("expected secret %q, got %q", "test", secret)
	}
}

func TestHandleCombineAPI_invalid(t *testing.T) {
	resp, err := HandleCombineAPI(&framework.FieldData{
		Raw: map[string]interface{}{
			"parts":  []string{"foo"},
			"format": "base64",
		},
		Schema: map[string]*framework.FieldSchema{
			"parts":  {Type: framework.TypeStringSlice},
			"format": {Type: framework.TypeString, Default: "base64"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Fatal("expected error for single part")
	}
}
