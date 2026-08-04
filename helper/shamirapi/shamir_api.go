// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package shamirapi

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/shamir"
)

const APIMaxBytes = 128 * 1024

func HandleSplitAPI(d *framework.FieldData) (*logical.Response, error) {
	inputB64 := d.Get("input").(string)
	format := d.Get("format").(string)
	parts := d.Get("parts").(int)
	threshold := d.Get("threshold").(int)

	secret, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return logical.ErrorResponse("unable to decode input as base64: %s", err), logical.ErrInvalidRequest
	}

	if len(secret) == 0 {
		return logical.ErrorResponse("input must not be empty"), logical.ErrInvalidRequest
	}

	if len(secret) > APIMaxBytes {
		return logical.ErrorResponse("input must be less than %d bytes", APIMaxBytes), logical.ErrInvalidRequest
	}

	switch format {
	case "hex", "base64":
	default:
		return logical.ErrorResponse("unsupported encoding format %q; must be \"hex\" or \"base64\"", format), nil
	}

	shares, err := shamir.Split(secret, parts, threshold)
	if err != nil {
		return logical.ErrorResponse("failed to split secret: %s", err), nil
	}

	encodedShares := make([]string, len(shares))
	for i, share := range shares {
		switch format {
		case "hex":
			encodedShares[i] = hex.EncodeToString(share)
		case "base64":
			encodedShares[i] = base64.StdEncoding.EncodeToString(share)
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"shares": encodedShares,
		},
	}, nil
}

func HandleCombineAPI(d *framework.FieldData) (*logical.Response, error) {
	encodedParts := d.Get("parts").([]string)
	format := d.Get("format").(string)

	if len(encodedParts) < 2 {
		return logical.ErrorResponse("at least two parts are required"), nil
	}

	switch format {
	case "hex", "base64":
	default:
		return logical.ErrorResponse("unsupported encoding format %q; must be \"hex\" or \"base64\"", format), nil
	}

	decodedParts := make([][]byte, len(encodedParts))
	for i, encodedPart := range encodedParts {
		var part []byte
		var err error
		switch format {
		case "hex":
			part, err = hex.DecodeString(encodedPart)
		case "base64":
			part, err = base64.StdEncoding.DecodeString(encodedPart)
		}
		if err != nil {
			return logical.ErrorResponse("unable to decode part %d: %s", i, err), logical.ErrInvalidRequest
		}
		decodedParts[i] = part
	}

	secret, err := shamir.Combine(decodedParts)
	if err != nil {
		return logical.ErrorResponse("failed to combine parts: %s", err), nil
	}

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(secret)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(secret)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret": retStr,
		},
	}, nil
}
