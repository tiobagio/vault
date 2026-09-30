// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pki

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAcmeHTTP01_SSRF_Characteristics documents and validates SSRF-relevant
// behavior of ValidateHTTP01Challenge for security review. It is not a
// product regression gate for intended ACME protocol behavior.
func TestAcmeHTTP01_SSRF_Characteristics(t *testing.T) {
	t.Parallel()

	t.Run("follows_redirect_to_different_host_without_private_ip_check", func(t *testing.T) {
		t.Parallel()

		var internalHits atomic.Int64
		internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			internalHits.Add(1)
			// Return a body that fails key authorization so we get a
			// validation error rather than success.
			_, _ = w.Write([]byte("not-the-expected-key-authz"))
		}))
		t.Cleanup(internal.Close)

		// Attacker-controlled challenge host redirects to an internal target.
		external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, internal.URL+"/.well-known/acme-challenge/tok", http.StatusFound)
		}))
		t.Cleanup(external.Close)

		host := strings.TrimPrefix(external.URL, "http://")
		ok, err := ValidateHTTP01Challenge(host, "tok", "thumb", &acmeConfigEntry{})
		require.False(t, ok)
		require.Error(t, err)
		require.GreaterOrEqual(t, internalHits.Load(), int64(1),
			"http-01 must have followed redirect to internal host (SSRF)")
	})

	t.Run("error_detail_includes_fetch_failure_not_body", func(t *testing.T) {
		t.Parallel()

		// Closed listener => connection refused with host:port in the error.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		ok, err := ValidateHTTP01Challenge(addr, "tok", "thumb", &acmeConfigEntry{})
		require.False(t, ok)
		require.Error(t, err)

		msg := err.Error()
		require.Contains(t, msg, "http-01: failed to fetch path")
		require.Contains(t, msg, addr, "error should identify the destination address")
		require.True(t,
			strings.Contains(msg, "connection refused") ||
				strings.Contains(msg, "connect:") ||
				strings.Contains(msg, "dial tcp"),
			"expected connection-level error detail, got: %s", msg)

		// Body is never part of the error path here (connection never succeeded).
		require.NotContains(t, msg, "SECRET")
	})

	t.Run("response_body_not_reflected_in_error", func(t *testing.T) {
		t.Parallel()

		secret := "INTERNAL_METADATA_SECRET_VALUE_SHOULD_NOT_LEAK"
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, secret)
		}))
		t.Cleanup(ts.Close)

		host := strings.TrimPrefix(ts.URL, "http://")
		ok, err := ValidateHTTP01Challenge(host, "tok", "thumb", &acmeConfigEntry{})
		require.False(t, ok)
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret,
			"response body must not appear in challenge validation errors")

		// Size-related errors may leak length but not content.
		translated := TranslateErrorToErrorResponse(fmt.Errorf("%w: %v", ErrIncorrectResponse, err))
		require.NotContains(t, translated.Detail, secret)
		require.Equal(t, ErrorPrefix+"incorrectResponse", translated.Type)
	})

	t.Run("status_code_not_included_in_error", func(t *testing.T) {
		t.Parallel()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("tok.thumb"))
		}))
		t.Cleanup(ts.Close)

		host := strings.TrimPrefix(ts.URL, "http://")
		// Status is ignored; matching key auth still validates successfully.
		ok, err := ValidateHTTP01Challenge(host, "tok", "thumb", &acmeConfigEntry{})
		require.True(t, ok, "unexpected: status codes are not checked before body validation")
		require.NoError(t, err)
	})

	t.Run("ip_literal_identifier_is_fetched_directly", func(t *testing.T) {
		t.Parallel()

		var hits atomic.Int64
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		srv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("wrong"))
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go srv.Serve(ln)
		t.Cleanup(func() { _ = srv.Close() })

		addr := ln.Addr().String() // 127.0.0.1:port
		ok, err := ValidateHTTP01Challenge(addr, "tok", "thumb", &acmeConfigEntry{})
		require.False(t, ok)
		require.Error(t, err)
		require.GreaterOrEqual(t, hits.Load(), int64(1),
			"IP literal must be dialed directly (loopback SSRF surface)")
	})

	t.Run("challenge_error_detail_propagates_via_TranslateErrorToErrorResponse", func(t *testing.T) {
		t.Parallel()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		_, fetchErr := ValidateHTTP01Challenge(addr, "tok", "thumb", &acmeConfigEntry{})
		require.Error(t, fetchErr)

		wrapped := fmt.Errorf("%w: error validating http-01 challenge id: %v; attempt failed", ErrIncorrectResponse, fetchErr)
		resp := TranslateErrorToErrorResponse(wrapped)
		stored := resp.MarshalForStorage()

		detail, _ := stored["detail"].(string)
		require.Contains(t, detail, addr)
		require.Contains(t, detail, "failed to fetch path")
		// This stored map is what NetworkMarshal exposes on challenge.error.
	})
}
