package oidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// verifyResult is the fixed comparison shape for a verification outcome:
// the error category, the JWKS HTTP status (when relevant), whether the same
// request is retryable, and whether a usable identity leaked on failure.
type verifyResult struct {
	kind         ErrorKind
	statusCode   int
	retryable    bool
	identityLeak bool
}

func TestVerifyErrorClassification(t *testing.T) {
	key := newRSAKey(t)

	tests := []struct {
		name   string
		token  string
		config Config
		// keySet builds the key set used by the verifier. When nil a static
		// key set containing signKey is used.
		keySet func() KeySet
		want   verifyResult
	}{
		{
			name:  "invalid signature is terminal and unclassified as claims",
			token: key.sign(t, []byte(`{"iss":"https://foo"}`)),
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			keySet: func() KeySet {
				return &StaticKeySet{PublicKeys: []crypto.PublicKey{newRSAKey(t).pub}}
			},
			want: verifyResult{
				kind:      KindInvalidSignature,
				retryable: false,
			},
		},
		{
			name:  "malformed jwt is terminal",
			token: "not-a-jwt",
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			want: verifyResult{
				kind:      KindMalformedToken,
				retryable: false,
			},
		},
		{
			name:  "issuer mismatch is an invalid-claims terminal error",
			token: key.sign(t, []byte(`{"iss":"https://evil"}`)),
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			want: verifyResult{
				kind:      KindInvalidClaims,
				retryable: false,
			},
		},
		{
			name:  "audience mismatch is an invalid-claims terminal error",
			token: key.sign(t, []byte(`{"iss":"https://foo","aud":"other"}`)),
			config: Config{
				ClientID:        "client1",
				SkipExpiryCheck: true,
			},
			want: verifyResult{
				kind:      KindInvalidClaims,
				retryable: false,
			},
		},
		{
			name: "expired token is its own non-retryable category",
			token: key.sign(t, []byte(`{"iss":"https://foo","exp":`+
				strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)+`}`)),
			config: Config{
				SkipClientIDCheck: true,
			},
			want: verifyResult{
				kind:      KindExpired,
				retryable: false,
			},
		},
		{
			name:  "missing client id is a configuration error",
			token: key.sign(t, []byte(`{"iss":"https://foo"}`)),
			config: Config{
				SkipExpiryCheck: true,
			},
			want: verifyResult{
				kind:      KindConfiguration,
				retryable: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var ks KeySet
			if test.keySet != nil {
				ks = test.keySet()
			} else {
				ks = &StaticKeySet{PublicKeys: []crypto.PublicKey{key.pub}}
			}
			verifier := NewVerifier("https://foo", ks, &test.config)

			tok, err := verifier.Verify(t.Context(), test.token)
			if err == nil {
				t.Fatal("expected verification to fail, got nil error")
			}
			assertVerifyResult(t, err, tok != nil, test.want)
		})
	}
}

func TestVerifyRemoteKeySetStatusAndRetry(t *testing.T) {
	key := newRSAKey(t)
	raw := key.sign(t, []byte(`{"iss":"https://foo"}`))

	t.Run("JWKS 503 is retryable and carries the status code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		verifier := NewVerifier("https://foo", NewRemoteKeySet(t.Context(), srv.URL), &Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		})

		tok, err := verifier.Verify(t.Context(), raw)
		if err == nil {
			t.Fatal("expected verification to fail, got nil error")
		}
		assertVerifyResult(t, err, tok != nil, verifyResult{
			kind:       KindRemoteKeySet,
			statusCode: http.StatusServiceUnavailable,
			retryable:  true,
		})
	})

	t.Run("JWKS network failure is retryable without a status code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // force connection errors

		verifier := NewVerifier("https://foo", NewRemoteKeySet(t.Context(), srv.URL), &Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		})

		tok, err := verifier.Verify(t.Context(), raw)
		if err == nil {
			t.Fatal("expected verification to fail, got nil error")
		}
		assertVerifyResult(t, err, tok != nil, verifyResult{
			kind:       KindRemoteKeySet,
			statusCode: 0,
			retryable:  true,
		})
	})

	t.Run("retried verification succeeds once the JWKS recovers", func(t *testing.T) {
		healthy := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-healthy:
				w.Header().Set("Content-Type", "application/json")
				_ = writeKeySet(w, key)
			default:
				http.Error(w, "starting", http.StatusBadGateway)
			}
		}))
		defer srv.Close()

		verifier := NewVerifier("https://foo", NewRemoteKeySet(t.Context(), srv.URL), &Config{
			SkipClientIDCheck: true,
			SkipExpiryCheck:   true,
		})

		if _, err := verifier.Verify(t.Context(), raw); err == nil {
			t.Fatal("expected first verification to fail while the JWKS is down")
		} else if !IsRetryable(err) {
			t.Fatalf("expected a retryable JWKS error, got %v", err)
		}

		close(healthy)

		tok, err := verifier.Verify(t.Context(), raw)
		if err != nil {
			t.Fatalf("expected retried verification to succeed, got %v", err)
		}
		if tok == nil {
			t.Fatal("expected a usable identity after successful verification")
		}
	})
}

func TestVerifyCanceledIsRetryable(t *testing.T) {
	key := newRSAKey(t)
	raw := key.sign(t, []byte(`{"iss":"https://foo"}`))

	// Block the JWKS request until the context is canceled.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	verifier := NewVerifier("https://foo", NewRemoteKeySet(t.Context(), srv.URL), &Config{
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	})

	tok, err := verifier.Verify(ctx, raw)
	if err == nil {
		t.Fatal("expected verification to fail after cancellation")
	}
	assertVerifyResult(t, err, tok != nil, verifyResult{
		kind:      KindCanceled,
		retryable: true,
	})
}

func TestVerifySentinelsAndExpiry(t *testing.T) {
	key := newRSAKey(t)

	t.Run("terminal categories match their sentinels", func(t *testing.T) {
		cases := []struct {
			name     string
			token    string
			config   Config
			sentinel error
			kind     ErrorKind
		}{
			{
				name:     "malformed",
				token:    "garbage",
				config:   Config{SkipClientIDCheck: true, SkipExpiryCheck: true},
				sentinel: ErrMalformedToken,
				kind:     KindMalformedToken,
			},
			{
				name:  "bad signature",
				token: key.sign(t, []byte(`{"iss":"https://foo"}`)),
				config: Config{
					SkipClientIDCheck: true,
					SkipExpiryCheck:   true,
				},
				sentinel: ErrInvalidSignature,
				kind:     KindInvalidSignature,
			},
			{
				name:     "bad claims",
				token:    key.sign(t, []byte(`{"iss":"https://other"}`)),
				config:   Config{SkipClientIDCheck: true, SkipExpiryCheck: true},
				sentinel: ErrInvalidClaims,
				kind:     KindInvalidClaims,
			},
			{
				name:     "bad config",
				token:    key.sign(t, []byte(`{"iss":"https://foo"}`)),
				config:   Config{SkipExpiryCheck: true},
				sentinel: ErrInvalidConfiguration,
				kind:     KindConfiguration,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var ks KeySet
				if tc.sentinel == ErrInvalidSignature {
					ks = &StaticKeySet{PublicKeys: []crypto.PublicKey{newRSAKey(t).pub}}
				} else {
					ks = &StaticKeySet{PublicKeys: []crypto.PublicKey{key.pub}}
				}
				verifier := NewVerifier("https://foo", ks, &tc.config)

				_, err := verifier.Verify(t.Context(), tc.token)
				if !errors.Is(err, tc.sentinel) {
					t.Errorf("expected errors.Is to match %v, got %v", tc.sentinel, err)
				}
				if got := ErrorKindOf(err); got != tc.kind {
					t.Errorf("expected kind %s, got %s", tc.kind, got)
				}
				if IsRetryable(err) {
					t.Errorf("terminal error %s must not be retryable", tc.kind)
				}
			})
		}
	})

	t.Run("expired token remains a TokenExpiredError and is non-retryable", func(t *testing.T) {
		raw := key.sign(t, []byte(`{"iss":"https://foo","exp":`+
			strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)+`}`))
		verifier := NewVerifier("https://foo",
			&StaticKeySet{PublicKeys: []crypto.PublicKey{key.pub}},
			&Config{SkipClientIDCheck: true})

		_, err := verifier.Verify(t.Context(), raw)
		var expired *TokenExpiredError
		if !errors.As(err, &expired) {
			t.Fatalf("expected *TokenExpiredError, got %v", err)
		}
		if ErrorKindOf(err) != KindExpired || IsRetryable(err) {
			t.Fatalf("expired token must be KindExpired and non-retryable, got kind %s", ErrorKindOf(err))
		}
	})
}

func TestErrorKindOfNilAndForeignErrors(t *testing.T) {
	if got := ErrorKindOf(nil); got != KindUnspecified {
		t.Errorf("nil error must map to KindUnspecified, got %s", got)
	}
	if IsRetryable(nil) {
		t.Error("nil error must not be retryable")
	}
	if got := ErrorKindOf(errors.New("foreign")); got != KindUnspecified {
		t.Errorf("foreign error must map to KindUnspecified, got %s", got)
	}
}

// assertVerifyResult pins the complete verification outcome against the fixed
// expectation: category, JWKS status code, the caller's next step, and the
// guarantee that no identity is returned on failure.
func assertVerifyResult(t *testing.T, err error, identityLeaked bool, want verifyResult) {
	t.Helper()

	if identityLeaked {
		t.Error("a failed verification returned a non-nil token; no identity must be usable on failure")
	}
	if got := ErrorKindOf(err); got != want.kind {
		t.Errorf("error kind: want %s, got %s (err: %v)", want.kind, got, err)
	}
	if got := IsRetryable(err); got != want.retryable {
		t.Errorf("retryable: want %v, got %v (err: %v)", want.retryable, got, err)
	}

	var remoteErr *RemoteKeySetError
	gotStatus := 0
	if errors.As(err, &remoteErr) {
		gotStatus = remoteErr.StatusCode
	}
	if gotStatus != want.statusCode {
		t.Errorf("jwks status code: want %d, got %d (err: %v)", want.statusCode, gotStatus, err)
	}
}

func writeKeySet(w http.ResponseWriter, key *signingKey) error {
	type jwkSet struct {
		Keys []any `json:"keys"`
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(jwkSet{Keys: []any{key.jwk()}})
}
