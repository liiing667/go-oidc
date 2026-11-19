package oidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type logoutTestClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub,omitempty"`
	Audience any            `json:"aud"`
	IAT      int64          `json:"iat"`
	EXP      int64          `json:"exp"`
	JTI      string         `json:"jti"`
	SID      string         `json:"sid,omitempty"`
	Events   map[string]any `json:"events"`
}

func signTestLogoutToken(t *testing.T, key *signingKey, claims logoutTestClaims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling logout claims: %v", err)
	}
	return key.sign(t, payload)
}

func baseLogoutClaims(jti string) logoutTestClaims {
	return logoutTestClaims{
		Issuer:   testLogoutIssuer,
		Subject:  "user-1",
		Audience: testLogoutClientID,
		IAT:      testLogoutIAT,
		EXP:      testLogoutExp,
		JTI:      jti,
		SID:      "sid-1",
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
}

func newOfflineLogoutVerifier(t *testing.T, key *signingKey, config *Config) *IDTokenVerifier {
	t.Helper()
	keySet := &StaticKeySet{PublicKeys: []crypto.PublicKey{key.pub}}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Unix(testLogoutIAT, 0) }
	}
	return NewVerifier(testLogoutIssuer, keySet, config)
}

// TestVerifyLogoutFirstReplayRecovery exercises the fixed offline verifier: a
// token is consumed once, its replay fails closed, and the next legitimate
// logout token is still processed.
func TestVerifyLogoutFirstReplayRecovery(t *testing.T) {
	key := newRSAKey(t)
	verifier := newOfflineLogoutVerifier(t, key, &Config{ClientID: testLogoutClientID})

	first := signTestLogoutToken(t, key, baseLogoutClaims("jti-1"))
	if _, err := verifier.VerifyLogout(t.Context(), first); err != nil {
		t.Fatalf("first VerifyLogout() returned unexpected error: %v", err)
	}

	// Replaying the exact same token must fail closed rather than running the
	// logout action a second time.
	replayed, err := verifier.VerifyLogout(t.Context(), first)
	if err == nil {
		t.Fatalf("replayed VerifyLogout() expected an error, got token: %#v", replayed)
	}
	if !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("replayed VerifyLogout() expected ErrLogoutTokenReplay, got: %v", err)
	}

	// A fresh logout event (new jti) must still be processed.
	next := signTestLogoutToken(t, key, baseLogoutClaims("jti-2"))
	if _, err := verifier.VerifyLogout(t.Context(), next); err != nil {
		t.Fatalf("next VerifyLogout() returned unexpected error: %v", err)
	}

	// The new event is itself one-time.
	if _, err := verifier.VerifyLogout(t.Context(), next); !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("replay of second token expected ErrLogoutTokenReplay, got: %v", err)
	}
}

// TestVerifyLogoutReplayBoundary verifies the one-time boundary is scoped by
// issuer and audience and bound to the sub/sid claims.
func TestVerifyLogoutReplayBoundary(t *testing.T) {
	key := newRSAKey(t)
	verifier := newOfflineLogoutVerifier(t, key, &Config{ClientID: testLogoutClientID})

	// Same jti but a different audience is a distinct one-time boundary.
	otherAudience := baseLogoutClaims("jti-1")
	otherAudience.Audience = []string{testLogoutClientID, "other-client-id"}
	otherAudienceToken := signTestLogoutToken(t, key, otherAudience)
	if _, err := verifier.VerifyLogout(t.Context(), otherAudienceToken); err != nil {
		t.Fatalf("VerifyLogout() with separate audience returned unexpected error: %v", err)
	}

	first := signTestLogoutToken(t, key, baseLogoutClaims("jti-1"))
	if _, err := verifier.VerifyLogout(t.Context(), first); err != nil {
		t.Fatalf("VerifyLogout() returned unexpected error: %v", err)
	}

	// Same jti/iss/aud but mismatched sub/sid claims still fails closed.
	mismatched := baseLogoutClaims("jti-1")
	mismatched.Subject = "user-2"
	mismatched.SID = "sid-2"
	if _, err := verifier.VerifyLogout(t.Context(), signTestLogoutToken(t, key, mismatched)); !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("mismatched sub/sid expected ErrLogoutTokenReplay, got: %v", err)
	}

	// Exact replay of the distinct-audience token is also rejected.
	if _, err := verifier.VerifyLogout(t.Context(), otherAudienceToken); !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("replay with separate audience expected ErrLogoutTokenReplay, got: %v", err)
	}
}

// TestVerifyLogoutReplaySharedStore ensures a replay is detected even when it
// reaches a different verifier instance sharing the same store.
func TestVerifyLogoutReplaySharedStore(t *testing.T) {
	key := newRSAKey(t)
	now := func() time.Time { return time.Unix(testLogoutIAT, 0) }
	store := newMemoryLogoutStoreWithClock(now)

	verifierOne := newOfflineLogoutVerifier(t, key, &Config{
		ClientID:         testLogoutClientID,
		LogoutTokenStore: store,
	})
	verifierTwo := newOfflineLogoutVerifier(t, key, &Config{
		ClientID:         testLogoutClientID,
		LogoutTokenStore: store,
	})

	token := signTestLogoutToken(t, key, baseLogoutClaims("jti-1"))
	if _, err := verifierOne.VerifyLogout(t.Context(), token); err != nil {
		t.Fatalf("first VerifyLogout() returned unexpected error: %v", err)
	}
	if _, err := verifierTwo.VerifyLogout(t.Context(), token); !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("cross-verifier replay expected ErrLogoutTokenReplay, got: %v", err)
	}
}

// TestVerifyLogoutSkipReplayCheck confirms callers that manage replay
// protection themselves can opt out.
func TestVerifyLogoutSkipReplayCheck(t *testing.T) {
	key := newRSAKey(t)
	verifier := newOfflineLogoutVerifier(t, key, &Config{
		ClientID:                   testLogoutClientID,
		SkipLogoutTokenReplayCheck: true,
	})
	if verifier.logoutStore != nil {
		t.Fatalf("expected no logout store when SkipLogoutTokenReplayCheck is set")
	}

	token := signTestLogoutToken(t, key, baseLogoutClaims("jti-1"))
	if _, err := verifier.VerifyLogout(t.Context(), token); err != nil {
		t.Fatalf("first VerifyLogout() returned unexpected error: %v", err)
	}
	if _, err := verifier.VerifyLogout(t.Context(), token); err != nil {
		t.Fatalf("replayed VerifyLogout() with check skipped returned unexpected error: %v", err)
	}
}

// TestVerifyLogoutStoreErrorFailsClosed ensures any store error rejects the
// token rather than allowing the logout to proceed.
func TestVerifyLogoutStoreErrorFailsClosed(t *testing.T) {
	key := newRSAKey(t)
	storeErr := errors.New("store unavailable")
	verifier := newOfflineLogoutVerifier(t, key, &Config{
		ClientID:         testLogoutClientID,
		LogoutTokenStore: failingLogoutStore{err: storeErr},
	})

	token := signTestLogoutToken(t, key, baseLogoutClaims("jti-1"))
	if _, err := verifier.VerifyLogout(t.Context(), token); !errors.Is(err, storeErr) {
		t.Fatalf("expected store error %v, got: %v", storeErr, err)
	}
}

type failingLogoutStore struct{ err error }

func (s failingLogoutStore) ConsumeLogoutToken(context.Context, *LogoutToken) error {
	return s.err
}

// TestVerifyLogoutInvalidTokenNotRecorded ensures tokens that fail earlier
// validation never reach the store, so their jti is not consumed.
func TestVerifyLogoutInvalidTokenNotRecorded(t *testing.T) {
	key := newRSAKey(t)
	store := &countingLogoutStore{}
	verifier := newOfflineLogoutVerifier(t, key, &Config{
		ClientID:         testLogoutClientID,
		LogoutTokenStore: store,
	})

	unknownKey := newRSAKey(t)
	token := signTestLogoutToken(t, unknownKey, baseLogoutClaims("jti-1"))
	if _, err := verifier.VerifyLogout(t.Context(), token); err == nil {
		t.Fatalf("expected signature validation failure")
	}
	if store.calls != 0 {
		t.Fatalf("expected no store consumption for an invalid token, got %d calls", store.calls)
	}
}

type countingLogoutStore struct {
	calls int
}

func (s *countingLogoutStore) ConsumeLogoutToken(context.Context, *LogoutToken) error {
	s.calls++
	return nil
}

// TestMemoryLogoutStoreExpiryEviction verifies that an expired record no
// longer blocks consumption, so legitimate later logout events still succeed.
func TestMemoryLogoutStoreExpiryEviction(t *testing.T) {
	now := time.Unix(testLogoutIAT, 0)
	expiry := time.Unix(testLogoutExp, 0)
	store := &memoryLogoutStore{
		now:    func() time.Time { return now },
		events: make(map[logoutTokenKey]logoutEvent),
	}

	token := &LogoutToken{
		Issuer:    testLogoutIssuer,
		Subject:   "user-1",
		Audience:  []string{testLogoutClientID},
		TokenID:   "jti-1",
		SessionID: "sid-1",
		Expiry:    expiry,
	}

	if err := store.ConsumeLogoutToken(t.Context(), token); err != nil {
		t.Fatalf("first ConsumeLogoutToken() returned unexpected error: %v", err)
	}
	if err := store.ConsumeLogoutToken(t.Context(), token); !errors.Is(err, ErrLogoutTokenReplay) {
		t.Fatalf("replay expected ErrLogoutTokenReplay, got: %v", err)
	}

	// After the token expires the boundary no longer blocks new consumption.
	now = expiry.Add(time.Second)
	if err := store.ConsumeLogoutToken(t.Context(), token); err != nil {
		t.Fatalf("ConsumeLogoutToken() after expiry returned unexpected error: %v", err)
	}
}
