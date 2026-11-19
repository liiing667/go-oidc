package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrLogoutTokenReplay is returned by [IDTokenVerifier.VerifyLogout] when a
// back-channel logout token has already been consumed. It is wrapped, so use
// errors.Is to check for it.
//
// A replay indicates that a previously processed logout token was submitted
// again. The one-time boundary of a logout token is formed by its "jti",
// "iss", and "aud" claims together with the recorded "sub"/"sid" and its
// consumption state. Replays must fail closed: the application must not run
// the logout action a second time.
var ErrLogoutTokenReplay = errors.New("oidc: logout token has already been processed (replay detected)")

// LogoutTokenStore records the one-time consumption of back-channel logout
// tokens. [IDTokenVerifier.VerifyLogout] calls ConsumeLogoutToken only after
// the token's signature, issuer, audience, expiry, and required claims have
// all been validated.
//
// Implementations must be safe for concurrent use. In deployments with more
// than one verifier instance (for example a horizontally scaled gateway),
// back the store with shared state such as Redis or a database so that a
// token replayed against a different instance is still rejected.
//
// Returning a non-nil error fails closed: VerifyLogout rejects the token and
// the logout action is not performed.
type LogoutTokenStore interface {
	// ConsumeLogoutToken atomically records that the given logout token has
	// been consumed. It returns an error wrapping ErrLogoutTokenReplay if the
	// token's one-time boundary was already consumed and is still within its
	// validity window. Any other non-nil error also causes verification to
	// fail.
	ConsumeLogoutToken(ctx context.Context, token *LogoutToken) error
}

// memoryLogoutStoreSweepThreshold bounds the work of the opportunistic sweep
// that removes records whose logout token has expired.
const memoryLogoutStoreSweepThreshold = 1024

// logoutTokenKey identifies the one-time boundary of a logout token from the
// claims that must uniquely scope a "jti": the issuer, the audience, and the
// "jti" itself.
type logoutTokenKey struct {
	issuer   string
	jti      string
	audience string
}

// logoutEvent records the consumption state of a logout token, including the
// "sub"/"sid" claims so a reused "jti" with mismatched session or subject
// claims is rejected rather than silently treated as the same event.
type logoutEvent struct {
	subject    string
	sessionID  string
	consumedAt time.Time
	expiry     time.Time
}

// memoryLogoutStore is the default [LogoutTokenStore]. It keeps consumed
// logout tokens in memory until they expire.
type memoryLogoutStore struct {
	mu     sync.Mutex
	now    func() time.Time
	events map[logoutTokenKey]logoutEvent
}

// NewMemoryLogoutStore returns an in-memory [LogoutTokenStore]. A single
// instance should be shared between the verifiers of one process; verifiers
// created without an explicit store get their own instance automatically.
func NewMemoryLogoutStore() LogoutTokenStore {
	return &memoryLogoutStore{
		now:    time.Now,
		events: make(map[logoutTokenKey]logoutEvent),
	}
}

// newMemoryLogoutStoreWithClock returns an in-memory [LogoutTokenStore] that
// measures expiry with the given clock. It is used for the verifier's default
// store so replay windows use the same notion of time as token expiry checks.
func newMemoryLogoutStoreWithClock(now func() time.Time) LogoutTokenStore {
	if now == nil {
		now = time.Now
	}
	return &memoryLogoutStore{
		now:    now,
		events: make(map[logoutTokenKey]logoutEvent),
	}
}

func newLogoutTokenKey(issuer string, audiences []string, jti string) logoutTokenKey {
	sorted := append([]string(nil), audiences...)
	slices.Sort(sorted)
	return logoutTokenKey{
		issuer:   issuer,
		jti:      jti,
		audience: strings.Join(sorted, "\x00"),
	}
}

func (s *memoryLogoutStore) ConsumeLogoutToken(_ context.Context, token *LogoutToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	key := newLogoutTokenKey(token.Issuer, token.Audience, token.TokenID)

	if previous, ok := s.events[key]; ok {
		// A record whose token has expired no longer provides replay
		// protection, so drop it and allow the new token to be consumed.
		if previous.expiry.IsZero() || !previous.expiry.Before(now) {
			if previous.subject != token.Subject || previous.sessionID != token.SessionID {
				return fmt.Errorf("%w: jti %q reused with mismatched sub/sid claims", ErrLogoutTokenReplay, token.TokenID)
			}
			return fmt.Errorf("%w: jti %q", ErrLogoutTokenReplay, token.TokenID)
		}
		delete(s.events, key)
	}

	s.events[key] = logoutEvent{
		subject:    token.Subject,
		sessionID:  token.SessionID,
		consumedAt: now,
		expiry:     token.Expiry,
	}

	// Opportunistically evict expired records to bound memory usage.
	if len(s.events) > memoryLogoutStoreSweepThreshold {
		for eventKey, event := range s.events {
			if !event.expiry.IsZero() && event.expiry.Before(now) {
				delete(s.events, eventKey)
			}
		}
	}
	return nil
}
