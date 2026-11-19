package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// LogoutToken represents a verified token from a Back-Channel Logout. Use
// [IDTokenVerifier.VerifyLogout] within a POST handler to receive and validate
// a token.
//
// See the ./example/logout at the top-level of this repo for a full example
// application.
type LogoutToken struct {
	// The required token ID claim ("jti"). When processing this token for
	// logout, applications should validate that no recent token with the same
	// value has been processed. LogoutReplayCache provides an in-memory
	// implementation of this replay protection.
	TokenID string
	// The unique identifier of the user that this logout token is for. This
	// will match the subject value of the ID Token.
	//
	// If not set, SessionID will be.
	Subject string

	// The "iss" claim. This is validated against the provider URL unless
	// explicitly skipped through SkipIssuerCheck.
	Issuer string
	// The Client ID this logout token is for. Validated against the config
	// unless SkipClientIDCheck is provided.
	Audience []string
	// When this token was issued.
	IssuedAt time.Time
	// When this token expires. Validated unless SkipExpiryCheck is provided.
	Expiry time.Time
	// Optional session ID claim ("sid").
	//
	// The exact semantics of session IDs vary between identity providers. Use
	// your provider's documentation to determine what this correlates to and
	// how it should be handled.
	SessionID string

	claims []byte
}

// Claims unmarshals the raw JSON payload of the Logout Token into a provided
// struct. This can be used to access field not exposed by the LogoutToken
// fields.
//
//	logoutToken, err := idTokenVerifier.VerifyLogout(ctx, rawLogoutToken)
//	if err != nil{
//		// ...
//	}
//	var claims struct {
//		TraceID string `json:"trace_id"`
//	}
//	if err := logoutToken.Claims(&claims); err != nil {
//		// ...
//	}
func (l *LogoutToken) Claims(v any) error {
	if l.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(l.claims, v)
}

// https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
type logoutTokenJSON struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   jsonTime `json:"exp"`
	IssuedAt jsonTime `json:"iat"`
	JTI      string   `json:"jti"`
	Events   struct {
		Logout json.RawMessage `json:"http://schemas.openid.net/event/backchannel-logout"`
	}
	SessionID string `json:"sid"`
	// Nonce is parsed as a raw message so its mere presence can be detected.
	// The spec requires logout tokens to not contain a nonce claim, regardless
	// of its value.
	Nonce json.RawMessage `json:"nonce"`
}

// VerifyLogout validates a back-channel logout token. Logout tokens are
// received by the relying party (this package) from the identity provider at a
// preconfigured "backchannel_logout_uri" through a POST. Then on certain
// events, such as RP-Initiated Logout, the identity provider will send a signed
// token indicating that sessions for a specific user should be terminated.
//
// To support back-channel logout within your app, register a POST endpoint and
// verify the token:
//
//	oidcConfig := &oidc.Config{
//		ClientID: clientID,
//	}
//	verifier := provider.Verifier(oidcConfig)
//
//	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
//		rawLogoutToken := r.PostFormValue("logout_token")
//		if rawLogoutToken == "" {
//			// ...
//		}
//		logoutToken, err := verifier.VerifyLogout(r.Context(), rawLogoutToken)
//		if err != nil {
//			// ...
//		}
//		// Use fields in the logoutToken to determine what sessions to
//		// terminate.
//
//	})
//
// Back-channel logout spec: https://openid.net/specs/openid-connect-backchannel-1_0.html
//
// RP-initiated logout spec: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
func (v *IDTokenVerifier) VerifyLogout(ctx context.Context, rawLogoutToken string) (*LogoutToken, error) {
	payload, _, err := v.verifyJWT(ctx, rawLogoutToken)
	if err != nil {
		return nil, err
	}
	var logoutToken logoutTokenJSON
	if err := json.Unmarshal(payload, &logoutToken); err != nil {
		return nil, fmt.Errorf("oidc: parsing logout token payload: %v", err)
	}

	if len(logoutToken.Events.Logout) == 0 {
		return nil, fmt.Errorf("oidc: logout token missing required http://schemas.openid.net/event/backchannel-logout event")
	}

	// A logout token MUST NOT contain a nonce claim. This prevents an ID token
	// from being replayed as a logout token.
	if len(logoutToken.Nonce) != 0 {
		return nil, fmt.Errorf("oidc: logout token must not contain a 'nonce' claim")
	}

	t := &LogoutToken{
		Issuer:    logoutToken.Issuer,
		Subject:   logoutToken.Subject,
		Audience:  logoutToken.Audience,
		IssuedAt:  time.Time(logoutToken.IssuedAt),
		Expiry:    time.Time(logoutToken.Expiry),
		SessionID: logoutToken.SessionID,
		TokenID:   logoutToken.JTI,
		claims:    payload,
	}
	if t.TokenID == "" {
		return nil, fmt.Errorf("oidc: logout token missing required claim 'jti'")
	}
	if t.Expiry.IsZero() {
		return nil, fmt.Errorf("oidc: logout token must contain an 'exp' claim")
	}

	// A logout token MUST contain a 'sub' claim, a 'sid' claim, or both.
	if t.Subject == "" && t.SessionID == "" {
		return nil, fmt.Errorf("oidc: logout token must contain a 'sub' claim, a 'sid' claim, or both")
	}

	if !v.config.SkipIssuerCheck && t.Issuer != v.issuer {
		return nil, fmt.Errorf("oidc: logout token issued by a different provider, expected %q, got %q", v.issuer, t.Issuer)
	}

	if !v.config.SkipClientIDCheck {
		if v.config.ClientID != "" {
			if !slices.Contains(t.Audience, v.config.ClientID) {
				return nil, fmt.Errorf("oidc: expected logout token audience %q got %q", v.config.ClientID, t.Audience)
			}
		} else {
			return nil, fmt.Errorf("oidc: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
		}
	}

	// If a SkipExpiryCheck is false, make sure token is not expired.
	if !v.config.SkipExpiryCheck {
		now := time.Now
		if v.config.Now != nil {
			now = v.config.Now
		}
		nowTime := now()

		if t.Expiry.Before(nowTime) {
			return nil, &TokenExpiredError{Expiry: t.Expiry}
		}
	}
	return t, nil
}

// ErrLogoutTokenReplayed is returned by LogoutReplayCache.Consume when a
// logout token describes an event that has already been consumed.
var ErrLogoutTokenReplayed = errors.New("oidc: logout token has already been consumed")

// LogoutReplayCache records consumed back-channel logout tokens so that a
// replayed logout event is not processed twice. The OpenID Connect
// Back-Channel Logout spec requires relying parties to validate that the
// "jti" of a logout token has not been seen before:
//
//	https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
//
// The cache treats the tuple of issuer, audience, subject, session ID, and
// token ID ("jti") as a one-time boundary: the first Consume of a token
// succeeds and records it, while any later Consume of a token with the same
// values fails closed with ErrLogoutTokenReplayed. A subsequent, legitimate
// logout for the same user or session carries a fresh "jti" and is accepted.
//
// Entries are retained until the token's expiry, after which the token would
// be rejected by IDTokenVerifier.VerifyLogout anyway. Applications that set
// SkipExpiryCheck must ensure tokens passed to Consume are still fresh.
//
//	logoutCache := oidc.NewLogoutReplayCache()
//	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
//		logoutToken, err := verifier.VerifyLogout(r.Context(), r.PostFormValue("logout_token"))
//		if err != nil {
//			// ...
//		}
//		if err := logoutCache.Consume(logoutToken); err != nil {
//			// Replayed logout event. Fail closed: do not process the logout
//			// a second time.
//			// ...
//		}
//		// Terminate the sessions identified by the logout token.
//	})
//
// LogoutReplayCache is safe for concurrent use. Applications that run
// multiple replicas should back the same boundary with shared storage.
type LogoutReplayCache struct {
	mu sync.Mutex
	// consumed maps a replay boundary key to the token's expiry, used to
	// evict entries that can no longer be replayed.
	consumed map[string]time.Time
	// now is a clock override for testing. If nil, time.Now is used.
	now func() time.Time
}

// NewLogoutReplayCache returns an empty, ready-to-use LogoutReplayCache.
func NewLogoutReplayCache() *LogoutReplayCache {
	return &LogoutReplayCache{consumed: make(map[string]time.Time)}
}

// replayKey derives the one-time boundary for a logout token from its issuer,
// audience, subject, session ID, and token ID. Fields are length-prefixed so
// distinct claim combinations cannot collide.
func logoutReplayKey(t *LogoutToken) string {
	h := sha256.New()
	writeField := func(s string) {
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(len(s)))
		h.Write(length[:])
		h.Write([]byte(s))
	}
	writeField(t.Issuer)
	var audienceCount [8]byte
	binary.LittleEndian.PutUint64(audienceCount[:], uint64(len(t.Audience)))
	h.Write(audienceCount[:])
	for _, aud := range t.Audience {
		writeField(aud)
	}
	writeField(t.Subject)
	writeField(t.SessionID)
	writeField(t.TokenID)
	return string(h.Sum(nil))
}

// Consume marks a verified logout token as consumed. It returns nil the first
// time a token within the token's replay boundary is seen, and
// ErrLogoutTokenReplayed for every subsequent token in the same boundary.
//
// Consume must only be called with tokens returned by
// IDTokenVerifier.VerifyLogout, and callers must not process a logout when
// Consume returns an error.
func (c *LogoutReplayCache) Consume(t *LogoutToken) error {
	if t == nil {
		return errors.New("oidc: cannot consume a nil logout token")
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	nowTime := now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict entries whose tokens have expired. An expired token is rejected
	// by VerifyLogout, so it can no longer be replayed.
	for key, expiry := range c.consumed {
		if expiry.Before(nowTime) {
			delete(c.consumed, key)
		}
	}

	key := logoutReplayKey(t)
	if _, ok := c.consumed[key]; ok {
		return fmt.Errorf("%w: jti %q", ErrLogoutTokenReplayed, t.TokenID)
	}
	c.consumed[key] = t.Expiry
	return nil
}
