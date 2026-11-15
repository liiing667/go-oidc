package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
	ScopeOpenID = "openid"

	// ScopeProfile can be used to request information about the user's profile,
	// such as "name", "picture", etc.
	//
	// The exact set of claims supported by identity providers differs widely,
	// though "name" and "picture" are commonly returned.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopeProfile = "profile"

	// ScopeEmail can be used to request the user's email address through the
	// "email" and "email_verified" claims.
	//
	// What it means to verify an email isn't well defined. Clients can
	// generally throw out emails when the "emvail_verified" claim is false, but
	// should consult identity provider specific docs if attempting to ensure
	// that the user controls the returned email address.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopeEmail = "email"

	// ScopeOfflineAccess is an optional scope defined by OpenID Connect for requesting
	// OAuth2 refresh tokens.
	//
	// Support for this scope differs between OpenID Connect providers. For instance
	// Google rejects it, favoring appending "access_type=offline" as part of the
	// authorization request instead.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	ScopeOfflineAccess = "offline_access"
)

var (
	errNoAtHash      = errors.New("id token did not have an access token hash")
	errInvalidAtHash = errors.New("access token hash does not match value in ID token")
)

type contextKey int

var issuerURLKey contextKey

// ClientContext returns a new Context that carries the provided HTTP client.
//
// This method sets the same context key used by the golang.org/x/oauth2 package,
// so the returned context works for that package too.
//
//	myClient := &http.Client{}
//	ctx := oidc.ClientContext(parentContext, myClient)
//
//	// This will use the custom client
//	provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	}
	return nil
}

// InsecureIssuerURLContext allows discovery to work when the issuer_url reported
// by upstream is mismatched with the discovery URL. This is meant for integration
// with off-spec providers such as Azure.
//
//	discoveryBaseURL := "https://login.microsoftonline.com/organizations/v2.0"
//	issuerURL := "https://login.microsoftonline.com/my-tenantid/v2.0"
//
//	ctx := oidc.InsecureIssuerURLContext(parentContext, issuerURL)
//
//	// Provider will be discovered with the discoveryBaseURL, but use issuerURL
//	// for future issuer validation.
//	provider, err := oidc.NewProvider(ctx, discoveryBaseURL)
//
// This is insecure because validating the correct issuer is critical for multi-tenant
// providers. Any overrides here MUST be carefully reviewed.
func InsecureIssuerURLContext(ctx context.Context, issuerURL string) context.Context {
	return context.WithValue(ctx, issuerURLKey, issuerURL)
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c := getClient(ctx); c != nil {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

// Provider represents an OpenID Connect server's configuration, fetched from
// the discovery document.
//
// To access fields in the discovery document that aren't exposed directly
// through this package's API, use the [Provider.Claims] method. For example, to
// access the registration or end session endpoints:
//
//	p, err := oidc.NewProvider(ctx, "https://issuer.example.com")
//	if err != nil {
//		// ...
//	}
//	var metadata struct {
//		EndSessionEndpoint   string `json:"end_session_endpoint"`
//		RegistrationEndpoint string `json:"registration_endpoint"`
//	}
//	if err := p.Claims(&metadata); err != nil {
//		// ...
//	}
type Provider struct {
	issuer        string
	authURL       string
	tokenURL      string
	deviceAuthURL string
	userInfoURL   string
	jwksURL       string
	algorithms    []string

	// Raw claims returned by the server.
	rawClaims []byte

	// Guards all of the following fields.
	mu sync.Mutex
	// HTTP client specified from the initial NewProvider request. This is used
	// when creating the common key set.
	client *http.Client
	// A key set that uses context.Background() and is shared between all code paths
	// that don't have a convinent way of supplying a unique context.
	commonRemoteKeySet KeySet
}

func (p *Provider) remoteKeySet() KeySet {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commonRemoteKeySet == nil {
		ctx := context.Background()
		if p.client != nil {
			ctx = ClientContext(ctx, p.client)
		}
		p.commonRemoteKeySet = NewRemoteKeySet(ctx, p.jwksURL)
	}
	return p.commonRemoteKeySet
}

type providerJSON struct {
	Issuer        string   `json:"issuer"`
	AuthURL       string   `json:"authorization_endpoint"`
	TokenURL      string   `json:"token_endpoint"`
	DeviceAuthURL string   `json:"device_authorization_endpoint"`
	JWKSURL       string   `json:"jwks_uri"`
	UserInfoURL   string   `json:"userinfo_endpoint"`
	Algorithms    []string `json:"id_token_signing_alg_values_supported"`
}

// supportedAlgorithms is a list of algorithms explicitly supported by this
// package. If a provider supports other algorithms, such as HS256 or none,
// those values won't be passed to the IDTokenVerifier.
var supportedAlgorithms = map[string]bool{
	RS256: true,
	RS384: true,
	RS512: true,
	ES256: true,
	ES384: true,
	ES512: true,
	PS256: true,
	PS384: true,
	PS512: true,
	EdDSA: true,
}

// ProviderConfig allows direct creation of a [Provider] from metadata
// configuration. This is intended for interop with providers that don't support
// discovery, or host the JSON discovery document at an off-spec path.
//
// The ProviderConfig struct specifies JSON struct tags to support document
// parsing.
//
//	// Directly fetch the metadata document.
//	resp, err := http.Get("https://login.example.com/custom-metadata-path")
//	if err != nil {
//		// ...
//	}
//	defer resp.Body.Close()
//
//	// Parse config from JSON metadata.
//	config := &oidc.ProviderConfig{}
//	if err := json.NewDecoder(resp.Body).Decode(config); err != nil {
//		// ...
//	}
//	p := config.NewProvider(context.Background())
//
// For providers that implement discovery, use [NewProvider] instead.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html
type ProviderConfig struct {
	// IssuerURL is the identity of the provider, and the string it uses to sign
	// ID tokens with. For example "https://accounts.google.com". This value MUST
	// match ID tokens exactly.
	IssuerURL string `json:"issuer"`
	// AuthURL is the endpoint used by the provider to support the OAuth 2.0
	// authorization endpoint.
	AuthURL string `json:"authorization_endpoint"`
	// TokenURL is the endpoint used by the provider to support the OAuth 2.0
	// token endpoint.
	TokenURL string `json:"token_endpoint"`
	// DeviceAuthURL is the endpoint used by the provider to support the OAuth 2.0
	// device authorization endpoint.
	DeviceAuthURL string `json:"device_authorization_endpoint"`
	// UserInfoURL is the endpoint used by the provider to support the OpenID
	// Connect UserInfo flow.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string `json:"userinfo_endpoint"`
	// JWKSURL is the endpoint used by the provider to advertise public keys to
	// verify issued ID tokens. This endpoint is polled as new keys are made
	// available.
	JWKSURL string `json:"jwks_uri"`

	// Algorithms, if provided, indicate a list of JWT algorithms allowed to sign
	// ID tokens. If not provided, this defaults to the algorithms advertised by
	// the JWK endpoint, then the set of algorithms supported by this package.
	Algorithms []string `json:"id_token_signing_alg_values_supported"`
}

// NewProvider initializes a provider from a set of endpoints, rather than
// through discovery.
//
// The provided context is only used for [http.Client] configuration through
// [ClientContext], not cancelation.
//
// For providers that implement discovery, use [NewProvider] instead.
func (p *ProviderConfig) NewProvider(ctx context.Context) *Provider {
	return &Provider{
		issuer:        p.IssuerURL,
		authURL:       p.AuthURL,
		tokenURL:      p.TokenURL,
		deviceAuthURL: p.DeviceAuthURL,
		userInfoURL:   p.UserInfoURL,
		jwksURL:       p.JWKSURL,
		algorithms:    p.Algorithms,
		client:        getClient(ctx),
	}
}

// IssuerMismatchError is returned by [NewProvider] when the "iss" value
// reported by the upstream is different than the expected value.
//
// Issuer mismatches can occur due to trailing slashes ("https://example.com"
// vs. "https://example.com/") or represent significant misconfiguration for
// multi-tenant issuers.
//
// Issuers must match exactly as they are also used to validate ID Tokens.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type IssuerMismatchError struct {
	// The value provided to this package. The expected value.
	Provided string
	// The value advertised by the discovery document.
	Discovered string
}

func (e *IssuerMismatchError) Error() string {
	return fmt.Sprintf("oidc: issuer URL provided to client (%q) did not match the issuer URL returned by provider (%q)", e.Provided, e.Discovered)
}

// NewProvider uses the OpenID Connect discovery mechanism to construct a Provider.
// The issuer is the URL identifier for the service. For example: "https://accounts.google.com"
// or "https://login.salesforce.com".
//
// If the "iss" value returned in the discovery document doesn't match the value
// provided here, [IssuerMismatchError] is returned.
//
// OpenID Connect providers that don't implement discovery or host the discovery
// document at a non-spec compliant path (such as requiring a URL parameter),
// should use [ProviderConfig] instead.
//
// See: https://openid.net/specs/openid-connect-discovery-1_0.html
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}
	if p.Issuer != issuerURL && !skipIssuerValidation {
		return nil, &IssuerMismatchError{
			Provided:   issuerURL,
			Discovered: p.Issuer,
		}
	}
	var algs []string
	for _, a := range p.Algorithms {
		if supportedAlgorithms[a] {
			algs = append(algs, a)
		}
	}
	return &Provider{
		issuer:        issuerURL,
		authURL:       p.AuthURL,
		tokenURL:      p.TokenURL,
		deviceAuthURL: p.DeviceAuthURL,
		userInfoURL:   p.UserInfoURL,
		jwksURL:       p.JWKSURL,
		algorithms:    algs,
		rawClaims:     body,
		client:        getClient(ctx),
	}, nil
}

// Claims unmarshals raw fields returned by the server during discovery.
//
//	var claims struct {
//	    ScopesSupported []string `json:"scopes_supported"`
//	    ClaimsSupported []string `json:"claims_supported"`
//	}
//
//	if err := provider.Claims(&claims); err != nil {
//	    // handle unmarshaling error
//	}
//
// For a list of fields defined by the OpenID Connect spec see:
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (p *Provider) Claims(v any) error {
	if p.rawClaims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(p.rawClaims, v)
}

// Endpoint returns the OAuth2 auth and token endpoints for the given provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.authURL, DeviceAuthURL: p.deviceAuthURL, TokenURL: p.tokenURL}
}

// UserInfoEndpoint returns the OpenID Connect userinfo endpoint for the given
// provider.
func (p *Provider) UserInfoEndpoint() string {
	return p.userInfoURL
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	claims []byte
}

type userInfoRaw struct {
	Subject string `json:"sub"`
	Profile string `json:"profile"`
	Email   string `json:"email"`
	// Handle providers that return email_verified as a string
	// https://forums.aws.amazon.com/thread.jspa?messageID=949441&#949441 and
	// https://discuss.elastic.co/t/openid-error-after-authenticating-against-aws-cognito/206018/11
	EmailVerified stringAsBool `json:"email_verified"`
}

// Claims unmarshals the raw JSON object claims into the provided object.
func (u *UserInfo) Claims(v any) error {
	if u.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(u.claims, v)
}

// UserInfo uses the token source to query the provider's user info endpoint.
//
// It's fewer round trips and better supported to validate the ID Token with
// [Provider.Verifier], rather than using the UserInfo endpoint. The ID Token
// contains all information [UserInfo] provides:
//
//	p, err := oidc.NewProvider(ctx, "https://issuer.example.com")
//	if err != nil {
//		// ...
//	}
//	config := &oidc.Config{
//		ClientID: clientID,
//	}
//	v := p.Verifier(config)
//	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
//		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
//		if err != nil {
//			// ...
//		}
//		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
//		if !ok {
//			// ...
//		}
//		idToken, err := verifier.Verify(ctx, rawIDToken)
//		if err != nil {
//			// ...
//		}
//		// https://openid.net/specs/openid-connect-core-1_0.html#Claims
//		var claims struct {
//			Email         string `json:"email"`
//			EmailVerified bool   `json:"email_verified"`
//			Name          string `json:"name"`
//			Picture       string `json:"picture"`
//		}
//		if err := idToken.Claims(&claims); err != nil {
//			// ...
//		}
//		// Use claims...
//	})
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*UserInfo, error) {
	body, isJWT, err := p.fetchUserInfo(ctx, tokenSource)
	if err != nil {
		return nil, err
	}
	if isJWT {
		payload, err := p.remoteKeySet().VerifySignature(ctx, string(body))
		if err != nil {
			return nil, fmt.Errorf("oidc: invalid userinfo jwt signature %v", err)
		}
		body = payload
	}
	return parseUserInfo(body)
}

// UserInfoVerified uses the token source to query the provider's user info
// endpoint and strongly binds the returned claims to an ID Token that has
// already been verified for this login session.
//
// Unlike [Provider.UserInfo], this method fails closed unless the user info
// response contains exactly one non-empty "sub" claim that matches the
// subject of the provided ID Token. When the user info endpoint responds
// with a signed JWT (Content-Type "application/jwt"), the JWT's issuer,
// audience, and expiry are validated in addition to its signature: the
// issuer must match the provider's issuer, the audience must overlap with
// the ID Token's audience, and the token must carry a valid, unexpired
// "exp" claim.
//
// Callers that rely on user info claims (such as "email" or group
// membership) to establish the caller's identity should use this method
// instead of [Provider.UserInfo] to ensure the claims describe the same
// subject as the verified ID Token.
func (p *Provider) UserInfoVerified(ctx context.Context, tokenSource oauth2.TokenSource, idToken *IDToken) (*UserInfo, error) {
	if idToken == nil {
		return nil, errors.New("oidc: id token is nil")
	}
	if idToken.Subject == "" {
		return nil, errors.New("oidc: id token subject is empty")
	}

	body, isJWT, err := p.fetchUserInfo(ctx, tokenSource)
	if err != nil {
		return nil, err
	}
	if isJWT {
		payload, err := p.remoteKeySet().VerifySignature(ctx, string(body))
		if err != nil {
			return nil, fmt.Errorf("oidc: invalid userinfo jwt signature %v", err)
		}
		if err := p.verifyUserInfoJWT(payload, idToken); err != nil {
			return nil, err
		}
		body = payload
	}

	userInfo, err := parseUserInfo(body)
	if err != nil {
		return nil, err
	}
	if userInfo.Subject == "" {
		return nil, errors.New("oidc: userinfo response is missing the sub claim")
	}
	if userInfo.Subject != idToken.Subject {
		return nil, fmt.Errorf("oidc: userinfo subject %q does not match id token subject %q", userInfo.Subject, idToken.Subject)
	}
	return userInfo, nil
}

// fetchUserInfo queries the provider's user info endpoint and returns the raw
// response body along with whether the response is a signed JWT.
func (p *Provider) fetchUserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (body []byte, isJWT bool, err error) {
	if p.userInfoURL == "" {
		return nil, false, errors.New("oidc: user info endpoint is not supported by this provider")
	}

	req, err := http.NewRequest("GET", p.userInfoURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("oidc: create GET request: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, false, fmt.Errorf("oidc: get access token: %v", err)
	}
	token.SetAuthHeader(req)

	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%s: %s", resp.Status, body)
	}

	ct := resp.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/jwt" {
		return body, true, nil
	}
	return body, false, nil
}

// parseUserInfo decodes a user info response body. It fails closed if the
// body contains duplicate "sub" claims, which would otherwise be silently
// collapsed by JSON unmarshaling.
func parseUserInfo(body []byte) (*UserInfo, error) {
	subs, err := countSubjectClaims(body)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	if subs > 1 {
		return nil, errors.New("oidc: userinfo response contains duplicate sub claims")
	}

	var userInfo userInfoRaw
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	return &UserInfo{
		Subject:       userInfo.Subject,
		Profile:       userInfo.Profile,
		Email:         userInfo.Email,
		EmailVerified: bool(userInfo.EmailVerified),
		claims:        body,
	}, nil
}

// countSubjectClaims returns the number of top-level "sub" members in a JSON
// object.
func countSubjectClaims(body []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, errors.New("expected JSON object")
	}
	subs := 0
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return 0, err
		}
		if name, ok := key.(string); ok && name == "sub" {
			subs++
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return 0, err
		}
	}
	return subs, nil
}

// userInfoJWTClaims are the claims of a JWT user info response that must be
// validated to bind the response to this provider and login session.
type userInfoJWTClaims struct {
	Issuer   string    `json:"iss"`
	Audience audience  `json:"aud"`
	Expiry   *jsonTime `json:"exp"`
}

// verifyUserInfoJWT validates the issuer, audience, and expiry of a signed
// JWT user info payload against this provider and the verified ID Token.
func (p *Provider) verifyUserInfoJWT(payload []byte, idToken *IDToken) error {
	var claims userInfoJWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("oidc: failed to unmarshal userinfo jwt claims: %v", err)
	}
	if claims.Issuer != p.issuer {
		return fmt.Errorf("oidc: userinfo jwt issued by a different provider, expected %q got %q", p.issuer, claims.Issuer)
	}
	if len(claims.Audience) == 0 {
		return errors.New("oidc: userinfo jwt is missing the aud claim")
	}
	audienceMatch := false
	for _, aud := range claims.Audience {
		if slices.Contains(idToken.Audience, aud) {
			audienceMatch = true
			break
		}
	}
	if !audienceMatch {
		return fmt.Errorf("oidc: userinfo jwt audience %q does not overlap with id token audience %q", []string(claims.Audience), idToken.Audience)
	}
	if claims.Expiry == nil {
		return errors.New("oidc: userinfo jwt is missing the exp claim")
	}
	if time.Time(*claims.Expiry).Before(time.Now()) {
		return &TokenExpiredError{Expiry: time.Time(*claims.Expiry)}
	}
	return nil
}

// IDToken is an OpenID Connect extension that provides a predictable representation
// of an authorization event.
//
// The ID Token only holds fields OpenID Connect requires. To access additional
// claims returned by the server, use the Claims method.
type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. This package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provide verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// signature algorithm used for ID token, needed to compute a verification hash of an
	// access token
	sigAlgorithm string

	// Raw payload of the id_token.
	claims []byte

	// Map of distributed claim names to claim sources
	distributedClaims map[string]claimSource
}

// Claims unmarshals the raw JSON payload of the ID Token into a provided struct.
//
//	idToken, err := idTokenVerifier.Verify(rawIDToken)
//	if err != nil {
//		// handle error
//	}
//	var claims struct {
//		Email         string `json:"email"`
//		EmailVerified bool   `json:"email_verified"`
//	}
//	if err := idToken.Claims(&claims); err != nil {
//		// handle error
//	}
func (i *IDToken) Claims(v any) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

// VerifyAccessToken verifies that the hash of the access token that corresponds to the ID token
// matches the hash in the ID token. It returns an error if the hashes don't match.
// It is the caller's responsibility to ensure that the optional access token hash is present for the ID token
// before calling this method. See https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
func (i *IDToken) VerifyAccessToken(accessToken string) error {
	if i.AccessTokenHash == "" {
		return errNoAtHash
	}
	var h hash.Hash
	switch i.sigAlgorithm {
	case RS256, ES256, PS256:
		h = sha256.New()
	case RS384, ES384, PS384:
		h = sha512.New384()
	case RS512, ES512, PS512, EdDSA:
		h = sha512.New()
	default:
		return fmt.Errorf("oidc: unsupported signing algorithm %q", i.sigAlgorithm)
	}
	h.Write([]byte(accessToken)) // hash documents that Write will never return an error
	sum := h.Sum(nil)[:h.Size()/2]
	actual := base64.RawURLEncoding.EncodeToString(sum)
	if actual != i.AccessTokenHash {
		return errInvalidAtHash
	}
	return nil
}

type idToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	NotBefore    *jsonTime              `json:"nbf"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

type stringAsBool bool

func (sb *stringAsBool) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case "true", `"true"`:
		*sb = true
	case "false", `"false"`:
		*sb = false
	default:
		return errors.New("invalid value for boolean")
	}
	return nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = auds
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}

func unmarshalResp(r *http.Response, body []byte, v any) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
