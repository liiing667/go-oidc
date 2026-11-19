package oidc

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// dualDiscoveryFixture serves two fixed generations of discovery metadata:
// the first request receives generation A, every later request generation B.
type dualDiscoveryFixture struct {
	server   *httptest.Server
	requests atomic.Int64
}

const (
	discoveryGenerationA = `{
		"issuer": "ISSUER",
		"authorization_endpoint": "https://example.com/a/auth",
		"token_endpoint": "https://example.com/a/token",
		"device_authorization_endpoint": "https://example.com/a/device",
		"userinfo_endpoint": "https://example.com/a/userinfo",
		"jwks_uri": "https://example.com/a/keys",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`
	discoveryGenerationB = `{
		"issuer": "ISSUER",
		"authorization_endpoint": "https://example.com/b/auth",
		"token_endpoint": "https://example.com/b/token",
		"device_authorization_endpoint": "https://example.com/b/device",
		"userinfo_endpoint": "https://example.com/b/userinfo",
		"jwks_uri": "https://example.com/b/keys",
		"id_token_signing_alg_values_supported": ["ES256"]
	}`
)

func newDualDiscoveryFixture(t *testing.T) *dualDiscoveryFixture {
	t.Helper()
	f := &dualDiscoveryFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data := discoveryGenerationA
		if f.requests.Add(1) > 1 {
			data = discoveryGenerationB
		}
		io.WriteString(w, strings.ReplaceAll(data, "ISSUER", f.server.URL))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func TestCachedProviderHit(t *testing.T) {
	ctx := t.Context()
	f := newDualDiscoveryFixture(t)

	p, err := NewProvider(ctx, f.server.URL)
	if err != nil {
		t.Fatalf("NewProvider() failed: %v", err)
	}
	m := p.CacheMetadata()

	if p.CacheID() == "" {
		t.Fatal("CacheID() is empty for a discovered provider")
	}
	if m.Source.CacheID != p.CacheID() || m.Issuer.CacheID != p.CacheID() || m.Endpoints.CacheID != p.CacheID() {
		t.Errorf("CacheMetadata() components not bound to the same identity: %+v", m)
	}

	cached, err := NewCachedProvider(ctx, f.server.URL, m)
	if err != nil {
		t.Fatalf("NewCachedProvider() failed: %v", err)
	}
	if got := f.requests.Load(); got != 1 {
		t.Errorf("cache hit refetched metadata, got %d requests, want 1", got)
	}
	if cached.CacheID() != p.CacheID() {
		t.Errorf("NewCachedProvider() cache identity = %q, want %q", cached.CacheID(), p.CacheID())
	}
	if cached.issuer != f.server.URL {
		t.Errorf("NewCachedProvider() issuer = %q, want %q", cached.issuer, f.server.URL)
	}
	if cached.authURL != "https://example.com/a/auth" || cached.tokenURL != "https://example.com/a/token" {
		t.Errorf("NewCachedProvider() endpoints = (%q, %q), want generation A", cached.authURL, cached.tokenURL)
	}
	if !reflect.DeepEqual(cached.algorithms, []string{"RS256"}) {
		t.Errorf("NewCachedProvider() algorithms = %v, want [RS256]", cached.algorithms)
	}

	// The metadata source is preserved, so claims remain available.
	var claims struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := cached.Claims(&claims); err != nil {
		t.Fatalf("Claims() failed: %v", err)
	}
	if claims.JWKSURL != "https://example.com/a/keys" {
		t.Errorf("Claims() jwks_uri = %q, want generation A", claims.JWKSURL)
	}
}

func TestCachedProviderIssuerMismatch(t *testing.T) {
	ctx := t.Context()
	f := newDualDiscoveryFixture(t)

	p, err := NewProvider(ctx, f.server.URL)
	if err != nil {
		t.Fatalf("NewProvider() failed: %v", err)
	}
	m := p.CacheMetadata()

	_, err = NewCachedProvider(ctx, f.server.URL+"/other-tenant", m)
	var mismatchErr *IssuerMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("NewCachedProvider() returned %v, want *IssuerMismatchError", err)
	}
	if mismatchErr.Provided != f.server.URL+"/other-tenant" || mismatchErr.Discovered != f.server.URL {
		t.Errorf("NewCachedProvider() mismatch = %+v", mismatchErr)
	}

	// The issuer advertised by the cached document is checked too, even when
	// the cached issuer component is absent.
	m.Issuer = Cached[string]{}
	if _, err := NewCachedProvider(ctx, f.server.URL+"/other-tenant", m); err == nil {
		t.Error("NewCachedProvider() with mismatched document issuer: expected error, got nil")
	} else if !errors.As(err, &mismatchErr) {
		t.Errorf("NewCachedProvider() returned %v, want *IssuerMismatchError", err)
	}
}

func TestCachedProviderCacheConflict(t *testing.T) {
	ctx := t.Context()
	f := newDualDiscoveryFixture(t)

	pA, err := NewProvider(ctx, f.server.URL)
	if err != nil {
		t.Fatalf("NewProvider() generation A failed: %v", err)
	}
	pB, err := NewProvider(ctx, f.server.URL)
	if err != nil {
		t.Fatalf("NewProvider() generation B failed: %v", err)
	}
	mA, mB := pA.CacheMetadata(), pB.CacheMetadata()
	if mA.Source.CacheID == mB.Source.CacheID {
		t.Fatal("fixture generations share a cache identity")
	}

	// Endpoints from generation B combined with the source and issuer of
	// generation A must be rejected.
	mixed := &CachedMetadata{
		Source:    mA.Source,
		Issuer:    mA.Issuer,
		Endpoints: mB.Endpoints,
	}
	_, err = NewCachedProvider(ctx, f.server.URL, mixed)
	var conflictErr *CacheConflictError
	if !errors.As(err, &conflictErr) {
		t.Fatalf("NewCachedProvider() returned %v, want *CacheConflictError", err)
	}
	if conflictErr.Source != mA.Source.CacheID || conflictErr.Endpoints != mB.Endpoints.CacheID {
		t.Errorf("CacheConflictError = %+v", conflictErr)
	}

	// A source stored under a foreign identity is rejected as well.
	forged := &CachedMetadata{
		Source: Cached[[]byte]{Value: mA.Source.Value, CacheID: mB.Source.CacheID},
	}
	if _, err := NewCachedProvider(ctx, f.server.URL, forged); !errors.As(err, &conflictErr) {
		t.Errorf("NewCachedProvider() forged source identity returned %v, want *CacheConflictError", err)
	}
}

func TestCachedProviderLegacy(t *testing.T) {
	ctx := t.Context()

	// Providers built without discovery remain constructible and export
	// untagged metadata.
	legacy := (&ProviderConfig{
		IssuerURL: "https://legacy.example.com",
		AuthURL:   "https://legacy.example.com/auth",
		TokenURL:  "https://legacy.example.com/token",
	}).NewProvider(ctx)
	if legacy.CacheID() != "" {
		t.Errorf("CacheID() = %q, want empty for a non-discovered provider", legacy.CacheID())
	}

	m := legacy.CacheMetadata()
	cached, err := NewCachedProvider(ctx, "https://legacy.example.com", m)
	if err != nil {
		t.Fatalf("NewCachedProvider() with untagged metadata failed: %v", err)
	}
	if cached.issuer != "https://legacy.example.com" || cached.authURL != "https://legacy.example.com/auth" {
		t.Errorf("NewCachedProvider() = (%q, %q), want legacy values", cached.issuer, cached.authURL)
	}
	if cached.CacheID() != "" {
		t.Errorf("NewCachedProvider() cache identity = %q, want empty", cached.CacheID())
	}
}
