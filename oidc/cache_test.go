package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

// discoveryServer serves a fixed sequence of discovery documents: the first
// request gets responses[0], the second responses[1], and any further
// requests repeat the last response. The responses slice is referenced, not
// copied, so tests can populate it after learning the server's URL. It
// reports how many requests it served.
type discoveryServer struct {
	*httptest.Server
	requests atomic.Int64
}

func newDiscoveryServer(responses *[]string) *discoveryServer {
	s := &discoveryServer{}
	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		docs := *responses
		n := s.requests.Add(1)
		i := int(n) - 1
		if i >= len(docs) {
			i = len(docs) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, docs[i])
	}
	s.Server = httptest.NewServer(http.HandlerFunc(hf))
	return s
}

func (s *discoveryServer) requestCount() int64 {
	return s.requests.Load()
}

func discoveryDoc(issuer, authURL, tokenURL string, algs ...string) string {
	return fmt.Sprintf(`{
		"issuer": %q,
		"authorization_endpoint": %q,
		"token_endpoint": %q,
		"jwks_uri": "https://example.com/keys",
		"id_token_signing_alg_values_supported": %q
	}`, issuer, authURL, tokenURL, algs)
}

// TestProviderCacheHitServesSingleGeneration verifies that once metadata is
// cached, later requests are served from the same response generation: the
// issuer, endpoints, and algorithms all come from the first document even
// after the server starts serving a newer one.
func TestProviderCacheHitServesSingleGeneration(t *testing.T) {
	ctx := context.Background()

	var responses []string
	s := newDiscoveryServer(&responses)
	defer s.Close()
	// Two generations of the same issuer's metadata, with different
	// endpoints and algorithms.
	responses = []string{
		discoveryDoc(s.URL, "https://example.com/v1/auth", "https://example.com/v1/token", "RS256"),
		discoveryDoc(s.URL, "https://example.com/v2/auth", "https://example.com/v2/token", "ES256"),
	}

	cache := NewProviderCache()

	// Cache miss: the first generation is fetched and cached.
	p1, err := cache.NewProvider(ctx, s.URL)
	if err != nil {
		t.Fatalf("NewProvider() first call: %v", err)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("after first call server served %d requests, want 1", got)
	}
	if got, want := p1.Endpoint().AuthURL, "https://example.com/v1/auth"; got != want {
		t.Errorf("first call AuthURL = %q, want %q", got, want)
	}

	// Cache hit: a valid provider is still constructed from the older
	// generation, without consulting the server again.
	p2, err := cache.NewProvider(ctx, s.URL)
	if err != nil {
		t.Fatalf("NewProvider() second call: %v", err)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("cached call hit the server, served %d requests, want 1", got)
	}
	if got, want := p2.Endpoint().AuthURL, "https://example.com/v1/auth"; got != want {
		t.Errorf("cached AuthURL = %q, want %q", got, want)
	}
	if got, want := p2.Endpoint().TokenURL, "https://example.com/v1/token"; got != want {
		t.Errorf("cached TokenURL = %q, want %q", got, want)
	}
	if got, want := p2.algorithms, []string{"RS256"}; !reflect.DeepEqual(got, want) {
		t.Errorf("cached algorithms = %v, want %v", got, want)
	}
	var claims struct {
		AuthURL string `json:"authorization_endpoint"`
	}
	if err := p2.Claims(&claims); err != nil {
		t.Fatalf("Claims() on cached provider: %v", err)
	}
	if want := "https://example.com/v1/auth"; claims.AuthURL != want {
		t.Errorf("cached raw claims AuthURL = %q, want %q", claims.AuthURL, want)
	}
}

// TestProviderCacheMismatchFailsClosed verifies that a request whose issuer
// conflicts with the cached identity fails closed: it returns an
// IssuerMismatchError and leaves the cached entry untouched.
func TestProviderCacheMismatchFailsClosed(t *testing.T) {
	ctx := context.Background()

	var responses []string
	s := newDiscoveryServer(&responses)
	defer s.Close()
	issuer := s.URL
	responses = []string{
		discoveryDoc(issuer, "https://example.com/v1/auth", "https://example.com/v1/token", "RS256"),
		discoveryDoc(issuer, "https://example.com/v2/auth", "https://example.com/v2/token", "ES256"),
	}

	cache := NewProviderCache()
	if _, err := cache.NewProvider(ctx, issuer); err != nil {
		t.Fatalf("NewProvider() first call: %v", err)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("after first call server served %d requests, want 1", got)
	}

	// The trailing-slash issuer resolves to the same discovery URL, but
	// conflicts with the cached issuer identity.
	_, err := cache.NewProvider(ctx, issuer+"/")
	if err == nil {
		t.Fatal("NewProvider() with conflicting issuer: expected error, got nil")
	}
	var mismatchErr *IssuerMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("NewProvider() returned %T, want *IssuerMismatchError: %v", err, err)
	}
	want := &IssuerMismatchError{Provided: issuer + "/", Discovered: issuer}
	if !reflect.DeepEqual(mismatchErr, want) {
		t.Errorf("NewProvider() error = %+v, want %+v", mismatchErr, want)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("conflicting request hit the server, served %d requests, want 1", got)
	}

	// The conflict must not have evicted or modified the cached entry.
	p, err := cache.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("NewProvider() after conflict: %v", err)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("cached entry was lost after conflict, served %d requests, want 1", got)
	}
	if got, want := p.Endpoint().AuthURL, "https://example.com/v1/auth"; got != want {
		t.Errorf("cached AuthURL = %q, want %q", got, want)
	}
}

// TestProviderCacheRejectsConflictingDocument verifies that a fetched
// document whose issuer doesn't match the requested issuer is rejected and
// never cached, so a later request retries and can cache a valid response.
func TestProviderCacheRejectsConflictingDocument(t *testing.T) {
	ctx := context.Background()

	var responses []string
	s := newDiscoveryServer(&responses)
	defer s.Close()
	issuer := s.URL
	responses = []string{
		discoveryDoc("https://evil.example.com", "https://evil.example.com/auth", "https://evil.example.com/token", "RS256"),
		discoveryDoc(issuer, "https://example.com/auth", "https://example.com/token", "RS256"),
	}

	cache := NewProviderCache()

	// The first generation advertises a conflicting issuer and is rejected.
	_, err := cache.NewProvider(ctx, issuer)
	if err == nil {
		t.Fatal("NewProvider() with conflicting document: expected error, got nil")
	}
	var mismatchErr *IssuerMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("NewProvider() returned %T, want *IssuerMismatchError: %v", err, err)
	}
	if got := s.requestCount(); got != 1 {
		t.Fatalf("after rejected response server served %d requests, want 1", got)
	}

	// The rejected document was not cached: the next request re-fetches and
	// caches the valid second generation.
	p, err := cache.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("NewProvider() after rejection: %v", err)
	}
	if got := s.requestCount(); got != 2 {
		t.Fatalf("rejected document was cached, served %d requests, want 2", got)
	}
	if got, want := p.Endpoint().AuthURL, "https://example.com/auth"; got != want {
		t.Errorf("AuthURL = %q, want %q", got, want)
	}

	// The valid generation is now served from the cache.
	if _, err := cache.NewProvider(ctx, issuer); err != nil {
		t.Fatalf("NewProvider() cached call: %v", err)
	}
	if got := s.requestCount(); got != 2 {
		t.Fatalf("cached call hit the server, served %d requests, want 2", got)
	}
}
