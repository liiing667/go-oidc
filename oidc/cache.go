package oidc

import (
	"context"
	"strings"
	"sync"
)

// cachedDiscovery is a single generation of discovery metadata. The metadata
// source, issuer, endpoints, and algorithms are bound together so a cache
// entry never mixes fields fetched from different responses.
type cachedDiscovery struct {
	// source is the ".well-known" URL the metadata was fetched from.
	source string
	// issuer is the issuer advertised by the cached document.
	issuer string

	metadata  providerJSON
	rawClaims []byte
}

// ProviderCache caches discovery metadata for integrators that construct
// providers repeatedly and want to avoid a discovery round trip each time.
//
// Entries are keyed by the discovery document's URL, and each entry binds to a
// single response generation: the issuer, endpoints, and algorithm list are
// always served from the same cached document. If a request conflicts with
// the cached identity, for example because the requested issuer differs from
// the cached one, the cache fails closed with an error instead of mixing
// metadata. A cached entry is only replaced by re-fetching after it has been
// evicted; documents whose issuer doesn't match the requested issuer are
// rejected and never cached.
//
//	cache := oidc.NewProviderCache()
//	provider, err := cache.NewProvider(ctx, "https://accounts.example.com")
//
// The zero value is not ready for use; always construct the cache with
// [NewProviderCache]. A ProviderCache is safe for concurrent use.
type ProviderCache struct {
	mu      sync.Mutex
	entries map[string]*cachedDiscovery
}

// NewProviderCache returns an empty cache for discovery metadata.
func NewProviderCache() *ProviderCache {
	return &ProviderCache{entries: make(map[string]*cachedDiscovery)}
}

// NewProvider returns a Provider for the issuer, reusing cached discovery
// metadata when an entry is bound to the same identity.
//
// On a cache hit the cached issuer must match the requested issuer, exactly
// as [NewProvider] requires of a freshly fetched document. A mismatch returns
// [IssuerMismatchError] and leaves the cached entry untouched. On a cache
// miss the discovery document is fetched and validated; documents that fail
// issuer validation are rejected and not cached.
//
// [InsecureIssuerURLContext] behaves the same as for [NewProvider].
func (c *ProviderCache) NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}

	c.mu.Lock()
	entry, ok := c.entries[wellKnown]
	c.mu.Unlock()
	if ok {
		// Fail closed: the cached issuer must match the requested identity,
		// and conflicting requests never modify the cached entry.
		if entry.issuer != issuerURL && !skipIssuerValidation {
			return nil, &IssuerMismatchError{
				Provided:   issuerURL,
				Discovered: entry.issuer,
			}
		}
		metadata := entry.metadata
		return newProvider(&metadata, issuerURL, entry.rawClaims, getClient(ctx)), nil
	}

	p, body, err := fetchDiscoveryDocument(ctx, wellKnown)
	if err != nil {
		return nil, err
	}
	if p.Issuer != issuerURL && !skipIssuerValidation {
		// Reject the document without caching it, so a later request can
		// retry against a valid response.
		return nil, &IssuerMismatchError{
			Provided:   issuerURL,
			Discovered: p.Issuer,
		}
	}

	c.mu.Lock()
	c.entries[wellKnown] = &cachedDiscovery{
		source:    wellKnown,
		issuer:    p.Issuer,
		metadata:  *p,
		rawClaims: body,
	}
	c.mu.Unlock()

	return newProvider(p, issuerURL, body, getClient(ctx)), nil
}
