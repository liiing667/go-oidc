package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CacheID identifies a single generation of discovery metadata: one response
// from the discovery endpoint. All components parsed from the same response
// (the raw document, the issuer, and the optional endpoints) share one
// identity, allowing integrators that cache discovery metadata to detect
// when components were assembled from different responses.
//
// The zero value ("") marks an untagged component, such as one built from a
// [ProviderConfig] rather than a discovered document.
type CacheID string

// computeCacheID derives the cache identity of a raw discovery document.
func computeCacheID(raw []byte) CacheID {
	sum := sha256.Sum256(raw)
	return CacheID("sha256:" + hex.EncodeToString(sum[:]))
}

// Cached binds a cached value to the identity of the discovery response it
// was read from. A value with an empty CacheID is a legacy, untagged
// component.
type Cached[T any] struct {
	Value   T
	CacheID CacheID
}

// CachedEndpoints holds the optional endpoints and signing algorithms
// advertised by a discovery document.
type CachedEndpoints struct {
	AuthURL       string
	TokenURL      string
	DeviceAuthURL string
	UserInfoURL   string
	JWKSURL       string
	Algorithms    []string
}

// CachedMetadata is a set of discovery components retrieved from an
// integrator-managed cache. Each component is bound to the cache identity of
// the discovery response it was read from, so components from different
// response generations can be detected before they are trusted.
//
// Use [Provider.CacheMetadata] to export a provider's metadata for caching
// and [NewCachedProvider] to rebuild a provider from cached components.
type CachedMetadata struct {
	// Source is the raw discovery document. When present, its cache identity
	// is derived from the document itself and is authoritative: every other
	// tagged component must match it.
	Source Cached[[]byte]
	// Issuer is the issuer URL advertised by the discovery document.
	Issuer Cached[string]
	// Endpoints are the optional endpoints and algorithms advertised by the
	// discovery document.
	Endpoints Cached[CachedEndpoints]
}

// CacheConflictError is returned by [NewCachedProvider] when cached
// components carry different cache identities, meaning they were read from
// different discovery responses, or when a component's identity does not
// match the metadata source it claims to come from.
//
// Mixing generations is rejected because endpoints, issuer, and algorithm
// lists from different responses may not describe a coherent provider.
type CacheConflictError struct {
	// Source is the resolved identity of the metadata source.
	Source CacheID
	// Issuer is the identity the cached issuer was tagged with.
	Issuer CacheID
	// Endpoints is the identity the cached endpoints were tagged with.
	Endpoints CacheID
}

func (e *CacheConflictError) Error() string {
	return fmt.Sprintf("oidc: cached discovery metadata combines different response generations (source=%q, issuer=%q, endpoints=%q)",
		e.Source, e.Issuer, e.Endpoints)
}

// CacheID returns the identity of the discovery response this provider was
// constructed from, or "" if the provider was not built from a discovered
// document (for example, through [ProviderConfig.NewProvider]).
func (p *Provider) CacheID() CacheID {
	return p.cacheID
}

// CacheMetadata exports the provider's discovery metadata as cacheable
// components. The metadata source, issuer, and optional endpoints are all
// bound to the provider's cache identity. Providers that weren't built from
// a discovered document return untagged components.
func (p *Provider) CacheMetadata() *CachedMetadata {
	return &CachedMetadata{
		Source: Cached[[]byte]{Value: p.rawClaims, CacheID: p.cacheID},
		Issuer: Cached[string]{Value: p.issuer, CacheID: p.cacheID},
		Endpoints: Cached[CachedEndpoints]{
			Value: CachedEndpoints{
				AuthURL:       p.authURL,
				TokenURL:      p.tokenURL,
				DeviceAuthURL: p.deviceAuthURL,
				UserInfoURL:   p.userInfoURL,
				JWKSURL:       p.jwksURL,
				Algorithms:    p.algorithms,
			},
			CacheID: p.cacheID,
		},
	}
}

// resolveCacheID verifies that all tagged components belong to a single
// response generation and returns that generation's identity. Untagged
// (legacy) components are accepted as-is.
func resolveCacheID(m *CachedMetadata) (CacheID, error) {
	conflict := &CacheConflictError{
		Source:    m.Source.CacheID,
		Issuer:    m.Issuer.CacheID,
		Endpoints: m.Endpoints.CacheID,
	}
	if len(m.Source.Value) > 0 {
		computed := computeCacheID(m.Source.Value)
		if m.Source.CacheID != "" && m.Source.CacheID != computed {
			return "", conflict
		}
		conflict.Source = computed
	}
	id := conflict.Source
	for _, component := range []CacheID{conflict.Issuer, conflict.Endpoints} {
		if component == "" {
			continue
		}
		if id == "" {
			id = component
			continue
		}
		if id != component {
			return "", conflict
		}
	}
	return id, nil
}

// NewCachedProvider reconstructs a Provider from cached discovery metadata
// without contacting the provider. The issuer argument is the expected issuer
// URL, as with [NewProvider].
//
// Every component that carries a cache identity must belong to the same
// discovery response; combining components from different responses fails
// closed with a [CacheConflictError]. Components with an empty cache
// identity are legacy, untagged values and are accepted as-is, so metadata
// captured before identities existed remains usable.
//
// If the cached issuer, or the issuer in the cached discovery document,
// doesn't match the expected issuer, an [IssuerMismatchError] is returned.
func NewCachedProvider(ctx context.Context, issuer string, m *CachedMetadata) (*Provider, error) {
	if m == nil {
		m = &CachedMetadata{}
	}
	cacheID, err := resolveCacheID(m)
	if err != nil {
		return nil, err
	}

	issuerURL, skipIssuerValidation := ctx.Value(issuerURLKey).(string)
	if !skipIssuerValidation {
		issuerURL = issuer
	}

	var rawClaims []byte
	if len(m.Source.Value) > 0 {
		rawClaims = m.Source.Value
		var p providerJSON
		if err := json.Unmarshal(rawClaims, &p); err != nil {
			return nil, fmt.Errorf("oidc: failed to decode cached provider discovery object: %v", err)
		}
		if p.Issuer != "" && p.Issuer != issuerURL && !skipIssuerValidation {
			return nil, &IssuerMismatchError{
				Provided:   issuerURL,
				Discovered: p.Issuer,
			}
		}
	}
	if m.Issuer.Value != "" {
		if m.Issuer.Value != issuerURL && !skipIssuerValidation {
			return nil, &IssuerMismatchError{
				Provided:   issuerURL,
				Discovered: m.Issuer.Value,
			}
		}
	}

	var algs []string
	for _, a := range m.Endpoints.Value.Algorithms {
		if supportedAlgorithms[a] {
			algs = append(algs, a)
		}
	}
	return &Provider{
		issuer:        issuerURL,
		authURL:       m.Endpoints.Value.AuthURL,
		tokenURL:      m.Endpoints.Value.TokenURL,
		deviceAuthURL: m.Endpoints.Value.DeviceAuthURL,
		userInfoURL:   m.Endpoints.Value.UserInfoURL,
		jwksURL:       m.Endpoints.Value.JWKSURL,
		algorithms:    algs,
		rawClaims:     rawClaims,
		cacheID:       cacheID,
		client:        getClient(ctx),
	}, nil
}
