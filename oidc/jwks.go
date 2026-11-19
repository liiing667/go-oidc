package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	jose "github.com/go-jose/go-jose/v4"
)

// StaticKeySet is a verifier that validates JWT against a static set of public keys.
type StaticKeySet struct {
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey,
	// *ecdsa.PublicKey, and ed25519.PublicKey.
	PublicKeys []crypto.PublicKey
}

// VerifySignature compares the signature against a static set of public keys.
func (s *StaticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	// Algorithms are already checked by Verifier, so this parse method accepts
	// any algorithm.
	jws, err := jose.ParseSigned(jwt, allAlgs)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %v", err)
	}
	for _, pub := range s.PublicKeys {
		switch pub.(type) {
		case *rsa.PublicKey:
		case *ecdsa.PublicKey:
		case ed25519.PublicKey:
		default:
			return nil, fmt.Errorf("invalid public key type provided: %T", pub)
		}
		payload, err := jws.Verify(pub)
		if err != nil {
			continue
		}
		return payload, nil
	}
	return nil, fmt.Errorf("no public keys able to verify jwt")
}

// NewRemoteKeySet returns a KeySet that can validate JSON web tokens by using HTTP
// GETs to fetch JSON web token sets hosted at a remote URL. This is automatically
// used by NewProvider using the URLs returned by OpenID Connect discovery, but is
// exposed for providers that don't support discovery or to prevent round trips to the
// discovery URL.
//
// The returned KeySet is a long lived verifier that caches keys in memory,
// re-fetching from the remote URL when it encounters a key ID it hasn't seen.
// Reuse a single remote key set rather than creating a new one for each
// verification.
func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return newRemoteKeySet(ctx, jwksURL)
}

func newRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return &RemoteKeySet{
		jwksURL: jwksURL,
		// For historical reasons, this package uses contexts for configuration, not just
		// cancellation. In hindsight, this was a bad idea.
		//
		// Attemps to reason about how cancels should work with background requests have
		// largely lead to confusion. Use the context here as a config bag-of-values and
		// ignore the cancel function.
		ctx: context.WithoutCancel(ctx),
	}
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint.
type RemoteKeySet struct {
	jwksURL string

	// Used for configuration. Cancelation is ignored.
	ctx context.Context

	// guard all other fields
	mu sync.RWMutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// cache is the latest published key set. The keys and their generation
	// are always swapped together under mu, so readers never observe a
	// partial update.
	cache keySetSnapshot
}

// keySetSnapshot is a coherent view of the cached key set. The generation is
// incremented each time a refreshed key set is published and is shared by the
// request, refresh, and publish paths so concurrent goroutines agree on cache
// boundaries. A failed refresh never advances the generation and leaves the
// previous complete set in place.
type keySetSnapshot struct {
	keys       []jose.JSONWebKey
	generation uint64
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	// baseGeneration is the cache generation the refresh was started from.
	// The refreshed keys are only published if the cache is still at this
	// generation, so a stale refresh can never overwrite a newer key set.
	baseGeneration uint64

	// waiters is the number of goroutines, including the one that started
	// the request, currently waiting on its result. It is guarded by
	// RemoteKeySet.mu and allows tests to deterministically observe
	// concurrent refreshes.
	waiters int

	snapshot keySetSnapshot
	err      error
}

func newInflight(baseGeneration uint64) *inflight {
	return &inflight{doneCh: make(chan struct{}), baseGeneration: baseGeneration}
}

// wait returns a channel that multiple goroutines can receive on. Once it returns
// a value, the inflight request is done and result() can be inspected.
func (i *inflight) wait() <-chan struct{} {
	return i.doneCh
}

// done can only be called by a single goroutine. It records the result of the
// inflight request and signals other goroutines that the result is safe to
// inspect.
func (i *inflight) done(snapshot keySetSnapshot, err error) {
	i.snapshot = snapshot
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() (keySetSnapshot, error) {
	return i.snapshot, i.err
}

// parsedJWTKey is a context key that allows common setups to avoid parsing the
// JWT twice. It holds a *jose.JSONWebSignature value.
var parsedJWTKey contextKey

// VerifySignature validates a payload against a signature from the jwks_uri.
//
// Users MUST NOT call this method directly and should use an IDTokenVerifier
// instead. This method skips critical validations such as 'alg' values and is
// only exported to implement the KeySet interface.
func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, ok := ctx.Value(parsedJWTKey).(*jose.JSONWebSignature)
	if !ok {
		// The algorithm values are already enforced by the Validator, which also sets
		// the context value above to pre-parsed signature.
		//
		// Practically, this codepath isn't called in normal use of this package, but
		// if it is, the algorithms have already been checked.
		var err error
		jws, err = jose.ParseSigned(jwt, allAlgs)
		if err != nil {
			return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
		}
	}
	return r.verify(ctx, jws)
}

func (r *RemoteKeySet) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	cached := r.keysFromCache()
	for _, key := range cached.keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	refreshed, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %w", err)
	}

	for _, key := range refreshed.keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("failed to verify id token signature")
}

func (r *RemoteKeySet) keysFromCache() keySetSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
//
// The refresh, publish, and request paths share the cache generation: the
// snapshot returned to waiters is the one published to the cache, a
// successful refresh publishes the next generation, and a failed refresh
// retains the previous complete set at its current generation.
func (r *RemoteKeySet) keysFromRemote(ctx context.Context) (keySetSnapshot, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	// If there's not a current inflight request, create one.
	if r.inflight == nil {
		inflight := newInflight(r.cache.generation)
		r.inflight = inflight

		// This goroutine has exclusive ownership over the current inflight
		// request. It releases the resource by nil'ing the inflight field
		// once the goroutine is done.
		go func() {
			// Sync keys and finish inflight when that's done.
			keys, err := r.updateKeys()

			// Lock to update the keys and indicate that there is no longer an
			// inflight request.
			r.mu.Lock()
			defer r.mu.Unlock()

			snapshot := r.cache
			if err == nil && r.cache.generation == inflight.baseGeneration {
				// Publish the refreshed keys as the next generation, but
				// only if the cache hasn't moved past the generation this
				// refresh started from. A failed refresh leaves the
				// previous complete set untouched.
				snapshot = keySetSnapshot{
					keys:       keys,
					generation: r.cache.generation + 1,
				}
				r.cache = snapshot
			}

			// Signal waiters while holding the lock so the snapshot they
			// observe and the published cache are the same generation.
			inflight.done(snapshot, err)

			// Free inflight so a different request can run.
			r.inflight = nil
		}()
	}
	r.inflight.waiters++
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return keySetSnapshot{}, ctx.Err()
	case <-inflight.wait():
		return inflight.result()
	}
}

// jwkJSON implements custom logic for unmarshaling JSON Web Key Sets.
type jwkJSON struct {
	Keys []jose.JSONWebKey
}

func (j *jwkJSON) UnmarshalJSON(data []byte) error {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// For each key, attempt to determine if the algorithm is supported before
	// unmarshaling the key. This allows us to ignore keys with unsupported
	// algorithms, rather than failing to load the entire set.
	for _, key := range raw.Keys {
		var metadata struct {
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(key, &metadata); err != nil {
			return err
		}
		if metadata.Alg != "" {
			// Algorithms are technically optional, but if the key advertises an
			// algorithm we don't support, ignore it rather than failing to load
			// the entire key set.
			//
			// https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
			//
			// This skip is currently implemented due to secp256k1, which some
			// providers use for signing with "ES256K". While we could also
			// ignore the curve, this seems like a more general check in case
			// providers start throwing in post-quantum algorithims or something
			// like that.
			//
			// https://github.com/coreos/go-oidc/issues/490
			if !supportedJOSEAlgs[metadata.Alg] {
				continue
			}
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(key, &jwk); err != nil {
			// Ignore keys with types that go-jose doesn't support, such as
			// OKP keys with Ed448 or X448 curves. Some providers include
			// them in their key sets without an "alg" value, so the check
			// above doesn't catch them.
			//
			// https://datatracker.ietf.org/doc/html/rfc7517#section-5
			//
			//     Implementations SHOULD ignore JWKs within a JWK Set that use
			//     "kty" (key type) values that are not understood by them, that
			//     are missing required members, or for which values are out of
			//     the supported ranges.
			if errors.Is(err, jose.ErrUnsupportedKeyType) {
				continue
			}
			return err
		}
		j.Keys = append(j.Keys, jwk)
	}
	return nil
}

func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %v", err)
	}
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := doRequest(r.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("oidc: get keys failed %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	var keySet jwkJSON
	err = unmarshalResp(resp, body, &keySet)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode keys: %v %s", err, body)
	}
	return keySet.Keys, nil
}
