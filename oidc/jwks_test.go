package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type keyServer struct {
	keys       jose.JSONWebKeySet
	setHeaders func(h http.Header)
}

func (k *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if k.setHeaders != nil {
		k.setHeaders(w.Header())
	}
	if err := json.NewEncoder(w).Encode(k.keys); err != nil {
		panic(err)
	}
}

type signingKey struct {
	keyID string // optional
	priv  any
	pub   any
	alg   jose.SignatureAlgorithm
}

// sign creates a JWS using the private key from the provided payload.
func (s *signingKey) sign(t testing.TB, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.priv, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (s *signingKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: s.pub, Use: "sig", Algorithm: string(s.alg), KeyID: s.keyID}
}

func newRSAKey(t testing.TB) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

func newECDSAKey(t *testing.T) *signingKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.ES256}
}

func newEdDSAKey(t *testing.T) *signingKey {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", privateKey, publicKey, jose.EdDSA}
}

func TestRSAVerify(t *testing.T) {
	good := newRSAKey(t)
	bad := newRSAKey(t)

	testKeyVerify(t, good, bad, good)
}

func TestECDSAVerify(t *testing.T) {
	good := newECDSAKey(t)
	bad := newECDSAKey(t)
	testKeyVerify(t, good, bad, good)
}

func TestEdDSAVerify(t *testing.T) {
	good := newEdDSAKey(t)
	bad := newEdDSAKey(t)
	testKeyVerify(t, good, bad, good)
}

func TestMultipleKeysVerify(t *testing.T) {
	key1 := newRSAKey(t)
	key2 := newRSAKey(t)
	bad := newECDSAKey(t)

	key1.keyID = "key1"
	key2.keyID = "key2"
	bad.keyID = "key3"

	testKeyVerify(t, key2, bad, key1, key2)
}

func TestMismatchedKeyID(t *testing.T) {
	key1 := newRSAKey(t)
	key2 := newRSAKey(t)

	// shallow copy
	bad := new(signingKey)
	*bad = *key1

	// The bad key is a valid key this time, but has a different Key ID.
	// It shouldn't match key1 because of the mismatched ID, even though
	// it would confirm the signature just fine.
	bad.keyID = "key3"

	key1.keyID = "key1"
	key2.keyID = "key2"

	testKeyVerify(t, key2, bad, key1, key2)
}

func TestKeyVerifyContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := []byte("a secret")

	good := newECDSAKey(t)
	jws, err := jose.ParseSigned(good.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "{}")
	}))
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	cancel()

	// Ensure the token verifies.
	_, err = rks.verify(ctx, jws)
	if err == nil {
		t.Fatal("expected context canceled, got nil error")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to be %q got %q", context.Canceled, err)
	}
}

func testKeyVerify(t *testing.T, good, bad *signingKey, verification ...*signingKey) {
	ctx := t.Context()

	keySet := jose.JSONWebKeySet{}
	for _, v := range verification {
		keySet.Keys = append(keySet.Keys, v.jwk())
	}

	payload := []byte("a secret")

	jws, err := jose.ParseSigned(good.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}
	badJWS, err := jose.ParseSigned(bad.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(&keyServer{keys: keySet})
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	// Ensure the token verifies.
	gotPayload, err := rks.verify(ctx, jws)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected payload %s got %s", payload, gotPayload)
	}

	// Ensure the token verifies from the cache.
	gotPayload, err = rks.verify(ctx, jws)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected payload %s got %s", payload, gotPayload)
	}

	// Ensure item signed by wrong token doesn't verify.
	if _, err := rks.verify(context.Background(), badJWS); err == nil {
		t.Errorf("incorrectly verified signature")
	}
}

func TestRotation(t *testing.T) {
	ctx := t.Context()

	key1 := newRSAKey(t)
	key2 := newRSAKey(t)

	key1.keyID = "key1"
	key2.keyID = "key2"

	payload := []byte("a secret")
	jws1, err := jose.ParseSigned(key1.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}
	jws2, err := jose.ParseSigned(key2.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}

	cacheForSeconds := 1200

	server := &keyServer{
		keys: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{key1.jwk()},
		},
		setHeaders: func(h http.Header) {
			h.Set("Cache-Control", "max-age="+strconv.Itoa(cacheForSeconds))
		},
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err == nil {
		t.Errorf("incorrectly verified signature")
	}

	// Add second key to public list.
	server.keys = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{key1.jwk(), key2.jwk()},
	}

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}

	// Kill server. Keys should still be cached.
	s.Close()

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
}

func TestUpdateKeysSendsCacheControlNoCache(t *testing.T) {
	ctx := t.Context()

	key := newRSAKey(t)
	var requestHeaders []http.Header

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHeaders = append(requestHeaders, r.Header.Clone())
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{key.jwk()},
		}); err != nil {
			panic(err)
		}
	}))
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	payload := []byte("a secret")
	jws, err := jose.ParseSigned(key.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rks.verify(ctx, jws); err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	if len(requestHeaders) == 0 {
		t.Fatal("expected at least one request to the JWKS endpoint")
	}
	for i, h := range requestHeaders {
		if got := h.Get("Cache-Control"); got != "no-cache" {
			t.Errorf("request %d: expected Cache-Control: no-cache, got %q", i, got)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	ctx := b.Context()

	key := newRSAKey(b)

	now := time.Date(2022, 1, 29, 0, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	payload := fmt.Appendf(nil, `{
		"iss": "https://example.com",
		"sub": "test_user",
		"aud": "test_client_id",
		"exp": %d
	}`, exp.Unix())

	idToken := key.sign(b, payload)
	server := &keyServer{
		keys: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{key.jwk()},
		},
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := NewRemoteKeySet(ctx, s.URL)
	verifier := NewVerifier("https://example.com", rks, &Config{
		ClientID: "test_client_id",
		Now:      func() time.Time { return now },
	})

	// Trigger the remote key set to query the public keys and cache them.
	if _, err := verifier.Verify(ctx, idToken); err != nil {
		b.Fatalf("verifying id token: %v", err)
	}

	for b.Loop() {
		if _, err := verifier.Verify(ctx, idToken); err != nil {
			b.Fatalf("verifying id token: %v", err)
		}
	}
}

func TestJWKParseWithIgnoredKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := jose.JSONWebKey{
		Key:       priv.Public(),
		Use:       "sig",
		Algorithm: string(jose.ES256),
		KeyID:     "key1",
	}
	pubRaw, err := json.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	privKey := jose.JSONWebKey{
		Key:       priv,
		Use:       "sig",
		Algorithm: string(jose.ES256),
		KeyID:     "key1",
	}

	hf := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"keys": [
				`+string(pubRaw)+`,
				{
					"alg": "ES256K",
					"kty": "EC",
					"x": "vsk5i5YJu8H_VPL7DWTgVGXBPrqgkyNmYvfgOrVut38",
					"y": "Mrg56tBhVeorHPXK1LbTX2jP7rEqOHIatM96HFzVMIU",
					"crv": "secp256k1",
					"kid": "oidc-es256k-1",
					"use": "sig"
				}
			]
		}`)
	}

	ks := NewRemoteKeySet(t.Context(), httptest.NewServer(http.HandlerFunc(hf)).URL)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	got, err := ks.VerifySignature(t.Context(), serialized)
	if err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("expected payload %q got %q", "payload", string(got))
	}
}

// gatedKeyServer is a key server whose responses can be held until the test
// releases them, allowing concurrent requests to deterministically pile up on
// a single in-flight refresh.
type gatedKeyServer struct {
	mu       sync.Mutex
	keys     jose.JSONWebKeySet
	fail     bool
	gate     chan struct{}
	requests int

	// requested is signaled when a gated request arrives.
	requested chan struct{}
}

func (g *gatedKeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.requests++
	keys := g.keys
	fail := g.fail
	gate := g.gate
	g.mu.Unlock()

	if gate != nil {
		select {
		case g.requested <- struct{}{}:
		default:
		}
		<-gate
	}
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		panic(err)
	}
}

func (g *gatedKeyServer) setKeys(keys jose.JSONWebKeySet) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.keys = keys
}

func (g *gatedKeyServer) setFail(fail bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail = fail
}

func (g *gatedKeyServer) setGate(gate chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = gate
}

func (g *gatedKeyServer) requestCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests
}

// TestRemoteKeySetRotationConcurrency exercises the RemoteKeySet cache
// generation boundaries: a failed refresh must retain the previous complete
// key set, a legitimate rotation must replace it, and concurrent requests
// during a rotation must share a single refresh and converge on the final
// key.
func TestRemoteKeySetRotationConcurrency(t *testing.T) {
	ctx := t.Context()

	oldKey := newRSAKey(t)
	oldKey.keyID = "old"
	currentKey := newRSAKey(t)
	currentKey.keyID = "current"
	finalKey := newRSAKey(t)
	finalKey.keyID = "final"

	payload := []byte("a secret")
	parse := func(key *signingKey) *jose.JSONWebSignature {
		jws, err := jose.ParseSigned(key.sign(t, payload), allAlgs)
		if err != nil {
			t.Fatal(err)
		}
		return jws
	}
	oldJWS := parse(oldKey)
	currentJWS := parse(currentKey)
	finalJWS := parse(finalKey)

	server := &gatedKeyServer{
		keys:      jose.JSONWebKeySet{Keys: []jose.JSONWebKey{oldKey.jwk()}},
		requested: make(chan struct{}, 1),
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	cachedKids := func() []string {
		var kids []string
		for _, key := range rks.keysFromCache() {
			kids = append(kids, key.KeyID)
		}
		return kids
	}

	// Prime the cache with the old key.
	if _, err := rks.verify(ctx, oldJWS); err != nil {
		t.Fatalf("verify with old key: %v", err)
	}
	if got := cachedKids(); !slices.Equal(got, []string{"old"}) {
		t.Fatalf("cached kids = %v, want [old]", got)
	}

	// Legitimate rotation: the unknown kid triggers a refresh and the new
	// generation is published.
	server.setKeys(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{currentKey.jwk()}})
	if _, err := rks.verify(ctx, currentJWS); err != nil {
		t.Fatalf("verify with rotated key: %v", err)
	}
	if got := cachedKids(); !slices.Equal(got, []string{"current"}) {
		t.Fatalf("cached kids = %v, want [current]", got)
	}

	// Cache boundary: once the generation switches, the old key must not hit.
	if _, err := rks.verify(ctx, oldJWS); err == nil {
		t.Fatal("old key verified after rotation, want failure")
	}

	// A failed refresh retains the previous complete set.
	server.setFail(true)
	if _, err := rks.verify(ctx, finalJWS); err == nil {
		t.Fatal("verify with unknown kid during outage succeeded, want failure")
	}
	if got := cachedKids(); !slices.Equal(got, []string{"current"}) {
		t.Fatalf("cached kids after failed refresh = %v, want [current]", got)
	}
	// The retained set keeps serving while the remote is down.
	if _, err := rks.verify(ctx, currentJWS); err != nil {
		t.Fatalf("verify with retained key after failed refresh: %v", err)
	}
	server.setFail(false)

	// Rotate to the final key and hold the refresh so concurrent requests
	// pile up on a single in-flight fetch.
	server.setKeys(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{finalKey.jwk()}})
	gate := make(chan struct{})
	server.setGate(gate)
	before := server.requestCount()

	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := rks.verify(ctx, finalJWS)
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("unexpected payload %q", got)
			}
			errs[i] = err
		}()
	}
	close(start)

	// Wait for the refresh to reach the server. While the gate is held, all
	// workers share this single in-flight request and no additional fetches
	// can be issued.
	<-server.requested
	if got, want := server.requestCount(), before+1; got != want {
		// Not Fatal: the gate must be closed below to release the workers
		// even when the assertion fails.
		t.Errorf("requests during gated refresh = %d, want %d", got, want)
	}

	close(gate)
	wg.Wait()
	server.setGate(nil)
	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}

	// Final key: the cache converges on the rotated set.
	if got := cachedKids(); !slices.Equal(got, []string{"final"}) {
		t.Fatalf("cached kids after concurrent rotation = %v, want [final]", got)
	}

	// Cache boundary: previous generations no longer hit.
	for _, jws := range map[string]*jose.JSONWebSignature{"old": oldJWS, "current": currentJWS} {
		if _, err := rks.verify(ctx, jws); err == nil {
			t.Errorf("previous generation key verified after final rotation, want failure")
		}
	}
}

func TestJWKParseWithUnsupportedKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := jose.JSONWebKey{
		Key:       priv.Public(),
		Use:       "sig",
		Algorithm: string(jose.ES256),
		KeyID:     "key1",
	}
	pubRaw, err := json.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	privKey := jose.JSONWebKey{
		Key:       priv,
		Use:       "sig",
		Algorithm: string(jose.ES256),
		KeyID:     "key1",
	}

	hf := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"keys": [
				`+string(pubRaw)+`,
				{
					"kty": "OKP",
					"crv": "Ed448",
					"kid": "oidc-ed448-1",
					"use": "sig",
					"x": "gH1eRK-6hW6ZoAy2k11U4L5uaIaMaZTMCf1cAbsxsYLvTqV2-TQG1PNyLOrhZkMyzUJulMc1wAfH"
				},
				{
					"kty": "OKP",
					"crv": "X448",
					"kid": "oidc-x448-1",
					"use": "enc",
					"x": "5Tegc13rI3bLqrCiUo-Cg1Ijjaj0l1aZrkVfUFbp-B5CGSj5z3wdAr3B0K7pPYDm9qbtjmMKOf0"
				}
			]
		}`)
	}

	ks := NewRemoteKeySet(t.Context(), httptest.NewServer(http.HandlerFunc(hf)).URL)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	got, err := ks.VerifySignature(t.Context(), serialized)
	if err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("expected payload %q got %q", "payload", string(got))
	}
}
