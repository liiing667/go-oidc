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

// rotatingKeyServer serves a mutable JWKS document. Requests can be gated so
// tests can deterministically synchronize concurrent refreshes, and can be
// toggled to fail to exercise refresh failures.
type rotatingKeyServer struct {
	mu       sync.Mutex
	keys     jose.JSONWebKeySet
	fail     bool
	gate     chan struct{}
	entered  chan struct{}
	requests int
}

func (s *rotatingKeyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	gate := s.gate
	entered := s.entered
	s.mu.Unlock()

	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		<-gate
	}

	s.mu.Lock()
	fail := s.fail
	keys := s.keys
	s.mu.Unlock()

	if fail {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		panic(err)
	}
}

func (s *rotatingKeyServer) setKeys(keys ...jose.JSONWebKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = jose.JSONWebKeySet{Keys: keys}
}

func (s *rotatingKeyServer) setFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

func (s *rotatingKeyServer) setGate(gate, entered chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = gate
	s.entered = entered
}

func (s *rotatingKeyServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// waitForInflightWaiters blocks until want goroutines are waiting on the
// remote key set's current inflight request.
func waitForInflightWaiters(t *testing.T, rks *RemoteKeySet, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		rks.mu.RLock()
		got := 0
		if rks.inflight != nil {
			got = rks.inflight.waiters
		}
		rks.mu.RUnlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d inflight waiters", want)
}

// TestRemoteKeySetConcurrentGenerations is a fixed concurrency fixture that
// exercises the cache generation shared by the request, refresh, and publish
// paths. It asserts the cache boundary after each phase: concurrent refreshes
// collapse into a single generation bump, failed refreshes retain the
// previous complete set, and legitimate rotations publish the final keys.
func TestRemoteKeySetConcurrentGenerations(t *testing.T) {
	ctx := t.Context()

	key1 := newRSAKey(t)
	key2 := newRSAKey(t)
	key3 := newRSAKey(t)
	key1.keyID = "key1"
	key2.keyID = "key2"
	key3.keyID = "key3"

	payload := []byte("a secret")
	jws1, err := jose.ParseSigned(key1.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}
	jws2, err := jose.ParseSigned(key2.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}
	jws3, err := jose.ParseSigned(key3.sign(t, payload), allAlgs)
	if err != nil {
		t.Fatal(err)
	}

	server := &rotatingKeyServer{
		keys: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key1.jwk()}},
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL)

	cacheGeneration := func() uint64 {
		rks.mu.RLock()
		defer rks.mu.RUnlock()
		return rks.cache.generation
	}
	cacheKeyIDs := func() []string {
		rks.mu.RLock()
		defer rks.mu.RUnlock()
		var ids []string
		for _, key := range rks.cache.keys {
			ids = append(ids, key.KeyID)
		}
		return ids
	}

	// The initial refresh publishes the first generation.
	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Fatalf("verify key1: %v", err)
	}
	if got := cacheGeneration(); got != 1 {
		t.Errorf("after initial refresh: generation = %d, want 1", got)
	}
	if got := cacheKeyIDs(); !slices.Equal(got, []string{"key1"}) {
		t.Errorf("after initial refresh: cached kids = %v, want [key1]", got)
	}

	// A cached key verifies without crossing a cache boundary.
	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Fatalf("verify key1 from cache: %v", err)
	}
	if got := server.requestCount(); got != 1 {
		t.Errorf("cached verify: requests = %d, want 1", got)
	}

	// Rotate to key2 and verify concurrently. All workers must observe the
	// same cache boundary: a single refresh publishing generation 2.
	server.setKeys(key2.jwk())
	gate := make(chan struct{})
	entered := make(chan struct{})
	server.setGate(gate, entered)

	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = rks.verify(ctx, jws2)
		}(i)
	}
	close(start)

	// Wait for the refresh to reach the server, then for every worker to
	// attach to the same inflight request, before allowing it to complete.
	<-entered
	waitForInflightWaiters(t, rks, workers)
	close(gate)
	wg.Wait()
	server.setGate(nil, nil)

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}
	if got := server.requestCount(); got != 2 {
		t.Errorf("concurrent rotation: requests = %d, want 2", got)
	}
	if got := cacheGeneration(); got != 2 {
		t.Errorf("concurrent rotation: generation = %d, want 2", got)
	}
	if got := cacheKeyIDs(); !slices.Equal(got, []string{"key2"}) {
		t.Errorf("concurrent rotation: cached kids = %v, want [key2]", got)
	}

	// A failed refresh retains the previous complete set and does not
	// advance the generation.
	server.setFail(true)
	if _, err := rks.verify(ctx, jws3); err == nil {
		t.Error("verify key3 during outage: expected error, got nil")
	}
	if got := cacheGeneration(); got != 2 {
		t.Errorf("failed refresh: generation = %d, want 2", got)
	}
	if got := cacheKeyIDs(); !slices.Equal(got, []string{"key2"}) {
		t.Errorf("failed refresh: cached kids = %v, want [key2]", got)
	}
	if _, err := rks.verify(ctx, jws2); err != nil {
		t.Errorf("verify key2 after failed refresh: %v", err)
	}

	// Once the endpoint recovers, a legitimate rotation publishes the next
	// generation holding the final key set.
	server.setFail(false)
	server.setKeys(key2.jwk(), key3.jwk())
	if _, err := rks.verify(ctx, jws3); err != nil {
		t.Fatalf("verify key3 after recovery: %v", err)
	}
	if got := cacheGeneration(); got != 3 {
		t.Errorf("recovery: generation = %d, want 3", got)
	}
	if got := cacheKeyIDs(); !slices.Equal(got, []string{"key2", "key3"}) {
		t.Errorf("recovery: cached kids = %v, want [key2 key3]", got)
	}

	// Keys rotated out of the final set no longer verify, even though the
	// refresh they trigger succeeds and advances the generation.
	if _, err := rks.verify(ctx, jws1); err == nil {
		t.Error("verify rotated-out key1: expected error, got nil")
	}
	if got := cacheGeneration(); got != 4 {
		t.Errorf("rotated-out key: generation = %d, want 4", got)
	}
	if got := cacheKeyIDs(); !slices.Equal(got, []string{"key2", "key3"}) {
		t.Errorf("rotated-out key: cached kids = %v, want [key2 key3]", got)
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
