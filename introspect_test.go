package introspect

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func durPtr(d time.Duration) *caddy.Duration {
	cd := caddy.Duration(d)
	return &cd
}

// newTestModule provisions a TokenIntrospect against a fake OIDC server,
// reading tokens from the Authorization header.
func newTestModule(t *testing.T, f *fakeOIDC, mutate func(*TokenIntrospect)) *TokenIntrospect {
	t.Helper()
	ti := &TokenIntrospect{
		Sources:   []TokenSource{{From: "header", Name: "Authorization"}},
		Providers: []ProviderConfig{{Type: "oidc", Issuer: f.srv.URL, ClientID: "app"}},
	}
	if mutate != nil {
		mutate(ti)
	}
	testProvision(t, ti)
	return ti
}

func TestAuthenticateActiveAndRevoked(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	live := makeJWT(t, map[string]any{"iss": f.srv.URL, "sub": "ignored"})
	f.active[live] = true

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+live)
	user, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sub-456", user.ID, "identity comes from the probe response, not the JWT payload")

	dead := makeJWT(t, map[string]any{"iss": f.srv.URL, "sub": "x"})
	r = httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+dead)
	_, ok, _ = ti.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok, "revoked token must not authenticate")
}

func TestAuthenticateNoToken(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	_, ok, err := ti.Authenticate(httptest.NewRecorder(), httptest.NewRequest("GET", "http://x/", nil))
	assert.False(t, ok)
	assert.Error(t, err)
}

func TestAuthenticateCacheReusesVerdicts(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil) // default 60s TTL

	live := makeJWT(t, map[string]any{"iss": f.srv.URL})
	f.active[live] = true
	for i := range 3 {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Set("Authorization", "Bearer "+live)
		_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
		require.Truef(t, ok, "request %d: %v", i, err)
	}
	assert.EqualValues(t, 1, f.introspectCalls.Load(), "3 requests should share 1 probe")

	// negative verdicts are cached too: a revoked token must not hammer the IdP
	dead := makeJWT(t, map[string]any{"iss": f.srv.URL, "jti": "dead"})
	before := f.introspectCalls.Load()
	for range 3 {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Set("Authorization", "Bearer "+dead)
		_, _, _ = ti.Authenticate(httptest.NewRecorder(), r)
	}
	assert.EqualValues(t, 1, f.introspectCalls.Load()-before)
}

func TestAuthenticateCacheDisabledProbesAlways(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) {
		ti.CacheTTL = durPtr(0)
	})

	live := makeJWT(t, map[string]any{"iss": f.srv.URL})
	f.active[live] = true
	for range 3 {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Header.Set("Authorization", "Bearer "+live)
		_, _, _ = ti.Authenticate(httptest.NewRecorder(), r)
	}
	assert.EqualValues(t, 3, f.introspectCalls.Load(), "cache_ttl 0 must probe every request")
}

func TestAuthenticateContinuesPastRevokedCandidate(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) {
		ti.Sources = []TokenSource{
			{From: "header", Name: "Authorization"},
			{From: "query", Name: "access_token"},
		}
	})

	dead := makeJWT(t, map[string]any{"iss": f.srv.URL, "jti": "dead"})
	live := makeJWT(t, map[string]any{"iss": f.srv.URL, "jti": "live"})
	f.active[live] = true

	// a revoked token in the higher-priority source must not block the valid one
	r := httptest.NewRequest("GET", "http://x/?access_token="+live, nil)
	r.Header.Set("Authorization", "Bearer "+dead)
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok, "the second candidate should authenticate")
}

func TestAuthenticateUnknownIssuerRejected(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	tok := makeJWT(t, map[string]any{"iss": "https://evil.example.com", "sub": "x"})
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, ok, _ := ti.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok)
	assert.Zero(t, f.introspectCalls.Load(), "unknown-issuer tokens must never be sent to any provider")
}

func TestAuthenticateOpaqueTokenChain(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)
	f.active["opaque-token-xyz"] = true

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer opaque-token-xyz")
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok, "opaque tokens authenticate via the provider chain")
}

func TestAuthenticateFailPolicy(t *testing.T) {
	f := newFakeOIDC(t)
	tok := makeJWT(t, map[string]any{"iss": f.srv.URL, "sub": "carol"})
	f.serverError.Store(true)

	closed := newTestModule(t, f, func(ti *TokenIntrospect) { ti.CacheTTL = durPtr(0) })
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, ok, err := closed.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok, "fail-closed must reject on infrastructure errors")
	assert.Error(t, err)

	open := newTestModule(t, f, func(ti *TokenIntrospect) {
		ti.CacheTTL = durPtr(0)
		ti.FailOpen = true
	})
	user, ok, err := open.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	require.True(t, ok, "fail-open must allow on infrastructure errors")
	assert.Equal(t, "carol", user.ID, "with no probe response, identity falls back to unverified JWT claims")
}

func TestFailOpenDoesNotApplyToRevoked(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) { ti.FailOpen = true })

	dead := makeJWT(t, map[string]any{"iss": f.srv.URL})
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+dead)
	_, ok, _ := ti.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok, "fail_open covers infrastructure errors only; a definitive rejection must always reject")
}

func TestEntryTTLCappedAtTokenExpiry(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil) // default 60s TTL

	far := makeJWT(t, map[string]any{"exp": float64(time.Now().Add(time.Hour).Unix())})
	assert.Equal(t, 60*time.Second, ti.entryTTL(far))

	near := makeJWT(t, map[string]any{"exp": float64(time.Now().Add(5 * time.Second).Unix())})
	got := ti.entryTTL(near)
	assert.Positive(t, got)
	assert.LessOrEqual(t, got, 5*time.Second, "a verdict must not outlive its token")

	// already-expired and opaque tokens fall back to the configured TTL
	expired := makeJWT(t, map[string]any{"exp": float64(time.Now().Add(-time.Minute).Unix())})
	assert.Equal(t, 60*time.Second, ti.entryTTL(expired))
	assert.Equal(t, 60*time.Second, ti.entryTTL("opaque"))
}

func TestConcurrentRequestsShareOneProbe(t *testing.T) {
	f := newFakeOIDC(t)
	f.introspectDelay = 50 * time.Millisecond
	ti := newTestModule(t, f, nil)

	live := makeJWT(t, map[string]any{"iss": f.srv.URL})
	f.active[live] = true

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("GET", "http://x/", nil)
			r.Header.Set("Authorization", "Bearer "+live)
			_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
			assert.NoError(t, err)
			assert.True(t, ok)
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, f.introspectCalls.Load(), "concurrent requests with one token must share a single probe")
}

func TestIssuerRoutingAcrossProviders(t *testing.T) {
	fc := newFakeCognito(t, "eu-west-1_Test")
	fo := newFakeOIDC(t)
	ti := &TokenIntrospect{
		Sources: []TokenSource{{From: "header", Name: "Authorization"}},
		Providers: []ProviderConfig{
			{Type: "cognito", UserPoolID: "eu-west-1_Test", Endpoint: fc.srv.URL},
			{Type: "oidc", Issuer: fo.srv.URL, ClientID: "app"},
		},
		CacheTTL: durPtr(0),
	}
	testProvision(t, ti)

	cogTok := makeJWT(t, map[string]any{"iss": fc.srv.URL + "/eu-west-1_Test", "token_use": "access", "scope": adminScope})
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+cogTok)
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.EqualValues(t, 1, fc.getUserCalls.Load())
	assert.Zero(t, fo.introspectCalls.Load(), "a cognito-issued token must never reach the oidc provider")

	oidcTok := makeJWT(t, map[string]any{"iss": fo.srv.URL})
	fo.active[oidcTok] = true
	r = httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+oidcTok)
	_, ok, err = ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.EqualValues(t, 1, fo.introspectCalls.Load())
	assert.EqualValues(t, 1, fc.getUserCalls.Load(), "an oidc-issued token must never reach the cognito provider")
}

func TestOpaqueChainSkipsCognito(t *testing.T) {
	fc := newFakeCognito(t, "eu-west-1_Test")
	fo := newFakeOIDC(t)
	ti := &TokenIntrospect{
		Sources: []TokenSource{{From: "header", Name: "Authorization"}},
		Providers: []ProviderConfig{
			{Type: "cognito", UserPoolID: "eu-west-1_Test", Endpoint: fc.srv.URL}, // first, but not opaque-capable
			{Type: "oidc", Issuer: fo.srv.URL, ClientID: "app"},
		},
	}
	testProvision(t, ti)
	fo.active["opaque-token-abc"] = true

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer opaque-token-abc")
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Zero(t, fc.getUserCalls.Load()+fc.userinfoCalls.Load(), "cognito cannot check opaque tokens and must be skipped")
}

func TestOpaqueTokenUnrecognisedRejected(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer unknown-opaque-token")
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider recognised")
}

func TestOpaqueChainInfraErrorHitsFailPolicy(t *testing.T) {
	f := newFakeOIDC(t)
	f.serverError.Store(true)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) { ti.CacheTTL = durPtr(0) })

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer some-opaque-token")
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	assert.False(t, ok, "an errored provider might have said active, so fail-closed must reject")
	assert.Error(t, err)
}

func TestJWTWithoutIssuerUsesProviderChain(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	tok := makeJWT(t, map[string]any{"sub": "x"}) // a JWT, but no iss to route on
	f.active[tok] = true
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIssuerTrailingSlashNormalised(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, nil)

	tok := makeJWT(t, map[string]any{"iss": f.srv.URL + "/"})
	f.active[tok] = true
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	assert.True(t, ok, "iss with a trailing slash must still match the configured issuer")
}

func TestDuplicateIssuerRejectedAtProvision(t *testing.T) {
	ti := &TokenIntrospect{
		Sources: []TokenSource{{From: "header", Name: "Authorization"}},
		Providers: []ProviderConfig{
			{Type: "oidc", Issuer: "https://idp.example.com", IntrospectionEndpoint: "https://idp.example.com/a"},
			{Type: "oidc", Issuer: "https://idp.example.com", IntrospectionEndpoint: "https://idp.example.com/b"},
		},
	}
	err := ti.provision(zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same issuer")
}

func TestAuthenticatePassthroughIdentity(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) {
		ti.UserClaims = []string{"passthrough"}
	})

	live := makeJWT(t, map[string]any{"iss": f.srv.URL})
	f.active[live] = true

	repl := caddy.NewReplacer()
	repl.Set("http.auth.user.id", "alice-from-jwtauth")
	r := httptest.NewRequest("GET", "http://x/", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
	r.Header.Set("Authorization", "Bearer "+live)

	user, ok, err := ti.Authenticate(httptest.NewRecorder(), r)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "alice-from-jwtauth", user.ID, "passthrough must echo the upstream identity")
}

func TestAuthenticateMetaClaims(t *testing.T) {
	f := newFakeOIDC(t)
	ti := newTestModule(t, f, func(ti *TokenIntrospect) {
		ti.MetaClaims = map[string]string{"scope": "scopes", "username": "user"}
	})

	live := makeJWT(t, map[string]any{"iss": f.srv.URL})
	f.active[live] = true

	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("Authorization", "Bearer "+live)
	user, ok, _ := ti.Authenticate(httptest.NewRecorder(), r)
	require.True(t, ok)
	assert.Equal(t, "read write", user.Metadata["scopes"])
	assert.Equal(t, "bob", user.Metadata["user"])
}

func TestProvisionRejectsBadConfig(t *testing.T) {
	authHeader := []TokenSource{{From: "header", Name: "Authorization"}}
	for name, ti := range map[string]*TokenIntrospect{
		"no sources":     {Providers: []ProviderConfig{{Type: "oidc", IntrospectionEndpoint: "https://x/introspect"}}},
		"no providers":   {Sources: authHeader},
		"unknown source": {Sources: []TokenSource{{From: "body", Name: "x"}}, Providers: []ProviderConfig{{Type: "oidc", IntrospectionEndpoint: "https://x/introspect"}}},
		"unknown type":   {Sources: authHeader, Providers: []ProviderConfig{{Type: "saml"}}},
	} {
		assert.Error(t, ti.provision(zap.NewNop()), name)
	}
}
