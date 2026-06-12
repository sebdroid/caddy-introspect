package introspect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeOIDC emulates an authorisation server with discovery, RFC 7662
// introspection and a userinfo endpoint.
type fakeOIDC struct {
	srv             *httptest.Server
	active          map[string]bool
	clientID        string
	clientSecret    string
	introspectCalls atomic.Int64
	serverError     atomic.Bool
	introspectDelay time.Duration // set before serving requests
	advertise       struct{ introspection, userinfo bool }
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	f := &fakeOIDC{active: make(map[string]bool)}
	f.advertise.introspection, f.advertise.userinfo = true, true
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{"issuer": f.srv.URL}
		if f.advertise.introspection {
			doc["introspection_endpoint"] = f.srv.URL + "/introspect"
		}
		if f.advertise.userinfo {
			doc["userinfo_endpoint"] = f.srv.URL + "/userinfo"
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		f.introspectCalls.Add(1)
		if f.introspectDelay > 0 {
			time.Sleep(f.introspectDelay)
		}
		if f.serverError.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		if f.clientID != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != f.clientID || pass != f.clientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		_ = r.ParseForm()
		if !f.active[r.PostFormValue("token")] {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":   true,
			"sub":      "sub-456",
			"username": "bob",
			"scope":    "read write",
		})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !f.active[tok] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "sub-456"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) provider(t *testing.T, pc ProviderConfig) *oidcProvider {
	t.Helper()
	pc.Type = "oidc"
	if pc.Issuer == "" && pc.IntrospectionEndpoint == "" && pc.UserinfoEndpoint == "" {
		pc.Issuer = f.srv.URL
	}
	p, err := newOIDCProvider(pc, zap.NewNop(), f.srv.Client())
	require.NoError(t, err)
	return p
}

func TestOIDCDiscoveryResolution(t *testing.T) {
	f := newFakeOIDC(t)
	p := f.provider(t, ProviderConfig{})
	assert.Equal(t, f.srv.URL+"/introspect", p.introspectURL)
	assert.Equal(t, f.srv.URL, p.issuer())
}

func TestOIDCIntrospectionVerdicts(t *testing.T) {
	f := newFakeOIDC(t)
	f.active["live"] = true
	p := f.provider(t, ProviderConfig{})

	v, err := p.check(context.Background(), "live", nil)
	require.NoError(t, err)
	assert.True(t, v.active)
	assert.Equal(t, "sub-456", v.claims["sub"], "claims come from the introspection response")

	v, err = p.check(context.Background(), "revoked", nil)
	require.NoError(t, err)
	assert.False(t, v.active)
}

func TestOIDCClientAuthRejectionIsInfraError(t *testing.T) {
	f := newFakeOIDC(t)
	f.active["live"] = true
	f.clientID, f.clientSecret = "app", "correct"

	// A 401 from introspection means OUR credentials failed; that must be an
	// infrastructure error, never a "token revoked" verdict.
	p := f.provider(t, ProviderConfig{ClientID: "app", ClientSecret: "wrong"})
	_, err := p.check(context.Background(), "live", nil)
	assert.Error(t, err)

	good := f.provider(t, ProviderConfig{ClientID: "app", ClientSecret: "correct"})
	v, err := good.check(context.Background(), "live", nil)
	require.NoError(t, err)
	assert.True(t, v.active)
}

func TestOIDCUserinfoMethod(t *testing.T) {
	f := newFakeOIDC(t)
	f.active["live"] = true
	p := f.provider(t, ProviderConfig{Method: "userinfo"})

	v, err := p.check(context.Background(), "live", nil)
	require.NoError(t, err)
	assert.True(t, v.active)

	v, err = p.check(context.Background(), "dead", nil)
	require.NoError(t, err)
	assert.False(t, v.active)

	assert.Zero(t, f.introspectCalls.Load(), "userinfo method must not call introspection")
}

func TestUserinfo400IsDefinitiveInactive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	v, err := checkUserinfo(context.Background(), srv.Client(), srv.URL, "test", "tok")
	require.NoError(t, err, "a 400 is a verdict about the token, not an infrastructure error")
	assert.False(t, v.active)
}

func TestOIDCProvisionErrors(t *testing.T) {
	_, err := newOIDCProvider(ProviderConfig{}, zap.NewNop(), http.DefaultClient)
	assert.Error(t, err, "neither issuer nor endpoint configured")

	// discovery succeeds but does not advertise introspection
	f := newFakeOIDC(t)
	f.advertise.introspection = false
	_, err = newOIDCProvider(ProviderConfig{Issuer: f.srv.URL}, zap.NewNop(), f.srv.Client())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "introspection")

	// an explicit endpoint without an issuer is fine (opaque-chain only)
	p, err := newOIDCProvider(ProviderConfig{IntrospectionEndpoint: f.srv.URL + "/introspect"}, zap.NewNop(), f.srv.Client())
	require.NoError(t, err)
	assert.Empty(t, p.issuer(), "endpoint-only provider must not claim an issuer")
}
