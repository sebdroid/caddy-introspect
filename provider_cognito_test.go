package introspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeCognito emulates the three Cognito endpoints the provider touches:
// the pool discovery document, the unsigned GetUser API and oauth2/userInfo.
type fakeCognito struct {
	poolID        string
	srv           *httptest.Server
	revoked       map[string]bool
	getUserCalls  atomic.Int64
	userinfoCalls atomic.Int64
}

func newFakeCognito(t *testing.T, poolID string) *fakeCognito {
	t.Helper()
	f := &fakeCognito{poolID: poolID, revoked: make(map[string]bool)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /"+poolID+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"userinfo_endpoint": f.srv.URL + "/oauth2/userInfo",
		})
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "AWSCognitoIdentityProviderService.GetUser" {
			http.Error(w, "unknown target", http.StatusBadRequest)
			return
		}
		f.getUserCalls.Add(1)
		var in struct{ AccessToken string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if f.revoked[in.AccessToken] {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"__type":  "NotAuthorizedException",
				"message": "Access Token has been revoked",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Username": "alice",
			"UserAttributes": []map[string]string{
				{"Name": "sub", "Value": "sub-123"},
				{"Name": "email", "Value": "alice@example.com"},
			},
		})
	})
	mux.HandleFunc("GET /oauth2/userInfo", func(w http.ResponseWriter, r *http.Request) {
		f.userinfoCalls.Add(1)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if f.revoked[tok] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "sub-123", "username": "alice"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCognito) provider(t *testing.T, pc ProviderConfig) *cognitoProvider {
	t.Helper()
	pc.Type = "cognito"
	pc.UserPoolID = f.poolID
	pc.Endpoint = f.srv.URL
	p, err := newCognitoProvider(pc, zap.NewNop(), f.srv.Client())
	require.NoError(t, err)
	return p
}

func TestCognitoRegionDerivation(t *testing.T) {
	_, err := newCognitoProvider(ProviderConfig{UserPoolID: "noregion", Domain: "https://d.example.com"}, zap.NewNop(), http.DefaultClient)
	assert.Error(t, err, "pool ID without a region prefix needs an explicit region")

	p, err := newCognitoProvider(ProviderConfig{UserPoolID: "eu-west-1_Test", Domain: "https://d.example.com"}, zap.NewNop(), http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Test", p.iss)
}

func TestCognitoGetUserProbe(t *testing.T) {
	f := newFakeCognito(t, "eu-west-1_Test")
	p := f.provider(t, ProviderConfig{})

	// InitiateAuth-style token: admin scope, no openid
	claims := map[string]any{"token_use": "access", "scope": adminScope}
	v, err := p.check(context.Background(), "live-token", claims)
	require.NoError(t, err)
	assert.True(t, v.active)
	assert.Equal(t, "alice", v.claims["username"])
	assert.Equal(t, "sub-123", v.claims["sub"])

	f.revoked["dead-token"] = true
	v, err = p.check(context.Background(), "dead-token", claims)
	require.NoError(t, err, "a revoked token is a verdict, not an error")
	assert.False(t, v.active)
	assert.Contains(t, v.reason, "NotAuthorizedException")
	assert.Zero(t, f.userinfoCalls.Load(), "admin-scope tokens must use GetUser, not userInfo")
}

func TestCognitoNoScopesUsesGetUser(t *testing.T) {
	f := newFakeCognito(t, "eu-west-1_Test")
	p := f.provider(t, ProviderConfig{})

	v, err := p.check(context.Background(), "live-token", map[string]any{"token_use": "access"})
	require.NoError(t, err)
	assert.True(t, v.active)
	assert.EqualValues(t, 1, f.getUserCalls.Load())
}

func TestCognitoUserinfoProbeViaDiscovery(t *testing.T) {
	f := newFakeCognito(t, "eu-west-1_Test")
	p := f.provider(t, ProviderConfig{}) // no Domain: discovered from the pool's discovery document

	claims := map[string]any{"token_use": "access", "scope": "openid profile"}
	v, err := p.check(context.Background(), "live-token", claims)
	require.NoError(t, err)
	assert.True(t, v.active)
	assert.EqualValues(t, 1, f.userinfoCalls.Load())
	assert.Zero(t, f.getUserCalls.Load())

	f.revoked["dead-token"] = true
	v, err = p.check(context.Background(), "dead-token", claims)
	require.NoError(t, err)
	assert.False(t, v.active)
}

func TestCognitoIDTokenRejected(t *testing.T) {
	f := newFakeCognito(t, "eu-west-1_Test")
	p := f.provider(t, ProviderConfig{})

	v, err := p.check(context.Background(), "id-token", map[string]any{"token_use": "id"})
	require.NoError(t, err)
	assert.False(t, v.active)
	assert.Zero(t, f.getUserCalls.Load()+f.userinfoCalls.Load(), "ID tokens must not be probed")
}

func TestCognitoUncheckableScopes(t *testing.T) {
	f := newFakeCognito(t, "eu-west-1_Test")
	p := f.provider(t, ProviderConfig{})

	v, err := p.check(context.Background(), "tok", map[string]any{"token_use": "access", "scope": "my-api/read"})
	require.NoError(t, err)
	assert.False(t, v.active)
	assert.Contains(t, v.reason, "openid", "the reason should explain the scope requirement")
}

func TestCognitoExplicitRegionOverride(t *testing.T) {
	p, err := newCognitoProvider(ProviderConfig{UserPoolID: "nounderscore", Region: "us-east-1", Domain: "https://d.example.com"}, zap.NewNop(), http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "https://cognito-idp.us-east-1.amazonaws.com/nounderscore", p.iss)
}

func TestCognitoNamespacedErrorType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"__type":"com.amazonaws.cognito.idp#NotAuthorizedException","message":"revoked"}`)
	}))
	t.Cleanup(srv.Close)

	p, err := newCognitoProvider(ProviderConfig{UserPoolID: "eu-west-1_Test", Endpoint: srv.URL, Domain: "https://d.example.com"}, zap.NewNop(), srv.Client())
	require.NoError(t, err)

	v, err := p.check(context.Background(), "tok", map[string]any{"token_use": "access"})
	require.NoError(t, err, "a namespaced NotAuthorizedException is still a definitive verdict")
	assert.False(t, v.active)
	assert.Contains(t, v.reason, "NotAuthorizedException")
}

func TestCognitoThrottlingIsInfraError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"__type":"TooManyRequestsException","message":"slow down"}`)
	}))
	t.Cleanup(srv.Close)

	p, err := newCognitoProvider(ProviderConfig{UserPoolID: "eu-west-1_Test", Endpoint: srv.URL, Domain: "https://d.example.com"}, zap.NewNop(), srv.Client())
	require.NoError(t, err)

	_, err = p.check(context.Background(), "tok", map[string]any{"token_use": "access"})
	assert.Error(t, err, "throttling must surface as an infrastructure error, not a verdict")
}
