package introspect

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	input := `token_introspect {
		from_var jwtauth.token
		from_header Authorization X-Api-Token
		from_cookies session
		from_query access_token

		cache_ttl 30s
		cache_max_entries 5000
		fail_open
		timeout 3s

		user_claims sub username
		meta_claims "username -> user" "cognito:groups -> groups" scope

		provider cognito {
			user_pool_id eu-west-1_AbCdEf123
			domain https://auth.example.com
		}
		provider oidc {
			issuer https://idp.example.com
			client_id app
			client_secret secret
			method introspection
		}
	}`

	ti := new(TokenIntrospect)
	require.NoError(t, ti.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)))

	assert.Equal(t, []TokenSource{
		{From: "var", Name: "jwtauth.token"},
		{From: "header", Name: "Authorization"},
		{From: "header", Name: "X-Api-Token"},
		{From: "cookie", Name: "session"},
		{From: "query", Name: "access_token"},
	}, ti.Sources)

	require.NotNil(t, ti.CacheTTL)
	assert.Equal(t, caddy.Duration(30*time.Second), *ti.CacheTTL)
	assert.Equal(t, 5000, ti.CacheMaxEntries)
	assert.True(t, ti.FailOpen)
	assert.Equal(t, caddy.Duration(3*time.Second), ti.Timeout)
	assert.Equal(t, []string{"sub", "username"}, ti.UserClaims)
	assert.Equal(t, map[string]string{
		"username":       "user",
		"cognito:groups": "groups",
		"scope":          "scope",
	}, ti.MetaClaims)

	require.Len(t, ti.Providers, 2)
	assert.Equal(t, ProviderConfig{Type: "cognito", UserPoolID: "eu-west-1_AbCdEf123", Domain: "https://auth.example.com"}, ti.Providers[0])
	assert.Equal(t, ProviderConfig{Type: "oidc", Issuer: "https://idp.example.com", ClientID: "app", ClientSecret: "secret", Method: "introspection"}, ti.Providers[1])
}

func TestUnmarshalCaddyfileZeroTTL(t *testing.T) {
	input := `token_introspect {
		cache_ttl 0
		provider oidc {
			introspection_endpoint https://as.example.com/introspect
		}
	}`

	ti := new(TokenIntrospect)
	require.NoError(t, ti.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)))
	require.NotNil(t, ti.CacheTTL)
	assert.Equal(t, caddy.Duration(0), *ti.CacheTTL, "an explicit 0 must be preserved, it disables caching")
}

func TestCaddyfileWithoutSourcesFailsProvision(t *testing.T) {
	input := `token_introspect {
		provider oidc {
			introspection_endpoint https://as.example.com/introspect
		}
	}`

	ti := new(TokenIntrospect)
	require.NoError(t, ti.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)), "parsing succeeds, provisioning must not")

	err := ti.provision(zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token source", "the error should tell the user what is missing")
}

func TestUnmarshalCaddyfileErrors(t *testing.T) {
	for name, input := range map[string]string{
		"inline arg":     "token_introspect foo",
		"unknown option": "token_introspect {\n\tbogus\n}",
		"empty source":   "token_introspect {\n\tfrom_header\n}",
		"bad ttl":        "token_introspect {\n\tcache_ttl nope\n}",
		"bad provider":   "token_introspect {\n\tprovider oidc {\n\t\tbogus x\n\t}\n}",
	} {
		ti := new(TokenIntrospect)
		assert.Error(t, ti.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)), name)
	}
}
