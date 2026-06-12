package introspect

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUnverifiedClaims(t *testing.T) {
	tok := makeJWT(t, map[string]any{"iss": "https://idp.example.com", "sub": "alice"})
	claims := parseUnverifiedClaims(tok)
	require.NotNil(t, claims)
	assert.Equal(t, "https://idp.example.com", claims["iss"])
	assert.Equal(t, "alice", claims["sub"])

	for _, opaque := range []string{"", "nodots", "two.parts", "a.b.c.d.e", "x.!!notbase64!!.z"} {
		assert.Nil(t, parseUnverifiedClaims(opaque), opaque)
	}
}

func TestLookupClaim(t *testing.T) {
	claims := map[string]any{
		"sub":            "alice",
		"cognito:groups": []any{"admins"},
		"settings": map[string]any{
			"payout": map[string]any{"enabled": true},
		},
	}

	v, ok := lookupClaim(claims, "sub")
	require.True(t, ok)
	assert.Equal(t, "alice", v)

	// exact-match keys containing separators resolve directly
	v, ok = lookupClaim(claims, "cognito:groups")
	require.True(t, ok)
	assert.Equal(t, "admins", stringify(v))

	v, ok = lookupClaim(claims, "settings.payout.enabled")
	require.True(t, ok)
	assert.Equal(t, true, v)

	_, ok = lookupClaim(claims, "missing.path")
	assert.False(t, ok)

	_, ok = lookupClaim(nil, "sub")
	assert.False(t, ok)
}

func TestStringify(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"x", "x"},
		{true, "true"},
		{float64(42), "42"},
		{float64(1.5), "1.5"},
		{[]any{"a", "b"}, "a,b"},
		{map[string]any{"k": "v"}, `{"k":"v"}`},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, stringify(c.in))
	}
}

func TestParseScopes(t *testing.T) {
	assert.Equal(t, []string{"openid", "profile", "email"}, parseScopes(map[string]any{"scope": "openid profile email"}))
	assert.Equal(t, []string{"openid", "email"}, parseScopes(map[string]any{"scope": []any{"openid", "email"}}))
	assert.Nil(t, parseScopes(map[string]any{}))
}

func TestTokenExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	exp, ok := tokenExpiry(map[string]any{"exp": float64(future)})
	require.True(t, ok)
	assert.Equal(t, future, exp.Unix())

	_, ok = tokenExpiry(map[string]any{})
	assert.False(t, ok)
}
