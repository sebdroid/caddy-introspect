package introspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
)

func TestExtractTokens(t *testing.T) {
	ti := &TokenIntrospect{Sources: []TokenSource{
		{From: "var", Name: "jwtauth.token"},
		{From: "header", Name: "Authorization"},
		{From: "query", Name: "access_token"},
		{From: "cookie", Name: "session"},
	}}

	r := httptest.NewRequest("GET", "http://x/?access_token=tok-query", nil)
	r.Header.Set("Authorization", "Bearer tok-header")
	r.AddCookie(&http.Cookie{Name: "session", Value: "tok-cookie"})
	vars := map[string]any{"jwtauth.token": "tok-var"}
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))

	assert.Equal(t, []string{"tok-var", "tok-header", "tok-query", "tok-cookie"}, ti.extractTokens(r))
}

func TestExtractTokensDedupeAndBearer(t *testing.T) {
	ti := &TokenIntrospect{Sources: []TokenSource{
		{From: "header", Name: "Authorization"},
		{From: "header", Name: "X-Api-Token"},
		{From: "query", Name: "access_token"},
	}}

	r := httptest.NewRequest("GET", "http://x/?access_token=tok-same", nil)
	r.Header.Set("Authorization", "BEARER tok-same") // scheme is case-insensitive
	r.Header.Set("X-Api-Token", "tok-other")

	assert.Equal(t, []string{"tok-same", "tok-other"}, ti.extractTokens(r))
}

func TestExtractTokensEmpty(t *testing.T) {
	ti := &TokenIntrospect{Sources: []TokenSource{
		{From: "header", Name: "Authorization"},
		{From: "var", Name: "missing"}, // no vars map in context: must not panic
	}}
	assert.Empty(t, ti.extractTokens(httptest.NewRequest("GET", "http://x/", nil)))
}
