// Package introspect checks bearer tokens for revocation by asking their
// issuer for a live verdict.
package introspect

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

func init() {
	caddy.RegisterModule(TokenIntrospect{})
}

const (
	defaultCacheTTL        = 60 * time.Second
	defaultCacheMaxEntries = 10000
	defaultTimeout         = 5 * time.Second
)

// TokenIntrospect is an HTTP authentication provider that checks bearer
// tokens for revocation by probing their issuer.
type TokenIntrospect struct {
	// Sources to extract tokens from, in priority order. At least one is
	// required.
	Sources []TokenSource `json:"sources,omitempty"`

	// CacheTTL bounds how long a verdict (active or not) is reused before
	// the issuer is probed again. nil means the 60s default; 0 disables
	// caching so every request probes the issuer.
	CacheTTL *caddy.Duration `json:"cache_ttl,omitempty"`

	// CacheMaxEntries bounds the verdict cache size. Defaults to 10000.
	CacheMaxEntries int `json:"cache_max_entries,omitempty"`

	// FailOpen allows requests through when no definitive verdict could be
	// obtained (issuer unreachable, timeouts, 5xx). Definitive rejections
	// are unaffected. Defaults to false: no verdict, no entry.
	FailOpen bool `json:"fail_open,omitempty"`

	// Timeout for each probe request. Defaults to 5s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// UserClaims lists probe-response fields tried in order for the user
	// identity ({http.auth.user.id}). Defaults to [sub, username]. The
	// single special value "passthrough" echoes the identity set by an
	// earlier authentication handler (e.g. caddy-jwt) instead.
	UserClaims []string `json:"user_claims,omitempty"`

	// MetaClaims maps probe-response fields to {http.auth.user.*}
	// placeholder names. Nested fields use dotted paths.
	MetaClaims map[string]string `json:"meta_claims,omitempty"`

	// Providers configured to give verdicts. Tokens are routed by their iss
	// claim; tokens without one (opaque) try providers in this order.
	Providers []ProviderConfig `json:"providers,omitempty"`

	logger      *zap.Logger
	httpClient  *http.Client
	cache       *verdictCache
	cacheTTL    time.Duration
	sf          *singleflight.Group
	providers   []provider
	byIssuer    map[string]provider
	passthrough bool
}

// CaddyModule returns the Caddy module information.
func (TokenIntrospect) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.token_introspect",
		New: func() caddy.Module { return new(TokenIntrospect) },
	}
}

// Provision implements caddy.Provisioner.
func (ti *TokenIntrospect) Provision(ctx caddy.Context) error {
	return ti.provision(ctx.Logger())
}

// provision is split from Provision so tests can run it without a Caddy
// instance.
func (ti *TokenIntrospect) provision(logger *zap.Logger) error {
	ti.logger = logger

	if len(ti.Sources) == 0 {
		return errors.New("at least one token source is required (from_var, from_header, from_query or from_cookies)")
	}
	for _, s := range ti.Sources {
		switch s.From {
		case "var", "header", "query", "cookie":
		default:
			return fmt.Errorf("unknown token source %q", s.From)
		}
	}

	timeout := time.Duration(ti.Timeout)
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ti.httpClient = &http.Client{Timeout: timeout}

	switch {
	case len(ti.UserClaims) == 0:
		ti.UserClaims = []string{"sub", "username"}
	case len(ti.UserClaims) == 1 && ti.UserClaims[0] == "passthrough":
		ti.passthrough = true
	}

	if len(ti.Providers) == 0 {
		return errors.New("at least one provider is required")
	}
	ti.byIssuer = make(map[string]provider)
	for i, pc := range ti.Providers {
		p, err := pc.build(logger, ti.httpClient)
		if err != nil {
			return fmt.Errorf("provider %d: %w", i, err)
		}
		ti.providers = append(ti.providers, p)
		if iss := p.issuer(); iss != "" {
			key := normaliseIssuer(iss)
			if other, dup := ti.byIssuer[key]; dup {
				return fmt.Errorf("providers %s and %s claim the same issuer %q", other.name(), p.name(), iss)
			}
			ti.byIssuer[key] = p
		}
	}

	ti.cacheTTL = defaultCacheTTL
	if ti.CacheTTL != nil {
		ti.cacheTTL = time.Duration(*ti.CacheTTL)
	}
	if ti.cacheTTL > 0 {
		maxEntries := ti.CacheMaxEntries
		if maxEntries <= 0 {
			maxEntries = defaultCacheMaxEntries
		}
		ti.cache = newVerdictCache(maxEntries)
		ti.sf = new(singleflight.Group)
	}
	return nil
}

// Validate implements caddy.Validator.
func (ti *TokenIntrospect) Validate() error {
	if len(ti.providers) == 0 {
		return errors.New("no providers provisioned")
	}
	return nil
}

// Authenticate implements caddyauth.Authenticator. Candidates are tried in
// source priority order, so a stale cookie cannot block a fresh header
// token. The 401 belongs to the wrapping authentication handler; the
// response writer is never touched here.
func (ti *TokenIntrospect) Authenticate(_ http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	candidates := ti.extractTokens(r)
	if len(candidates) == 0 {
		return caddyauth.User{}, false, errors.New("no token found in request")
	}

	var (
		lastReason string
		infraTok   string
		infraErr   error
	)
	for _, tok := range candidates {
		v, err := ti.checkToken(r.Context(), tok)
		if err != nil {
			ti.logger.Warn("no verdict for token", zap.Error(err))
			if infraErr == nil {
				infraTok, infraErr = tok, err
			}
			continue
		}
		if v.active {
			return ti.buildUser(r, v.claims), true, nil
		}
		lastReason = v.reason
		ti.logger.Debug("token rejected", zap.String("reason", v.reason))
	}

	if infraErr != nil {
		if ti.FailOpen {
			ti.logger.Warn("FAIL OPEN: allowing request without a definitive verdict; identity derived from unverified claims",
				zap.Error(infraErr))
			return ti.buildUser(r, parseUnverifiedClaims(infraTok)), true, nil
		}
		return caddyauth.User{}, false, infraErr
	}
	if lastReason == "" {
		lastReason = "token rejected"
	}
	return caddyauth.User{}, false, errors.New(lastReason)
}

// checkToken consults the cache, then probes via singleflight so concurrent
// requests with the same token share one probe. With caching disabled every
// call probes.
func (ti *TokenIntrospect) checkToken(ctx context.Context, token string) (verdict, error) {
	if ti.cache == nil {
		return ti.introspect(ctx, token)
	}
	key := sha256.Sum256([]byte(token))
	if v, ok := ti.cache.get(key); ok {
		return v, nil
	}
	res, err, _ := ti.sf.Do(string(key[:]), func() (any, error) {
		v, err := ti.introspect(ctx, token)
		if err != nil {
			return verdict{}, err
		}
		ti.cache.set(key, v, ti.entryTTL(token))
		return v, nil
	})
	if err != nil {
		return verdict{}, err
	}
	return res.(verdict), nil
}

// entryTTL caps the cache TTL at the token's own exp; a verdict outliving
// the token is waste.
func (ti *TokenIntrospect) entryTTL(token string) time.Duration {
	ttl := ti.cacheTTL
	if claims := parseUnverifiedClaims(token); claims != nil {
		if exp, ok := tokenExpiry(claims); ok {
			if until := time.Until(exp); until > 0 && until < ttl {
				ttl = until
			}
		}
	}
	return ttl
}

// introspect routes a token to a provider for a verdict. A JWT goes only to
// the provider owning its iss (no fallthrough: nobody can vouch for a token
// they did not issue, and spraying tokens across endpoints leaks them); an
// unknown iss is rejected outright. Opaque tokens try providers in order and
// the first "active" wins, since RFC 7662 cannot distinguish "revoked" from
// "not my token".
func (ti *TokenIntrospect) introspect(ctx context.Context, token string) (verdict, error) {
	claims := parseUnverifiedClaims(token)
	if claims != nil {
		if iss, _ := claims["iss"].(string); iss != "" {
			p, ok := ti.byIssuer[normaliseIssuer(iss)]
			if !ok {
				return verdict{reason: fmt.Sprintf("issuer %q is not configured", iss)}, nil
			}
			return p.check(ctx, token, claims)
		}
	}

	var firstErr error
	for _, p := range ti.providers {
		if !p.opaqueCapable() {
			continue
		}
		v, err := p.check(ctx, token, claims)
		if err != nil {
			ti.logger.Debug("provider gave no verdict", zap.String("provider", p.name()), zap.Error(err))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if v.active {
			return v, nil
		}
	}
	if firstErr != nil {
		// an errored provider might have said "active": no definitive verdict
		return verdict{}, firstErr
	}
	return verdict{reason: "no provider recognised the token"}, nil
}

// buildUser maps probe-response claims to the {http.auth.user.*} fields.
// Passthrough must echo the upstream identity because the wrapping handler
// overwrites {http.auth.user.id} unconditionally, even with an empty value.
func (ti *TokenIntrospect) buildUser(r *http.Request, claims map[string]any) caddyauth.User {
	user := caddyauth.User{Metadata: make(map[string]string)}

	if ti.passthrough {
		if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
			if id, ok := repl.GetString("http.auth.user.id"); ok {
				user.ID = id
			}
		}
	} else {
		for _, name := range ti.UserClaims {
			if v, ok := lookupClaim(claims, name); ok {
				if s := stringify(v); s != "" {
					user.ID = s
					break
				}
			}
		}
		if user.ID == "" {
			ti.logger.Debug("no user identity found in probe response", zap.Strings("user_claims", ti.UserClaims))
		}
	}

	for claimPath, placeholder := range ti.MetaClaims {
		if v, ok := lookupClaim(claims, claimPath); ok {
			user.Metadata[placeholder] = stringify(v)
		}
	}
	return user
}

func normaliseIssuer(iss string) string {
	return strings.TrimSuffix(iss, "/")
}

// Interface guards
var (
	_ caddy.Provisioner       = (*TokenIntrospect)(nil)
	_ caddy.Validator         = (*TokenIntrospect)(nil)
	_ caddyauth.Authenticator = (*TokenIntrospect)(nil)
)
