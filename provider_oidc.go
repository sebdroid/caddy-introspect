package introspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// oidcProvider checks tokens via RFC 7662 introspection, or the userinfo
// endpoint for servers without it.
type oidcProvider struct {
	iss           string
	clientID      string
	clientSecret  string
	method        string // "introspection" or "userinfo"
	introspectURL string
	userinfoURL   string
	logger        *zap.Logger
	client        *http.Client
}

func newOIDCProvider(pc ProviderConfig, logger *zap.Logger, client *http.Client) (*oidcProvider, error) {
	method := pc.Method
	if method == "" {
		method = "introspection"
	}
	if method != "introspection" && method != "userinfo" {
		return nil, fmt.Errorf("oidc provider: unknown method %q (want introspection or userinfo)", pc.Method)
	}

	p := &oidcProvider{
		iss:           strings.TrimSuffix(pc.Issuer, "/"),
		clientID:      pc.ClientID,
		clientSecret:  pc.ClientSecret,
		method:        method,
		introspectURL: pc.IntrospectionEndpoint,
		userinfoURL:   pc.UserinfoEndpoint,
		logger:        logger,
		client:        client,
	}

	needsDiscovery := (method == "introspection" && p.introspectURL == "") ||
		(method == "userinfo" && p.userinfoURL == "")
	if needsDiscovery {
		if pc.Issuer == "" {
			return nil, fmt.Errorf("oidc provider: set issuer (for discovery) or the %s endpoint explicitly", method)
		}
		doc, err := fetchDiscovery(client, pc.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc provider: discovery failed: %w", err)
		}
		if p.introspectURL == "" {
			p.introspectURL = doc.IntrospectionEndpoint
		}
		if p.userinfoURL == "" {
			p.userinfoURL = doc.UserinfoEndpoint
		}
	}

	switch {
	case method == "introspection" && p.introspectURL == "":
		// RFC 8414 metadata; not every discovery document includes it
		return nil, fmt.Errorf("oidc provider: issuer %q does not advertise an introspection endpoint; set introspection_endpoint explicitly, or use 'method userinfo'", pc.Issuer)
	case method == "userinfo" && p.userinfoURL == "":
		return nil, fmt.Errorf("oidc provider: issuer %q does not advertise a userinfo endpoint; set userinfo_endpoint explicitly", pc.Issuer)
	}
	if method == "introspection" && p.clientID == "" {
		logger.Warn("oidc provider has no client_id; most introspection endpoints require client authentication (RFC 7662 §2.1)",
			zap.String("issuer", pc.Issuer))
	}
	return p, nil
}

func (p *oidcProvider) name() string {
	if p.iss != "" {
		return "oidc/" + p.iss
	}
	return "oidc/" + p.introspectURL
}

func (p *oidcProvider) issuer() string { return p.iss }

// Both introspection and userinfo accept opaque tokens.
func (p *oidcProvider) opaqueCapable() bool { return true }

func (p *oidcProvider) check(ctx context.Context, token string, _ map[string]any) (verdict, error) {
	if p.method == "userinfo" {
		return checkUserinfo(ctx, p.client, p.userinfoURL, p.name(), token)
	}
	return p.checkIntrospection(ctx, token)
}

// checkIntrospection performs an RFC 7662 request. A non-200 (including a
// 401: OUR client credentials) is an infrastructure error, never a token
// verdict; only a 200 body is definitive.
func (p *oidcProvider) checkIntrospection(ctx context.Context, token string) (verdict, error) {
	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return verdict{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.clientID != "" {
		// RFC 6749 §2.3.1: credentials are form-encoded before Basic auth
		req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return verdict{}, fmt.Errorf("%s: introspection request: %w", p.name(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return verdict{}, fmt.Errorf("%s: introspection returned status %d (401/403 mean the configured client credentials were rejected)", p.name(), resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return verdict{}, fmt.Errorf("%s: decoding introspection response: %w", p.name(), err)
	}
	if active, _ := body["active"].(bool); active {
		return verdict{active: true, claims: body}, nil
	}
	return verdict{reason: p.name() + ": introspection says token is inactive (revoked, expired or unknown)"}, nil
}
