package introspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// verdict is a definitive probe outcome: active, or not (with reason).
// Infrastructure failures are returned as errors instead, and only those
// are subject to the fail_open policy.
type verdict struct {
	active bool
	claims map[string]any
	reason string
}

// provider is one configured token issuer we can ask for a live verdict.
type provider interface {
	name() string
	issuer() string      // iss this provider owns; "" if not routable by issuer
	opaqueCapable() bool // can it check non-JWT tokens?
	check(ctx context.Context, token string, claims map[string]any) (verdict, error)
}

// ProviderConfig configures a single provider; Type selects the implementation.
type ProviderConfig struct {
	// Type is "cognito" or "oidc".
	Type string `json:"type"`

	// UserPoolID is the Cognito user pool, e.g. "eu-west-1_AbCdEf123".
	// The region, issuer and endpoints are derived from it (cognito).
	UserPoolID string `json:"user_pool_id,omitempty"`

	// Region overrides the region derived from the pool ID (cognito).
	Region string `json:"region,omitempty"`

	// Domain overrides the discovered user pool domain used for the
	// userInfo probe of hosted UI tokens (cognito).
	Domain string `json:"domain,omitempty"`

	// Endpoint overrides the cognito-idp base URL, for FIPS or
	// PrivateLink deployments (cognito).
	Endpoint string `json:"endpoint,omitempty"`

	// Issuer enables endpoint discovery and routes tokens whose iss
	// claim matches it to this provider (oidc).
	Issuer string `json:"issuer,omitempty"`

	// ClientID authenticates us to the introspection endpoint (oidc).
	ClientID string `json:"client_id,omitempty"`

	// ClientSecret authenticates us to the introspection endpoint (oidc).
	ClientSecret string `json:"client_secret,omitempty"`

	// Method is "introspection" (default) or "userinfo", for servers
	// without an introspection endpoint (oidc).
	Method string `json:"method,omitempty"`

	// IntrospectionEndpoint sets or overrides the discovered endpoint (oidc).
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// UserinfoEndpoint sets or overrides the discovered endpoint (oidc).
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
}

func (pc ProviderConfig) build(logger *zap.Logger, client *http.Client) (provider, error) {
	switch pc.Type {
	case "cognito":
		return newCognitoProvider(pc, logger, client)
	case "oidc":
		return newOIDCProvider(pc, logger, client)
	default:
		return nil, fmt.Errorf("unknown provider type %q (want cognito or oidc)", pc.Type)
	}
}

// discoveryDocument is the slice of OIDC discovery / RFC 8414 metadata we use.
type discoveryDocument struct {
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func fetchDiscovery(client *http.Client, issuer string) (discoveryDocument, error) {
	var doc discoveryDocument
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(url)
	if err != nil {
		return doc, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("fetching %s: unexpected status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("decoding discovery document from %s: %w", url, err)
	}
	return doc, nil
}

// checkUserinfo probes a userinfo endpoint: 200 → active (body as claims),
// 400/401 → inactive, anything else → infrastructure error.
func checkUserinfo(ctx context.Context, client *http.Client, url, providerName, token string) (verdict, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return verdict{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return verdict{}, fmt.Errorf("%s: userinfo request: %w", providerName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var claims map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			return verdict{}, fmt.Errorf("%s: decoding userinfo response: %w", providerName, err)
		}
		return verdict{active: true, claims: claims}, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		return verdict{reason: fmt.Sprintf("%s: userinfo rejected token (status %d)", providerName, resp.StatusCode)}, nil
	default:
		return verdict{}, fmt.Errorf("%s: userinfo returned unexpected status %d", providerName, resp.StatusCode)
	}
}
