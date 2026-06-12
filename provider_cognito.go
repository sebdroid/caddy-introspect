package introspect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"go.uber.org/zap"
)

// adminScope authorises self-service API calls such as GetUser.
const adminScope = "aws.cognito.signin.user.admin"

// cognitoProvider checks Cognito access tokens for revocation. Cognito has
// no introspection endpoint, so the probe depends on the token's scopes:
// openid (hosted UI / SSO) → GET {domain}/oauth2/userInfo; admin scope or no
// scopes (InitiateAuth) → the unsigned GetUser API call, where the access
// token itself is the credential. ID tokens cannot be probed at all.
type cognitoProvider struct {
	poolID      string
	iss         string
	apiEndpoint string // cognito-idp base URL, GetUser target
	userinfoURL string // {domain}/oauth2/userInfo; "" if unknown
	logger      *zap.Logger
	client      *http.Client
}

func newCognitoProvider(pc ProviderConfig, logger *zap.Logger, client *http.Client) (*cognitoProvider, error) {
	if pc.UserPoolID == "" {
		return nil, fmt.Errorf("cognito provider: user_pool_id is required")
	}
	region := pc.Region
	if region == "" {
		// Pool IDs embed their region: "eu-west-1_AbCdEf123".
		i := strings.Index(pc.UserPoolID, "_")
		if i <= 0 {
			return nil, fmt.Errorf("cognito provider: cannot derive region from user_pool_id %q; set region explicitly", pc.UserPoolID)
		}
		region = pc.UserPoolID[:i]
	}
	base := pc.Endpoint
	if base == "" {
		base = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com", region)
	}
	base = strings.TrimSuffix(base, "/")

	p := &cognitoProvider{
		poolID:      pc.UserPoolID,
		iss:         base + "/" + pc.UserPoolID,
		apiEndpoint: base + "/",
		logger:      logger,
		client:      client,
	}

	if pc.Domain != "" {
		p.userinfoURL = strings.TrimSuffix(pc.Domain, "/") + "/oauth2/userInfo"
	} else {
		// the pool's discovery document advertises the domain's userinfo endpoint
		doc, err := fetchDiscovery(client, p.iss)
		if err != nil {
			logger.Warn("could not fetch Cognito discovery document; hosted-UI (SSO) tokens will be rejected until 'domain' is configured",
				zap.String("user_pool_id", pc.UserPoolID), zap.Error(err))
		} else if doc.UserinfoEndpoint != "" {
			p.userinfoURL = doc.UserinfoEndpoint
		} else {
			logger.Info("user pool has no domain configured; hosted-UI (SSO) tokens cannot be issued or checked, InitiateAuth tokens are unaffected",
				zap.String("user_pool_id", pc.UserPoolID))
		}
	}
	return p, nil
}

func (p *cognitoProvider) name() string        { return "cognito/" + p.poolID }
func (p *cognitoProvider) issuer() string      { return p.iss }
func (p *cognitoProvider) opaqueCapable() bool { return false }

func (p *cognitoProvider) check(ctx context.Context, token string, claims map[string]any) (verdict, error) {
	if claims == nil {
		return verdict{reason: p.name() + ": not a JWT; Cognito access tokens are always JWTs"}, nil
	}
	if use, _ := claims["token_use"].(string); use != "access" {
		return verdict{reason: fmt.Sprintf("%s: %q tokens cannot be checked for revocation; present an access token", p.name(), use)}, nil
	}
	scopes := parseScopes(claims)
	hasOpenID := slices.Contains(scopes, "openid")
	switch {
	case hasOpenID && p.userinfoURL != "":
		return checkUserinfo(ctx, p.client, p.userinfoURL, p.name(), token)
	case slices.Contains(scopes, adminScope) || len(scopes) == 0:
		return p.checkGetUser(ctx, token)
	case hasOpenID:
		return verdict{reason: p.name() + ": token needs the userInfo probe but no user pool domain is known; set 'domain'"}, nil
	default:
		return verdict{reason: fmt.Sprintf("%s: token has neither 'openid' nor '%s' scope, so no probe can check it; grant one of those scopes", p.name(), adminScope)}, nil
	}
}

// checkGetUser probes the user pools API with the access token as the sole
// credential (no AWS signature involved). Authorisation and account-state
// errors are definitive verdicts; throttling and server errors are not.
func (p *cognitoProvider) checkGetUser(ctx context.Context, token string) (verdict, error) {
	body, err := json.Marshal(map[string]string{"AccessToken": token})
	if err != nil {
		return verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiEndpoint, bytes.NewReader(body))
	if err != nil {
		return verdict{}, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSCognitoIdentityProviderService.GetUser")
	resp, err := p.client.Do(req)
	if err != nil {
		return verdict{}, fmt.Errorf("%s: GetUser request: %w", p.name(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		var out struct {
			Username       string
			UserAttributes []struct{ Name, Value string }
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return verdict{}, fmt.Errorf("%s: decoding GetUser response: %w", p.name(), err)
		}
		claims := map[string]any{
			"Username": out.Username,
			"username": out.Username, // alias so the default user_claims resolve
		}
		for _, attr := range out.UserAttributes {
			claims[attr.Name] = attr.Value
		}
		return verdict{active: true, claims: claims}, nil
	}

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var apiErr struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &apiErr)
	// __type is sometimes namespaced, e.g. "com.amazon...#NotAuthorizedException".
	if i := strings.LastIndex(apiErr.Type, "#"); i >= 0 {
		apiErr.Type = apiErr.Type[i+1:]
	}

	switch apiErr.Type {
	case "NotAuthorizedException", "UserNotFoundException",
		"UserNotConfirmedException", "PasswordResetRequiredException":
		return verdict{reason: fmt.Sprintf("%s: GetUser: %s: %s", p.name(), apiErr.Type, apiErr.Message)}, nil
	default:
		return verdict{}, fmt.Errorf("%s: GetUser failed: status %d, %s: %s", p.name(), resp.StatusCode, apiErr.Type, apiErr.Message)
	}
}
