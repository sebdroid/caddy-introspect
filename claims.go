package introspect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseUnverifiedClaims decodes a JWT payload WITHOUT verifying the
// signature; nil for anything that is not a JWT. Used for routing and
// TTL-capping only: the probe verdict is the sole authority on validity.
func parseUnverifiedClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// some non-compliant issuers pad their base64url
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

// lookupClaim resolves a claim by exact name first (so "cognito:groups"
// works), then as a dot-separated path into nested objects.
func lookupClaim(claims map[string]any, path string) (any, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	cur := any(claims)
	for part := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// stringify renders a claim value placeholder-friendly: scalars verbatim,
// arrays comma-joined, objects JSON-encoded.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = stringify(e)
		}
		return strings.Join(parts, ",")
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// parseScopes handles scope as a space-separated string (per spec) or an
// array (some identity providers).
func parseScopes(claims map[string]any) []string {
	switch s := claims["scope"].(type) {
	case string:
		return strings.Fields(s)
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func tokenExpiry(claims map[string]any) (time.Time, bool) {
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}
