package introspect

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// TokenSource is one place to look for a token; configured order is the
// extraction priority.
type TokenSource struct {
	// From is one of "var", "header", "query" or "cookie".
	From string `json:"from"`

	// Name is the variable, header, query parameter or cookie to read.
	Name string `json:"name"`
}

// extractTokens collects de-duplicated candidates in source priority order,
// stripping any "Bearer " prefix.
func (ti *TokenIntrospect) extractTokens(r *http.Request) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(v string) {
		v = stripBearer(strings.TrimSpace(v))
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, src := range ti.Sources {
		switch src.From {
		case "header":
			add(r.Header.Get(src.Name))
		case "query":
			add(r.URL.Query().Get(src.Name))
		case "cookie":
			if c, err := r.Cookie(src.Name); err == nil {
				add(c.Value)
			}
		case "var":
			// read the vars map directly so requests without one are safe
			if vars, ok := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
				if s, ok := vars[src.Name].(string); ok {
					add(s)
				}
			}
		}
	}
	return out
}

func stripBearer(v string) string {
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}
