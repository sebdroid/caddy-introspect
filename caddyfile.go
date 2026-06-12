package introspect

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("token_introspect", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("token_introspect", httpcaddyfile.After, "basic_auth")
}

// parseCaddyfile wraps the provider in its own authentication handler, the
// same shape caddy-jwt uses, so the two directives stack (both must pass).
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	ti := new(TokenIntrospect)
	if err := ti.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"token_introspect": caddyconfig.JSON(ti, nil),
		},
	}, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	token_introspect {
//	    from_var     <name...>
//	    from_header  <name...>
//	    from_query   <name...>
//	    from_cookies <name...>
//
//	    cache_ttl         <duration>   # 0 disables caching
//	    cache_max_entries <int>
//	    fail_open         [true|false]
//	    timeout           <duration>
//
//	    user_claims <claim...> | passthrough
//	    meta_claims "<claim> -> <placeholder>"...
//
//	    provider cognito {
//	        user_pool_id <id>
//	        region       <region>
//	        domain       <url>
//	        endpoint     <url>
//	    }
//	    provider oidc {
//	        issuer                 <url>
//	        client_id              <id>
//	        client_secret          <secret>
//	        method                 introspection|userinfo
//	        introspection_endpoint <url>
//	        userinfo_endpoint      <url>
//	    }
//	}
//
// Source directives may repeat and take several names; the order in which
// they appear is the extraction priority. Provider order is the fallback
// chain for opaque tokens.
func (ti *TokenIntrospect) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch option := d.Val(); option {
		case "from_var", "from_header", "from_query", "from_cookies":
			from := strings.TrimSuffix(strings.TrimPrefix(option, "from_"), "s")
			names := d.RemainingArgs()
			if len(names) == 0 {
				return d.ArgErr()
			}
			for _, name := range names {
				ti.Sources = append(ti.Sources, TokenSource{From: from, Name: name})
			}

		case "cache_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing cache_ttl: %v", err)
			}
			ttl := caddy.Duration(dur)
			ti.CacheTTL = &ttl

		case "cache_max_entries":
			if !d.NextArg() {
				return d.ArgErr()
			}
			n, err := strconv.Atoi(d.Val())
			if err != nil || n <= 0 {
				return d.Errf("cache_max_entries must be a positive integer")
			}
			ti.CacheMaxEntries = n

		case "fail_open":
			ti.FailOpen = true
			if d.NextArg() {
				val, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("fail_open must be a boolean")
				}
				ti.FailOpen = val
			}

		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing timeout: %v", err)
			}
			ti.Timeout = caddy.Duration(dur)

		case "user_claims":
			claims := d.RemainingArgs()
			if len(claims) == 0 {
				return d.ArgErr()
			}
			ti.UserClaims = claims

		case "meta_claims":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			if ti.MetaClaims == nil {
				ti.MetaClaims = make(map[string]string)
			}
			for _, arg := range args {
				claim, placeholder, err := parseMetaClaim(arg)
				if err != nil {
					return d.Err(err.Error())
				}
				ti.MetaClaims[claim] = placeholder
			}

		case "provider":
			if !d.NextArg() {
				return d.ArgErr()
			}
			pc := ProviderConfig{Type: d.Val()}
			if err := pc.unmarshalCaddyfile(d); err != nil {
				return err
			}
			ti.Providers = append(ti.Providers, pc)

		default:
			return d.Errf("unrecognised subdirective %q", option)
		}
	}
	return nil
}

func (pc *ProviderConfig) unmarshalCaddyfile(d *caddyfile.Dispenser) error {
	set := func(target *string) error {
		if !d.NextArg() {
			return d.ArgErr()
		}
		*target = d.Val()
		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		var target *string
		switch option := d.Val(); option {
		case "user_pool_id":
			target = &pc.UserPoolID
		case "region":
			target = &pc.Region
		case "domain":
			target = &pc.Domain
		case "endpoint":
			target = &pc.Endpoint
		case "issuer":
			target = &pc.Issuer
		case "client_id":
			target = &pc.ClientID
		case "client_secret":
			target = &pc.ClientSecret
		case "method":
			target = &pc.Method
		case "introspection_endpoint":
			target = &pc.IntrospectionEndpoint
		case "userinfo_endpoint":
			target = &pc.UserinfoEndpoint
		default:
			return d.Errf("unrecognised provider option %q", option)
		}
		if err := set(target); err != nil {
			return err
		}
	}
	return nil
}

// parseMetaClaim parses "claim -> placeholder" with the claim name reused as
// the placeholder when no arrow is given, matching caddy-jwt's syntax.
func parseMetaClaim(arg string) (claim, placeholder string, err error) {
	claim, placeholder, found := strings.Cut(arg, "->")
	claim = strings.TrimSpace(claim)
	placeholder = strings.TrimSpace(placeholder)
	if !found {
		placeholder = claim
	}
	if claim == "" || placeholder == "" {
		return "", "", fmt.Errorf("invalid meta_claims entry %q: want \"claim -> placeholder\"", arg)
	}
	return claim, placeholder, nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*TokenIntrospect)(nil)
