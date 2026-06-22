# caddy-introspect
> http.authentication.providers.token_introspect

[![Go Build](https://github.com/sebdroid/caddy-introspect/actions/workflows/go.yml/badge.svg)](https://github.com/sebdroid/caddy-introspect/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/sebdroid/caddy-introspect)](https://goreportcard.com/report/github.com/sebdroid/caddy-introspect)

Caddy authentication provider that checks bearer tokens for revocation.

Signature validation alone cannot catch a revoked token: it keeps passing until it expires. This module asks the issuer directly on every request (or per cache TTL), so revoking a token actually locks it out. It speaks RFC 7662 token introspection and OIDC userinfo for any OAuth 2.0 / OpenID Connect server, and knows how to check Amazon Cognito tokens, which have no introspection endpoint at all.

[Documentation](https://caddyserver.com/docs/modules/http.authentication.providers.token_introspect)

## Install

Build with [`xcaddy`](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/sebdroid/caddy-introspect
```

> [!IMPORTANT]
> Requires Caddy v2.11.4 or newer - the oldest release this module is tested against that has no known vulnerabilities in its dependencies. Building with any newer Caddy works automatically: Go always selects the newer of your Caddy version and this minimum.

## Sample Caddyfile

```Caddyfile
{
	order token_introspect after basic_auth
}

api.example.com {
	token_introspect {
		from_header Authorization
		provider cognito {
			user_pool_id eu-west-1_AbCdEf123
		}
	}
	reverse_proxy backend:8080 {
		header_up X-User-Id {http.auth.user.id}
	}
}
```

That is a complete setup for a Cognito user pool: region, API endpoints and the hosted UI domain are all worked out from the pool ID.

> [!IMPORTANT]
> This module checks revocation only. It does not validate signatures, so pair it with [caddy-jwt](https://github.com/ggicci/caddy-jwt) for JWTs (see below), or use it alone with opaque tokens where the introspection endpoint is the only authority anyway.

## Use with caddy-jwt

Both directives are authentication handlers, so stacking them means a request must pass both: caddy-jwt proves the token is genuine, this module proves it is still alive.

```Caddyfile
api.example.com {
	route {
		jwtauth {
			jwk_url https://idp.example.com/.well-known/jwks.json
		}
		token_introspect {
			from_header Authorization
			provider oidc {
				issuer https://idp.example.com
				client_id caddy-gateway
				client_secret {env.INTROSPECT_CLIENT_SECRET}
			}
			user_claims passthrough
		}
		reverse_proxy backend:8080
	}
}
```

`user_claims passthrough` keeps the `{http.auth.user.id}` that caddy-jwt resolved instead of overwriting it.

> [!WARNING]
> Only use `passthrough` when a request carries a single token. With several candidates (say a cookie and a header), the token this module approves may not be the one caddy-jwt identified, and the identity would be misattributed. The default (identity from the issuer's response) is always safe.

## Configuration

```Caddyfile
token_introspect {
	from_var     <name...>        # token sources; at least one is required,
	from_header  <name...>        # and the order they appear is the priority
	from_query   <name...>
	from_cookies <name...>

	cache_ttl         60s         # how long verdicts are reused; 0 probes every request
	cache_max_entries 10000
	fail_open                     # allow requests through when the issuer is unreachable
	timeout           5s          # per-probe HTTP timeout

	user_claims sub username      # issuer-response fields tried for {http.auth.user.id}
	meta_claims "username -> user" "scope -> scopes"

	provider cognito { ... }      # repeatable; tokens are routed by their iss claim
	provider oidc { ... }
}
```

JSON config uses the same names under `http.authentication.providers.token_introspect`.

A `Bearer ` prefix is stripped from any source, so `from_header Authorization` works as expected. When a request carries several tokens, each is tried in priority order and a rejected one does not block the rest, so a stale cookie cannot lock out a fresh header token.

`from_var` reads a Caddy variable instead of the request, which is handy when another handler has already extracted the token.

### Caching

Verdicts (including rejections) are cached per token for `cache_ttl`, so a revoked token cannot flood your identity provider with probes. Revocation takes effect within one TTL at the latest.

Set `cache_ttl 0` to probe on every request for immediate revocation.

> [!WARNING]
> With caching off, every request becomes an API call to your identity provider. Watch your rate limits, especially Cognito's API quotas.

### When the issuer is unreachable

By default the module fails closed: no verdict, no entry. Set `fail_open` to let requests through when the issuer cannot answer (timeouts, server errors). A token the issuer has definitively rejected is always refused, regardless of `fail_open`.

### Provider: `cognito`

```Caddyfile
provider cognito {
	user_pool_id eu-west-1_AbCdEf123   # required, everything else is derived
	region       eu-west-1             # override if your pool ID has no region prefix
	domain       https://auth.example.com              # override the discovered domain
	endpoint     https://cognito-idp.eu-west-1.amazonaws.com   # FIPS or PrivateLink
}
```

Cognito has no introspection endpoint, so the module picks the right probe per token: hosted UI / SSO tokens (with the `openid` scope) are checked against your pool domain's `userInfo` endpoint, and `InitiateAuth` tokens against the `GetUser` API. No AWS credentials are needed, the access token itself is the credential.

> [!IMPORTANT]
> Only access tokens can be checked. Cognito offers no way to check an ID token for revocation, so ID tokens are always rejected. Make sure your clients send access tokens.

> [!NOTE]
> Tokens must carry the `openid` or `aws.cognito.signin.user.admin` scope to be checkable. A token with only custom resource-server scopes cannot be probed and is rejected, so grant one of those scopes alongside your custom ones. Revocation itself must be enabled on the app client (`EnableTokenRevocation`, on by default for new clients).

### Provider: `oidc`

```Caddyfile
provider oidc {
	issuer        https://idp.example.com    # endpoints come from discovery
	client_id     caddy-gateway
	client_secret {env.INTROSPECT_CLIENT_SECRET}
	method        introspection              # or: userinfo
	introspection_endpoint https://...       # set if discovery does not advertise it
	userinfo_endpoint      https://...
}
```

Works with any RFC 7662 introspection endpoint, including opaque (non-JWT) tokens.

> [!TIP]
> Some providers support introspection but do not advertise it in their discovery document; set `introspection_endpoint` yourself in that case. For providers with no introspection at all (Auth0, for example), `method userinfo` checks the token against the userinfo endpoint instead.

Tokens are routed to the provider matching their `iss` claim, and a token from an issuer you have not configured is rejected without being sent anywhere. Opaque tokens, which carry no issuer, try the providers in the order they are configured.

### Identity and metadata

On success, `{http.auth.user.id}` is set from the first `user_claims` field found in the issuer's response (default: `sub`, then `username`), and each `meta_claims` mapping becomes a `{http.auth.user.<name>}` placeholder. Nested fields use dots (`settings.tier -> tier`); names with their own dots or colons, like `cognito:groups`, just work.

### Customising the 401

Failures surface as standard Caddy errors, so `handle_errors` owns the response:

```Caddyfile
handle_errors {
	@unauth expression {http.error.status_code} == 401
	respond @unauth `{"error":"unauthorised"}` 401
}
```

The failure reason is available as `{http.auth.token_introspect.error}`.

### Logging

Definitive rejections (revoked token, unknown issuer, uncheckable scopes) log at `DEBUG` with the full reason, so a bot replaying a dead token cannot flood your logs. Probe failures and fail-open decisions log at `WARN`, provider configuration concerns at startup at `WARN` or `INFO`. Token values are never logged. Successful requests are not logged here at all; Caddy's access log already carries the authenticated `user_id`.

## Licence

caddy-introspect is licensed under the [Apache License 2.0](LICENSE): use it, modify it, and redistribute it freely, commercially or not. When you redistribute, include the licence, carry forward the attribution notices from the [NOTICE](NOTICE) file, and mark any files you change as modified - that keeps the credit with the original work and the responsibility for changes with whoever made them.
