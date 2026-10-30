# Athens

Athens is an OpenID Connect and OAuth 2.0 authorization server, written in Go
and designed to be embedded in your own application rather than run as a
separate product.

It handles the protocol: authorization code flow with PKCE, refresh tokens,
client credentials, device authorization, token exchange, introspection,
revocation, dynamic client registration, discovery and JWKS. Everything else
is pluggable and lives behind small interfaces: where users come from, what
tokens look like, how keys rotate, and where state is stored.

## Why

Most OIDC servers are opinionated about the token format (JWT), the storage
(their database) and the deployment (a separate service with its own config
language). Athens inverts that. You bring the storage and the identity
providers; Athens brings the endpoints. Token formats are a plugin, and the
primary motivating case is issuing [Biscuit](https://www.biscuitsec.org/)
tokens from a standard OIDC flow, so services can attenuate capabilities
offline while clients keep speaking plain OAuth.

## Overview

```
                 ┌──────────────┐
  browser ──────>│ /authorize   │──> Connector (Google, GitHub, any OIDC, ...)
                 │ /callback    │<──
                 │              │
  client ───────>│ /oauth/token │──> TokenMinter (JWT, opaque, biscuit, ...)
                 │              │──> Store (codes, tokens, sessions, users)
  services ─────>│ /userinfo    │
                 │ /introspect  │──> TokenValidator
                 │ /revoke      │
                 │ /jwks        │──> KeyManager
                 └──────────────┘
```

An `athens.Server` is a plain struct. You fill in the fields and call
`Serve` on a listener:

```go
jwt := jwtminter.New(jwtminter.Config{Issuer: issuer})
minter := athens.OpenIDMinter{
	Access:  jwt,
	ID:      jwt,
	Refresh: opaque.New(opaque.Config{Store: store}),
}

srv := &athens.Server{
	Connectors: []athens.ConnectorConfig{
		{ID: "google", Name: "Google", Connector: google},
	},
	Clients:   clients,
	Minter:    minter,
	Validator: minter,
	Keys:      keys,
	Store:     store,
	OpenIDConfig: athens.OpenIDConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/oauth/token",
		JWKSURI:               issuer + "/oauth/jwks",
		// ...
	},
}
log.Fatal(srv.Serve(listener))
```

## Extension points

| Interface | Responsibility | Provided implementations |
|---|---|---|
| `Connector` | Authenticate a user against an upstream provider | `ext/connector/oidc` (any OIDC issuer), `ext/connector/github` |
| `TokenMinter` | Turn a claims map into a token | `jwt`, `opaque`, `ext/minter/biscuit` |
| `TokenValidator` | Parse and verify a token back into claims | the minters above, `TrustedIssuer`, `federation.Validator`, `MultiValidator` |
| `ExchangeGuard` | Decide whether a token exchange is allowed | default: strict scope subset |
| `KeyManager` | Supply the current signing key and the public key set | `RotatingKeyManager` |
| `Store` | Persist codes, token status, auth sessions and users | you implement this on your own database |
| `ClientStore` / `ClientRegistrar` | Look up clients; optionally allow RFC 7591/7592 registration | you implement this |

Connectors and minters deliberately use only standard library types in their
signatures. A minter module does not import Athens, and Athens inspects minter
results structurally, looking for methods such as `Token()`, `TTL()` and
`IDToken()`. This keeps each extension in its own Go module with its own
dependency tree, so pulling in the biscuit minter does not force
`biscuit-go` on users of the JWT minter.

### Composing minters

- `OpenIDMinter` issues an access token, an ID token and a refresh token,
  each from its own minter.
- `AccessRefreshMinter` does the same without an ID token, for pure OAuth
  clients.
- `RoutingMinter` picks a minter by requested token type URI or by the
  presence of a claim, which is how a single server can hand out JWTs to
  one audience and biscuits to another.

### Trust between servers

Two mechanisms let one Athens instance accept tokens issued by another and
exchange them for its own, following RFC 8693:

- `TrustedIssuer` trusts a single OIDC issuer by discovery and JWKS. No
  configuration beyond the issuer URL.
- `federation` implements OpenID Federation trust chains: entity statements,
  trust anchors, a caching resolver and a validator that verifies a token
  against the resolved chain.

Set either as `ExchangeValidator` on the server to enable the token exchange
grant.

## Endpoints

| Method | Path | Spec |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OIDC Discovery |
| GET | `/connectors` | List configured login providers |
| GET, POST | `/authorize` | Authorization endpoint, with PKCE |
| GET | `/callback` | Upstream provider callback |
| POST | `/oauth/token` | `authorization_code`, `refresh_token`, `client_credentials`, `device_code`, `token-exchange` |
| GET | `/oauth/jwks` | JSON Web Key Set |
| GET | `/userinfo` | OIDC UserInfo |
| POST | `/oauth/revoke` | RFC 7009 revocation |
| POST | `/oauth/introspect` | RFC 7662 introspection |
| POST | `/oauth/device` | RFC 8628 device authorization |
| POST, GET, PUT, DELETE | `/oauth/register[/{client_id}]` | RFC 7591/7592, only when `Clients` implements `ClientRegistrar` |

## Running the example

The example in `example/sso` runs three processes in one binary and needs no
configuration:

- an SSO server on port 8080, with a Google connector using Google's public
  gcloud client ID and a local test connector that logs anyone in,
- a second Athens instance on port 8082 that trusts the SSO through
  federation and offers token exchange,
- a tiny test client on port 8081 with login buttons.

```sh
cd example/sso
go run .
```

Then open <http://localhost:8081>, log in, inspect the tokens, and click
"Exchange at Service" to trade the SSO token for a service token.

Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`, or `MICROSOFT_CLIENT_ID`
and `MICROSOFT_CLIENT_SECRET`, to add those providers. `GOOGLE_CLIENT_ID`
and `GOOGLE_CLIENT_SECRET` override the default public credentials, which
you should do before using the example for anything beyond a demo.

## Module layout

```
snai.pe/athens                        core server, interfaces, keys, JWKS, trusted issuer
snai.pe/athens/jwt                    JWT minter and validator
snai.pe/athens/opaque                 opaque token minter backed by your store
snai.pe/athens/federation             OpenID Federation resolver and validator
snai.pe/athens/ext/minter/biscuit     Biscuit token minter (separate module)
snai.pe/athens/ext/connector/oidc     generic OIDC connector (separate module)
snai.pe/athens/ext/connector/github   GitHub OAuth connector (separate module)
snai.pe/athens/example/sso            runnable end-to-end example
```

The `ext` packages and the example are separate Go modules so that their
third-party dependencies stay out of the core module.

## Status

Athens is early. The protocol surface is in place and the example works end to
end, but the API has not stabilised and there is no test suite yet. Expect
breaking changes.

## License

MIT. See [LICENSE](LICENSE).
