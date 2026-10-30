module snai.pe/athens/example/sso

go 1.23.0

require (
	snai.pe/athens v0.0.0
	snai.pe/athens/ext/connector/github v0.0.0
	snai.pe/athens/ext/connector/oidc v0.0.0
)

require (
	github.com/coreos/go-oidc/v3 v3.14.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	snai.pe/go-htutil v0.0.0-20220706173936-b7f7873282e4 // indirect
)

replace (
	snai.pe/athens => ../..
	snai.pe/athens/ext/connector/github => ../../ext/connector/github
	snai.pe/athens/ext/connector/oidc => ../../ext/connector/oidc
)
