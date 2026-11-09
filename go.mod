module github.com/awapf/nebula-oidc-signer

go 1.27.3

replace github.com/awapf/terraform-provider-nebula => ../terraform-provider-nebula

require (
	github.com/awapf/terraform-provider-nebula v0.0.0-00010101000000-000000000000
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/slackhq/nebula v1.12.0
)

require (
	filippo.io/bigmod v0.1.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
