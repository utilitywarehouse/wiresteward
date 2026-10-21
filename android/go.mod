module github.com/utilitywarehouse/wiresteward/android

go 1.27.3

replace github.com/utilitywarehouse/wiresteward => ../

require (
	github.com/stretchr/testify v1.12.1
	github.com/utilitywarehouse/wiresteward v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.61.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.8.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
