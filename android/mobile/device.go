package mobile

import "github.com/utilitywarehouse/wiresteward/internal/devicemanager"

// tunnelDevice is the devicemanager.Backend of one configured device. All of them share
// the tunnel, which merges their leases into the single VPN interface.
type tunnelDevice struct {
	name   string
	tunnel *tunnel
}

// Run does nothing, the interface is established with the first lease.
// Name returns the name of the configured device.
func (d *tunnelDevice) Name() string { return d.name }

func (d *tunnelDevice) Run() error { return nil }

// Stop does nothing, the tunnel is stopped once for all the devices.
func (d *tunnelDevice) Stop() {}

func (d *tunnelDevice) PublicKey() (string, error) { return d.tunnel.PublicKey(), nil }

func (d *tunnelDevice) Configure(_, lease *devicemanager.WirestewardPeerConfig) error {
	return d.tunnel.Configure(d.name, lease)
}
