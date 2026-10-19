package mobile

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/devicemanager"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var tunnelLogger = logging.NewLogger("wiresteward")

// TunProvider is implemented by the Android app (a VpnService). It is called
// whenever the set of routes changes.
type TunProvider interface {
	// Establish builds the VPN interface (VpnService.Builder: addAddress,
	// addRoute for every entry of routes, setMtu, establish) and returns its
	// file descriptor. Ownership of the descriptor moves to the agent, so the
	// app must hand it over with ParcelFileDescriptor.detachFd().
	// routes is a newline separated list of CIDRs.
	Establish(address string, prefixLen int, routes string, mtu int) (int, error)
}

// tunnel is the single VPN interface and wireguard-go device shared by all the
// configured devices. Android only allows one VPN interface per app, so the
// leases of all devices are merged: one peer per device, the union of their
// allowed IPs as routes and one private key (every server leases an address
// to the public key it is given).
//
// The tun interface cannot be created upfront: Android needs the routes,
// which are part of the leases, to establish it. It is (re)established when
// the set of routes changes. Other lease changes are applied to the running
// device.
type tunnel struct {
	mtu      int
	keyFile  string
	provider TunProvider
	logger   *device.Logger

	mu         sync.Mutex
	privateKey wgtypes.Key
	leases     map[string]*devicemanager.WirestewardPeerConfig // by device name
	dev        *device.Device
	nat        *natTun
	routesKey  string // routes the current interface was established with
	stopped    bool
}

func newTunnel(mtu int, keyFile string, provider TunProvider) *tunnel {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	return &tunnel{
		mtu:      mtu,
		keyFile:  keyFile,
		provider: provider,
		logger:   logging.NewLogger("wireguard-go"),
		leases:   map[string]*devicemanager.WirestewardPeerConfig{},
	}
}

// Run loads the private key from disk, or generates and stores a new one.
func (t *tunnel) Run() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b, err := os.ReadFile(t.keyFile); err == nil {
		key, err := wgtypes.ParseKey(strings.TrimSpace(string(b)))
		if err == nil {
			t.privateKey = key
			return nil
		}
		tunnelLogger.Errorf("Invalid key in %s, generating a new one: %v", t.keyFile, err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(t.keyFile, []byte(key.String()+"\n"), 0600); err != nil {
		return fmt.Errorf("cannot store private key: %w", err)
	}
	t.privateKey = key
	return nil
}

// PublicKey returns the base64 public key that is sent to the servers.
func (t *tunnel) PublicKey() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.privateKey.PublicKey().String()
}

// Configure sets the lease of the named device and applies the merged config.
// On failure the previous lease of the device is kept.
func (t *tunnel) Configure(name string, cfg *devicemanager.WirestewardPeerConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return fmt.Errorf("tunnel stopped")
	}
	prev, had := t.leases[name]
	t.leases[name] = cfg
	if err := t.applyLocked(); err != nil {
		if had {
			t.leases[name] = prev
		} else {
			delete(t.leases, name)
		}
		return err
	}
	return nil
}

func (t *tunnel) applyLocked() error {
	names := make([]string, 0, len(t.leases))
	for name := range t.leases {
		names = append(names, name)
	}
	sort.Strings(names)

	var peers []*wgtypes.PeerConfig
	leaseAddr := map[string][4]byte{}
	owner := map[string]string{} // allowed ip -> device
	for _, name := range names {
		cfg := t.leases[name]
		ip4 := cfg.LocalAddress.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("device %s: lease address %s is not IPv4", name, cfg.LocalAddress)
		}
		leaseAddr[name] = [4]byte(ip4)
		for _, ip := range cfg.AllowedIPs {
			if o, dup := owner[ip.String()]; dup {
				tunnelLogger.Errorf("Allowed ip %s is offered by both %s and %s, %s wins", ip.String(), o, name, name)
			}
			owner[ip.String()] = name
		}
		peers = append(peers, cfg.PeerConfig)
	}
	routes := make([]string, 0, len(owner))
	natRoutes := make([]natRoute, 0, len(owner))
	for cidr, name := range owner {
		routes = append(routes, cidr)
		natRoutes = append(natRoutes, natRoute{netip.MustParsePrefix(cidr), leaseAddr[name]})
	}
	sort.Strings(routes)
	routesKey := strings.Join(routes, "\n")

	if t.dev != nil && routesKey == t.routesKey {
		t.nat.update(natRoutes)
		return t.dev.IpcSet(uapiConfig(t.privateKey, peers))
	}

	fd, err := t.provider.Establish(tunLocalAddress, 32, routesKey, t.mtu)
	if err != nil {
		return fmt.Errorf("cannot establish vpn interface: %w", err)
	}
	// The unmonitored variant skips the netlink link monitoring that Android
	// does not allow for apps. The mtu is set by VpnService.Builder instead.
	tunDev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return fmt.Errorf("cannot create tun from fd: %w", err)
	}
	nat := newNatTun(tunDev)
	nat.update(natRoutes)
	dev := device.NewDevice(nat, conn.NewDefaultBind(), t.logger)
	if err := dev.IpcSet(uapiConfig(t.privateKey, peers)); err != nil {
		dev.Close()
		return fmt.Errorf("cannot configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("cannot bring device up: %w", err)
	}
	if t.dev != nil {
		t.dev.Close()
	}
	t.dev, t.nat, t.routesKey = dev, nat, routesKey
	return nil
}

// Stop closes the wireguard-go device and the underlying tun interface.
func (t *tunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.dev != nil {
		t.dev.Close()
		t.dev, t.nat, t.routesKey = nil, nil, ""
	}
	t.leases = map[string]*devicemanager.WirestewardPeerConfig{}
}
