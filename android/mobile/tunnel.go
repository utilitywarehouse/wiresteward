package mobile

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"

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

	// createTUN wraps the file descriptor of the VPN interface and newBind
	// creates the socket layer of the device, they are replaced in tests.
	createTUN func(fd int) (tun.Device, error)
	newBind   func() conn.Bind

	mu         sync.Mutex
	privateKey wgtypes.Key
	leases     map[string]*devicemanager.WirestewardPeerConfig // by device name
	dev        *device.Device
	nat        *natTun
	peerKeys   map[wgtypes.Key]struct{} // peers of dev
	routesKey  string                   // routes the current interface was established with
	stopped    bool
}

// createUnmonitoredTUN skips the netlink link monitoring that Android does not
// allow for apps. The mtu is set by VpnService.Builder instead.
func createUnmonitoredTUN(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}

func newTunnel(mtu int, keyFile string, provider TunProvider) *tunnel {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	return &tunnel{
		mtu:       mtu,
		keyFile:   keyFile,
		provider:  provider,
		logger:    logging.NewLogger("wireguard-go"),
		createTUN: createUnmonitoredTUN,
		newBind:   conn.NewDefaultBind,
		leases:    map[string]*devicemanager.WirestewardPeerConfig{},
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
	peerKeys := map[wgtypes.Key]struct{}{}
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
		peerKeys[cfg.PublicKey] = struct{}{}
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
		var removed []wgtypes.Key
		for key := range t.peerKeys {
			if _, ok := peerKeys[key]; !ok {
				removed = append(removed, key)
			}
		}
		t.nat.update(natRoutes)
		if err := t.dev.IpcSet(uapiConfig(t.privateKey, peers, removed)); err != nil {
			return err
		}
		t.peerKeys = peerKeys
		return nil
	}

	fd, err := t.provider.Establish(tunLocalAddress, 32, routesKey, t.mtu)
	if err != nil {
		return fmt.Errorf("cannot establish vpn interface: %w", err)
	}
	// Establishing a new interface replaces the previous one, so from here on
	// the current device is dead whether or not the new one comes up.
	t.closeDeviceLocked()
	tunDev, err := t.createTUN(fd)
	if err != nil {
		syscall.Close(fd)
		return fmt.Errorf("cannot create tun from fd: %w", err)
	}
	nat := newNatTun(tunDev)
	nat.update(natRoutes)
	dev := device.NewDevice(nat, t.newBind(), t.logger)
	if err := dev.IpcSet(uapiConfig(t.privateKey, peers, nil)); err != nil {
		dev.Close()
		return fmt.Errorf("cannot configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("cannot bring device up: %w", err)
	}
	t.dev, t.nat, t.peerKeys, t.routesKey = dev, nat, peerKeys, routesKey
	return nil
}

// closeDeviceLocked closes the wireguard-go device and the underlying tun
// interface, the next apply establishes a new one.
func (t *tunnel) closeDeviceLocked() {
	if t.dev != nil {
		t.dev.Close()
	}
	t.dev, t.nat, t.peerKeys, t.routesKey = nil, nil, nil, ""
}

// Stop closes the wireguard-go device and the underlying tun interface.
func (t *tunnel) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	t.closeDeviceLocked()
	t.leases = map[string]*devicemanager.WirestewardPeerConfig{}
}
