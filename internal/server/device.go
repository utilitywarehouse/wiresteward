package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/config"
)

// ServerDevice represents a wireguard network device on the system, setup
// for use with kernel space wireguard. This is utilised by the server-side
// wiresteward.
type ServerDevice struct {
	deviceAddress netlink.Addr
	deviceMTU     int
	iptablesRule  []string
	keyFilename   string
	link          netlink.Link
	listenPort    int
}

func newServerDevice(cfg *config.ServerConfig) *ServerDevice {
	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name:   cfg.DeviceName,
			TxQLen: 1000,
		},
	}
	return &ServerDevice{
		deviceAddress: netlink.Addr{
			IPNet: netipx.PrefixIPNet(cfg.WireguardIPPrefix),
		},
		deviceMTU: cfg.DeviceMTU,
		iptablesRule: []string{
			"-s", cfg.WireguardIPPrefix.String(),
			"-d", strings.Join(cfg.AllowedIPs, ","),
			"-j", "MASQUERADE",
		},
		keyFilename: cfg.KeyFilename,
		link:        link,
		listenPort:  cfg.WireguardListenPort,
	}
}

// Start will create and setup the wireguard device.
func (sd *ServerDevice) Start() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Verbosef("Adding iptables rule %v", sd.iptablesRule)
	if err := ipt.AppendUnique("nat", "POSTROUTING", sd.iptablesRule...); err != nil {
		return err
	}
	h := netlink.Handle{}
	defer h.Delete()
	logger.Verbosef(
		"Creating device %s with address %s",
		sd.link.Attrs().Name,
		sd.deviceAddress,
	)
	if err := h.LinkAdd(sd.link); err != nil {
		return err
	}
	if err := sd.ensureLinkIsUp(h); err != nil {
		return err
	}
	if err := sd.configureWireguard(); err != nil {
		return err
	}
	if err := h.AddrAdd(sd.link, &sd.deviceAddress); err != nil {
		return err
	}
	mtu := sd.deviceMTU
	if mtu <= 0 {
		defaultMTU, err := sd.defaultMTU(h)
		if err != nil {
			logger.Errorf(
				"Could not detect default MTU, defaulting to 1500: %v",
				err,
			)
			defaultMTU = 1500
		}
		mtu = defaultMTU - 80
	}
	logger.Verbosef(
		"Setting MTU to %d on device %s", mtu, sd.link.Attrs().Name)
	if err := h.LinkSetMTU(sd.link, mtu); err != nil {
		return err
	}
	logger.Verbosef("Initialised device %s", sd.link.Attrs().Name)
	return nil
}

// Stop will cleanup and delete the wireguard device.
func (sd *ServerDevice) Stop() error {
	h := netlink.Handle{}
	defer h.Delete()
	if err := h.LinkSetDown(sd.link); err != nil {
		return err
	}
	if err := h.LinkDel(sd.link); err != nil {
		return err
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Verbosef("Removing iptables rule %v", sd.iptablesRule)
	if err := ipt.Delete("nat", "POSTROUTING", sd.iptablesRule...); err != nil {
		return err
	}
	logger.Verbosef("Cleaned up device %s", sd.link.Attrs().Name)
	return nil
}

func (sd *ServerDevice) privateKey() (wgtypes.Key, error) {
	kd, err := os.ReadFile(sd.keyFilename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Verbosef(
				"No key found in %s, generating a new private key",
				sd.keyFilename,
			)
			keyDir := filepath.Dir(sd.keyFilename)
			err := os.MkdirAll(keyDir, 0755)
			if err != nil {
				logger.Errorf(
					"Unable to create directory=%s",
					keyDir,
				)
				return wgtypes.Key{}, err
			}
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return wgtypes.Key{}, err
			}
			if err := os.WriteFile(sd.keyFilename, []byte(key.String()), 0600); err != nil {
				return wgtypes.Key{}, err
			}
			return key, nil
		}
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(string(kd))
}

func (sd *ServerDevice) configureWireguard() error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			logger.Errorf(
				"Failed to close wireguard client: %v",
				err,
			)
		}
	}()
	key, err := sd.privateKey()
	if err != nil {
		return err
	}
	logger.Verbosef(
		"Configuring wireguard on port %v with public key %s",
		sd.listenPort,
		key.PublicKey(),
	)
	return wg.ConfigureDevice(sd.link.Attrs().Name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &sd.listenPort,
	})
}

// defaultMTU returns the MTU of the default route or the respective device.
func (sd *ServerDevice) defaultMTU(h netlink.Handle) (int, error) {
	routes, err := h.RouteList(nil, unix.AF_INET)
	if err != nil {
		return -1, err
	}
	for _, r := range routes {
		if r.Dst == nil {
			if r.MTU > 0 {
				return r.MTU, nil
			}
			link, err := h.LinkByIndex(r.LinkIndex)
			if err != nil {
				return -1, err
			}
			return link.Attrs().MTU, nil
		}
	}
	return -1, fmt.Errorf("could not detect default route")
}

// In Flatcar linux, the link automatically transitions to the UP state. In
// Debian, the link will stay in the DOWN state until LinkSetUp is called.
// Additionally, if LinkSetUp is called in Flatcar, the link appears to properly
// get the UP flag set but subsequent AddrAdd() calls might fail, indicating
// it did not properly set up. This method, will wait for the link to come up
// automatically and will explicitly bring it up after timeout.
func (sd *ServerDevice) ensureLinkIsUp(h netlink.Handle) error {
	tries := 1
	for {
		link, err := h.LinkByName(sd.link.Attrs().Name)
		if err != nil {
			return err
		}
		logger.Verbosef(
			"waiting for device %s to come up, current flags: %s",
			sd.link.Attrs().Name,
			link.Attrs().Flags,
		)
		if link.Attrs().Flags&net.FlagUp != 0 {
			logger.Verbosef(
				"device %s came up automatically",
				sd.link.Attrs().Name,
			)
			return nil
		}
		if tries > 4 {
			logger.Verbosef(
				"timeout waiting for device %s to come up automatically",
				sd.link.Attrs().Name,
			)
			return h.LinkSetUp(sd.link)
		}
		tries++
		time.Sleep(time.Second)
	}
}
