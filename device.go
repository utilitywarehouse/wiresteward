package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type AgentDevice interface {
	Name() string
	Run() error
	Stop()
}

// TunDevice represents a tun network device on the system, setup for use with
// user space wireguard. This is utilised by the agent-side wiresteward, to
// provide a cross-platform implementation basd on wireguard-go.
type TunDevice struct {
	device     *device.Device
	deviceMTU  int
	deviceName string
	errs       chan error
	logger     *device.Logger
	uapi       net.Listener
	uapiSocket *os.File
	stop       chan bool
	stopped    chan bool
}

func newTunDevice(name string, mtu int) *TunDevice {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	return &TunDevice{
		deviceMTU:  mtu,
		deviceName: name,
		errs:       make(chan error),
		logger:     newLogger(fmt.Sprintf("wireguard-go/%s", name)),
	}
}

// Name returns the name of the device.
func (td *TunDevice) Name() string {
	return td.deviceName
}

// Run starts processing UAPI operations for the device.
func (td *TunDevice) Run() error {
	if err := td.init(); err != nil {
		return err
	}
	go td.run()
	return nil
}

// Stop will stop the device and cleanup underlying resources.
func (td *TunDevice) Stop() {
	if td.stop == nil {
		return
	}
	close(td.stop)
	<-td.stopped
}

func (td *TunDevice) init() error {
	tunDevice, err := tun.CreateTUN(td.deviceName, td.deviceMTU)
	if err != nil {
		return fmt.Errorf("Cannot create tun device %v", err)
	}

	device := device.NewDevice(tunDevice, td.logger)
	td.logger.Info.Println("Device started")

	uapiSocket, err := ipc.UAPIOpen(td.deviceName)
	if err != nil {
		device.Close()
		return fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(td.deviceName, uapiSocket)
	if err != nil {
		if err := td.uapiSocket.Close(); err != nil {
			td.logger.Error.Println(err)
		}
		device.Close()
		return fmt.Errorf("Failed to listen on uapi socket: %v", err)
	}

	td.device = device
	td.uapiSocket = uapiSocket
	td.uapi = uapi
	return nil
}

func (td *TunDevice) run() {
	td.stop = make(chan bool)
	td.stopped = make(chan bool)

	go func() {
		for {
			conn, err := td.uapi.Accept()
			if err != nil {
				td.errs <- err
				return
			}
			go td.device.IpcHandle(conn)
		}
	}()
	td.logger.Info.Println("UAPI listener started")

	select {
	case <-td.stop:
		td.logger.Info.Printf("Device stopping...")
	case err := <-td.errs:
		td.logger.Error.Printf("Device error: %v", err)
	case <-td.device.Wait():
		td.logger.Info.Printf("Device stopped")
	}

	td.cleanup()
	close(td.stopped)
}

func (td *TunDevice) cleanup() {
	td.logger.Info.Println("Shutting down")
	if err := td.uapi.Close(); err != nil {
		td.logger.Error.Println(err)
	}
	td.logger.Debug.Println("UAPI listener stopped")
	if err := td.uapiSocket.Close(); err != nil {
		td.logger.Error.Println(err)
	}
	td.logger.Debug.Println("UAPI socket stopped")
	td.device.Close()
	td.logger.Debug.Println("Device closed")
}

// WireguardDevice represents a wireguard network device on the system, setup
// for use with kernel space wireguard. This is utilised by the server-side
// wiresteward.
type WireguardDevice struct {
	deviceAddress netlink.Addr
	deviceMTU     int
	iptablesRule  []string
	keyFilename   string
	link          netlink.Link
	listenPort    int
}

func newWireguardDevice(cfg *serverConfig) *WireguardDevice {
	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name:   cfg.DeviceName,
			TxQLen: 1000,
		},
	}
	return &WireguardDevice{
		deviceAddress: netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cfg.WireguardIPAddress,
				Mask: cfg.WireguardIPNetwork.Mask,
			},
		},
		deviceMTU: cfg.DeviceMTU,
		iptablesRule: []string{
			"-s", cfg.WireguardIPNetwork.String(),
			"-d", strings.Join(cfg.AllowedIPs, ","),
			"-j", "MASQUERADE",
		},
		keyFilename: cfg.KeyFilename,
		link:        link,
		listenPort:  cfg.WireguardListenPort,
	}
}

// Start will create and setup the wireguard device.
func (wd *WireguardDevice) Start() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Info.Printf("Adding iptables rule %v", wd.iptablesRule)
	if err := ipt.AppendUnique("nat", "POSTROUTING", wd.iptablesRule...); err != nil {
		return err
	}
	h := netlink.Handle{}
	defer h.Delete()
	logger.Info.Printf(
		"Creating device %s with address %s",
		wd.link.Attrs().Name,
		wd.deviceAddress,
	)
	if err := h.LinkAdd(wd.link); err != nil {
		return err
	}
	if err := wd.ensureLinkIsUp(h); err != nil {
		return err
	}
	if err := wd.configureWireguard(); err != nil {
		return err
	}
	if err := h.AddrAdd(wd.link, &wd.deviceAddress); err != nil {
		return err
	}
	mtu := wd.deviceMTU
	if mtu <= 0 {
		defaultMTU, err := wd.defaultMTU(h)
		if err != nil {
			logger.Error.Printf(
				"Could not detect default MTU, defaulting to 1500: %v",
				err,
			)
			defaultMTU = 1500
		}
		mtu = defaultMTU - 80
	}
	logger.Info.Printf(
		"Setting MTU to %d on device %s", mtu, wd.link.Attrs().Name)
	if err := h.LinkSetMTU(wd.link, mtu); err != nil {
		return err
	}
	logger.Info.Printf("Initialised device %s", wd.link.Attrs().Name)
	return nil
}

// Stop will cleanup and delete the wireguard device.
func (wd *WireguardDevice) Stop() error {
	h := netlink.Handle{}
	defer h.Delete()
	if err := h.LinkSetDown(wd.link); err != nil {
		return err
	}
	if err := h.LinkDel(wd.link); err != nil {
		return err
	}
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	logger.Info.Printf("Removing iptables rule %v", wd.iptablesRule)
	if err := ipt.Delete("nat", "POSTROUTING", wd.iptablesRule...); err != nil {
		return err
	}
	logger.Info.Printf("Cleaned up device %s", wd.link.Attrs().Name)
	return nil
}

func (wd *WireguardDevice) privateKey() (wgtypes.Key, error) {
	kd, err := ioutil.ReadFile(wd.keyFilename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info.Printf(
				"No key found in %s, generating a new private key",
				wd.keyFilename,
			)
			keyDir := filepath.Dir(wd.keyFilename)
			err := os.MkdirAll(keyDir, 0755)
			if err != nil {
				logger.Error.Printf(
					"Unable to create directory=%s",
					keyDir,
				)
				return wgtypes.Key{}, err
			}
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return wgtypes.Key{}, err
			}
			if err := ioutil.WriteFile(wd.keyFilename, []byte(key.String()), 0600); err != nil {
				return wgtypes.Key{}, err
			}
			return key, nil
		}
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(string(kd))
}

func (wd *WireguardDevice) configureWireguard() error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() {
		if err := wg.Close(); err != nil {
			logger.Error.Printf(
				"Failed to close wireguard client: %v",
				err,
			)
		}
	}()
	key, err := wd.privateKey()
	if err != nil {
		return err
	}
	logger.Info.Printf(
		"Configuring wireguard on port %v with public key %s",
		wd.listenPort,
		key.PublicKey(),
	)
	return wg.ConfigureDevice(wd.link.Attrs().Name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &wd.listenPort,
	})
}

// defaultMTU returns the MTU of the default route or the respective device.
func (wd *WireguardDevice) defaultMTU(h netlink.Handle) (int, error) {
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
func (wd *WireguardDevice) ensureLinkIsUp(h netlink.Handle) error {
	tries := 1
	for {
		link, err := h.LinkByName(wd.link.Attrs().Name)
		if err != nil {
			return err
		}
		logger.Info.Printf(
			"waiting for device %s to come up, current flags: %s",
			wd.link.Attrs().Name,
			link.Attrs().Flags,
		)
		if link.Attrs().Flags&net.FlagUp != 0 {
			logger.Info.Printf(
				"device %s came up automatically",
				wd.link.Attrs().Name,
			)
			return nil
		}
		if tries > 4 {
			logger.Info.Printf(
				"timeout waiting for device %s to come up automatically",
				wd.link.Attrs().Name,
			)
			return h.LinkSetUp(wd.link)
		}
		tries++
		time.Sleep(time.Second)
	}
}
