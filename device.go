package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
	logger := device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", name),
	)
	return &TunDevice{
		deviceMTU:  mtu,
		deviceName: name,
		errs:       make(chan error),
		logger:     logger,
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
	deviceAddress *net.IPNet
	deviceName    string
	ipTablesRule  []string
	keyFilename   string
	link          netlink.Link
}

func newWireguardDevice(cfg *serverConfig) *WireguardDevice {
	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: cfg.DeviceName,
		},
	}
	if cfg.DeviceMTU != 0 {
		link.LinkAttrs.MTU = cfg.DeviceMTU
	}
	return &WireguardDevice{
		deviceAddress: &net.IPNet{
			IP:   cfg.WireguardIPAddress,
			Mask: cfg.WireguardIPNetwork.Mask,
		},
		deviceName: cfg.DeviceName,
		ipTablesRule: []string{
			"-s", cfg.WireguardIPNetwork.String(),
			"-d", strings.Join(cfg.AllowedIPs, ","),
			"-j", "MASQUERADE",
		},
		keyFilename: cfg.KeyFilename,
		link:        link,
	}
}

// Start will create and setup the wireguard device.
func (wd *WireguardDevice) Start() error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	if err := ipt.AppendUnique("nat", "POSTROUTING", wd.ipTablesRule...); err != nil {
		return err
	}
	log.Printf("Setup iptables")
	h := netlink.Handle{}
	defer h.Delete()
	if err := h.LinkAdd(wd.link); err != nil {
		return err
	}
	log.Printf("Created device %s", wd.deviceName)
	if err := h.AddrAdd(wd.link, &netlink.Addr{IPNet: wd.deviceAddress}); err != nil {
		return err
	}
	key, err := wd.privateKey()
	if err != nil {
		return err
	}
	if err := setPrivateKey(wd.deviceName, key); err != nil {
		return err
	}
	if err := h.LinkSetUp(wd.link); err != nil {
		return err
	}
	log.Printf("Setup device %s", wd.deviceName)
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
	if err := ipt.Delete("nat", "POSTROUTING", wd.ipTablesRule...); err != nil {
		return err
	}
	log.Printf("Cleanup iptables")
	return nil
}

func (wd *WireguardDevice) privateKey() (string, error) {
	kd, err := ioutil.ReadFile(wd.keyFilename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("No key found in %s, generating a new private key", wd.keyFilename)
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return "", err
			}
			if err := ioutil.WriteFile(wd.keyFilename, []byte(key.String()), 0600); err != nil {
				return "", err
			}
			return key.String(), nil
		}
		return "", err
	}
	return string(kd), nil
}
