package device

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/utilitywarehouse/wiresteward/internal/logging"
)

var logger = logging.Logger

// Device is a network device that the agent manages.
type Device interface {
	Name() string
	Run() error
	Stop()
}

// TunDevice represents a tun network device on the system, setup for use with
// user space wireguard. This is utilised by the agent-side wiresteward, to
// provide a cross-platform implementation based on wireguard-go.
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

func NewTunDevice(name string, mtu int) *TunDevice {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	return &TunDevice{
		deviceMTU:  mtu,
		deviceName: name,
		errs:       make(chan error),
		logger:     logging.NewLogger(fmt.Sprintf("wireguard-go/%s", name)),
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

	device := device.NewDevice(tunDevice, conn.NewDefaultBind(), td.logger)
	td.logger.Verbosef("Device started")

	uapiSocket, err := ipc.UAPIOpen(td.deviceName)
	if err != nil {
		device.Close()
		return fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(td.deviceName, uapiSocket)
	if err != nil {
		if err := td.uapiSocket.Close(); err != nil {
			td.logger.Errorf("%v", err)
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
	td.logger.Verbosef("UAPI listener started")

	select {
	case <-td.stop:
		td.logger.Verbosef("Device stopping...")
	case err := <-td.errs:
		td.logger.Errorf("Device error: %v", err)
	case <-td.device.Wait():
		td.logger.Verbosef("Device stopped")
	}

	td.cleanup()
	close(td.stopped)
}

func (td *TunDevice) cleanup() {
	td.logger.Verbosef("Shutting down")
	if err := td.uapi.Close(); err != nil {
		td.logger.Errorf("%v", err)
	}
	td.logger.Verbosef("UAPI listener stopped")
	if err := td.uapiSocket.Close(); err != nil {
		td.logger.Errorf("%v", err)
	}
	td.logger.Verbosef("UAPI socket stopped")
	td.device.Close()
	td.logger.Verbosef("Device closed")
}

// WireguardDevice represents a kernel space wireguard network device on the
// system. This is utilised by the agent-side wiresteward, to provide a native
// device on linux systems with kernel support for wireguard.
type WireguardDevice struct {
	deviceName string
	link       netlink.Link
	logger     *device.Logger
}

func NewWireguardDevice(name string, mtu int) *WireguardDevice {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	return &WireguardDevice{
		deviceName: name,
		link: &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{
			MTU:    mtu,
			Name:   name,
			TxQLen: 1000,
		}},
		logger: logging.NewLogger(fmt.Sprintf("wireguard/%s", name)),
	}
}

// Name returns the name of the device.
func (wd *WireguardDevice) Name() string {
	return wd.deviceName
}

// Run creates the wireguard device.
func (wd *WireguardDevice) Run() error {
	h := netlink.Handle{}
	defer h.Delete()
	if err := h.LinkAdd(wd.link); err != nil {
		return err
	}
	return nil
}

// Stop will stop the device and cleanup underlying resources.
func (wd *WireguardDevice) Stop() {
	if wd.link == nil {
		return
	}
	h := netlink.Handle{}
	defer h.Delete()
	if err := h.LinkSetDown(wd.link); err != nil {
		wd.logger.Errorf("%v", err)
	}
	if err := h.LinkDel(wd.link); err != nil {
		wd.logger.Errorf("%v", err)
	}
}
