package main

import (
	"fmt"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// TunDevice represents a tun network device on the system, setup for use with
// userspace wireguard.
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
