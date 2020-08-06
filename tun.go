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
	deviceName string
	errs       chan error
	logger     *device.Logger
	uapi       net.Listener
	uapiSocket *os.File
	stop       chan bool
	stopped    chan bool
}

func startTunDevice(name string, mtu int) (*TunDevice, error) {
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tunDevice, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("Cannot create tun device %v", err)
	}

	logger := device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", name),
	)

	device := device.NewDevice(tunDevice, logger)
	logger.Info.Println("Device started")

	uapiSocket, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(name, uapiSocket)
	if err != nil {
		return nil, fmt.Errorf("Failed to listen on uapi socket: %v", err)
	}
	return &TunDevice{
		device:     device,
		deviceName: name,
		errs:       make(chan error),
		logger:     logger,
		uapi:       uapi,
		uapiSocket: uapiSocket,
	}, nil
}

// Name returns the name of the device.
func (td *TunDevice) Name() string {
	return td.deviceName
}

// Run starts processing UAPI operations for the device. It should only be
// called once after creating the TunDevice.
func (td *TunDevice) Run() {
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

// Stop will stop the device and cleanup underlying resources.
func (td *TunDevice) Stop() {
	close(td.stop)
	<-td.stopped
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
