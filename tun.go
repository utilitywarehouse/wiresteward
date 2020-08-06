package main

import (
	"fmt"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type TunDevice struct {
	device     *device.Device
	deviceName string
	errs       chan error
	logger     *device.Logger
	uapi       net.Listener
	uapiSocket *os.File
	stop       chan bool
	stopped    chan bool
	tunDevice  tun.Device
}

func startTunDevice(name string, MTU int) (*TunDevice, error) {
	if MTU == 0 {
		MTU = device.DefaultMTU
	}
	tunDevice, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Cannot create tun device %v", err)
	}

	logger := device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", name),
	)

	device := device.NewDevice(tunDevice, logger)
	logger.Info.Println("Device started")

	uapiSocket, err := ipc.UAPIOpen(name)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(name, uapiSocket)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Failed to listen on uapi socket: %v", err)
	}
	tundev := &TunDevice{
		device:     device,
		deviceName: name,
		errs:       make(chan error),
		logger:     logger,
		uapi:       uapi,
		uapiSocket: uapiSocket,
		tunDevice:  tunDevice,
	}

	return tundev, nil
}

func (td *TunDevice) Name() string {
	return td.deviceName
}

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
	case <-td.errs:
	case <-td.device.Wait():
	}

	td.cleanup()
	close(td.stopped)
}

func (td *TunDevice) Stop() {
	close(td.stop)
	<-td.stopped
}

func (td *TunDevice) cleanup() {
	td.logger.Info.Println("Shutting down")
	td.uapi.Close()
	td.logger.Info.Println("UAPI listener stopped")
	td.uapiSocket.Close()
	td.device.Close()
	td.tunDevice.Close()
}
