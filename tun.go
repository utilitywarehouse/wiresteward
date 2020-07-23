package main

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

type TunDevice struct {
	tun    tun.Device
	device *device.Device
	logger *device.Logger
	uapi   net.Listener
	errs   chan error
	stop   chan bool
}

func startTunDevice(name string, stop chan bool) (*TunDevice, error) {
	tun, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Cannot create tun device %v", err)
	}

	logger := device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", name),
	)

	device := device.NewDevice(tun, logger)
	logger.Info.Println("Device started")

	fileUAPI, err := ipc.UAPIOpen(name)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(name, fileUAPI)
	if err != nil {
		return &TunDevice{}, fmt.Errorf("Failed to listen on uapi socket: %v", err)
	}
	tundev := &TunDevice{
		tun:    tun,
		device: device,
		logger: logger,
		uapi:   uapi,
		errs:   make(chan error),
		stop:   stop,
	}

	return tundev, nil
}

func (td *TunDevice) Run() {
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

	td.CleanUp()
}

func (td *TunDevice) CleanUp() {
	td.uapi.Close()
	td.device.Close()

	td.logger.Info.Println("Shutting down")
}
