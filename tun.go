package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func startTunDevice(name string) error {
	tun, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("Cannot create tun device %v", err)
	}

	logger := device.NewLogger(
		device.LogLevelInfo,
		fmt.Sprintf("(%s) ", name),
	)

	device := device.NewDevice(tun, logger)
	logger.Info.Println("Device started")

	errs := make(chan error)

	fileUAPI, err := ipc.UAPIOpen(name)
	if err != nil {
		return fmt.Errorf("Failed to open uapi socket file: %v", err)
	}

	uapi, err := ipc.UAPIListen(name, fileUAPI)
	if err != nil {
		return fmt.Errorf("Failed to listen on uapi socket: %v", err)
	}
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Info.Println("UAPI listener started")
	return nil

}
