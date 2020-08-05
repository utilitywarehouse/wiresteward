package main

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Agent struct {
	device        string
	pubKey        string
	privKey       string
	netlinkHandle *netlinkHandle
	tundev        *TunDevice
}

// NewAgent: Creates an agent associated with a net device
func NewAgent(deviceName string) (*Agent, error) {
	a := &Agent{
		device:        deviceName,
		netlinkHandle: NewNetLinkHandle(),
	}

	tundev, err := startTunDevice(deviceName)
	if err != nil {
		return a, fmt.Errorf("Error starting wg device: %s: %v", deviceName, err)
	}

	a.tundev = tundev

	go a.tundev.Run()

	// Bring device up
	if err := a.netlinkHandle.EnsureLinkUp(deviceName); err != nil {
		return a, err
	}

	// Check if there is a private key or generate one
	_, privKey, err := getKeys(deviceName)
	if err != nil {
		return a, fmt.Errorf("Cannot get keys for device: %s: %v", deviceName, err)
	}
	// the base64 value of an empty key will come as
	// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	if privKey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		newKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return a, err
		}
		a.privKey = newKey.String()
		if err := a.SetPrivKey(); err != nil {
			return a, err
		}
	}

	// Fetch keys from interface and save them
	a.pubKey, a.privKey, err = getKeys(deviceName)
	if err != nil {
		return a, err
	}

	return a, nil
}

func (a *Agent) SetPrivKey() error {
	return setPrivateKey(a.device, a.privKey)
}

func (a *Agent) Stop() {
	a.tundev.Stop()
}

// TODO: remove, temporary method to aid with transition
func (a *Agent) UpdateDeviceConfig(deviceName string, config *WirestewardPeerConfig) error {
	return a.netlinkHandle.UpdateDeviceConfig(deviceName, nil, config)
}
