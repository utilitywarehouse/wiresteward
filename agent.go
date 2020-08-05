package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

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

type WirestewardPeerConfig struct {
	*wgtypes.PeerConfig
	LocalAddress *net.IPNet
}

func newWirestewardPeerConfigFromLeaseResponse(lr *LeaseResponse) (*WirestewardPeerConfig, error) {
	ip, mask, err := net.ParseCIDR(lr.IP)
	if err != nil {
		return nil, err
	}
	address := &net.IPNet{IP: ip, Mask: mask.Mask}
	pc, err := newPeerConfig(lr.PubKey, "", lr.Endpoint, lr.AllowedIPs)
	if err != nil {
		return nil, err
	}
	return &WirestewardPeerConfig{
		PeerConfig:   pc,
		LocalAddress: address,
	}, nil
}

func requestWirestewardPeerConfig(serverUrl, token, publicKey string) (*WirestewardPeerConfig, error) {
	// Marshal key into json
	r, err := json.Marshal(&LeaseRequest{PubKey: publicKey})
	if err != nil {
		return nil, err
	}

	// Prepare the request
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/newPeerLease", serverUrl),
		bytes.NewBuffer(r),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w,", err)
	}

	response := &LeaseResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		return nil, err
	}
	return newWirestewardPeerConfigFromLeaseResponse(response)
}
