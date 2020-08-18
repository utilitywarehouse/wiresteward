package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceManager embeds a TunDevice and implements functionality related to
// configuring the device and system based on information retrieved from
// wiresteward servers.
type DeviceManager struct {
	*TunDevice
	configMutex sync.Mutex
	// config maps a wiresteward server url to a running configuration. It is
	// used to cleanup running configuration before applying a new one.
	config map[string]*WirestewardPeerConfig
}

func newDeviceManager(deviceName string, mtu int, wirestewardURLs []string) *DeviceManager {
	config := make(map[string]*WirestewardPeerConfig, len(wirestewardURLs))
	for _, e := range wirestewardURLs {
		config[e] = nil
	}
	return &DeviceManager{
		TunDevice: newTunDevice(deviceName, mtu),
		config:    config,
	}
}

// Run starts the TunDevice by calling its Run() method and proceeds to
// initialise it.
func (dm *DeviceManager) Run() error {
	if err := dm.TunDevice.Run(); err != nil {
		return fmt.Errorf("Error starting tun device `%s`: %w", dm.Name(), err)
	}
	if err := dm.ensureLinkUp(); err != nil {
		return err
	}
	// Check if there is a private key or generate one
	_, privKey, err := getKeys(dm.Name())
	if err != nil {
		return fmt.Errorf("Cannot get keys for device `%s`: %w", dm.Name(), err)
	}
	// the base64 value of an empty key will come as
	// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
	if privKey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		log.Printf("No keys found for device `%s`, generating a new pair", dm.Name())
		newKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		if err := setPrivateKey(dm.Name(), newKey.String()); err != nil {
			return err
		}
	}
	return nil
}

// RenewLeases uses the provided oauth2 token to retrieve new leases from the
// wiresteward servers associated with the underlying device. The received
// configuration is then applied to the device.
func (dm *DeviceManager) RenewLeases(token string) error {
	publicKey, _, err := getKeys(dm.Name())
	if err != nil {
		return fmt.Errorf("Could not get keys from device %s: %w", dm.Name(), err)
	}
	peers := []wgtypes.PeerConfig{}
	for serverURL, oldConfig := range dm.config {
		config, err := requestWirestewardPeerConfig(serverURL, token, publicKey)
		if err != nil {
			log.Printf("Could not get wiresteward peer config from `%s`: %v", serverURL, err)
			continue
		}
		peers = append(peers, *config.PeerConfig)

		dm.configMutex.Lock()
		log.Printf("Configuring offered ip address %s on device %s", config.LocalAddress, dm.Name())
		// TODO: Depending on the implementation of updateDeviceConfig, if the
		// update fails partially, we might end up with the wrong "old" config
		// and fail to cleanup properly when we update the next time.
		if err := dm.updateDeviceConfig(oldConfig, config); err != nil {
			log.Printf("Could not update peer configuration for `%s`: %v", serverURL, err)
		} else {
			dm.config[serverURL] = config
		}
		dm.configMutex.Unlock()
	}
	if err := setPeers(dm.Name(), peers); err != nil {
		return fmt.Errorf("Error setting new peers for device %s: %w", dm.Name(), err)
	}
	return nil
}

// WirestewardPeerConfig embeds wgtypes.PeerConfig and additional configuration
// received from a wiresteward server.
type WirestewardPeerConfig struct {
	*wgtypes.PeerConfig
	LocalAddress *net.IPNet
}

func newWirestewardPeerConfigFromLeaseResponse(lr *leaseResponse) (*WirestewardPeerConfig, error) {
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

func requestWirestewardPeerConfig(serverURL, token, publicKey string) (*WirestewardPeerConfig, error) {
	// Marshal key into json
	r, err := json.Marshal(&leaseRequest{PubKey: publicKey})
	if err != nil {
		return nil, err
	}

	// Prepare the request
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/newPeerLease", serverURL),
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

	response := &leaseResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		return nil, err
	}
	return newWirestewardPeerConfigFromLeaseResponse(response)
}
