package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceManager embeds an AgentDevice and implements functionality related to
// configuring the device and system based on information retrieved from
// wiresteward servers.
type DeviceManager struct {
	AgentDevice
	cachedToken string // cache the token on every renew lease request in case we need to use it on a renewal triggered by healthchecks
	configMutex sync.Mutex
	// config maps a wiresteward server url to a running configuration. It is
	// used to cleanup running configuration before applying a new one.
	config          map[string]*WirestewardPeerConfig
	serverURLs      []string
	healthCheck     *healthCheck
	forceRenewLease chan struct{}
}

// Shoule be called before creating new device managers to initialize the pseudo
// random generator for picking serveres
func InitDeviceManagerSeed() {
	rand.Seed(time.Now().Unix())
}

func newDeviceManager(deviceName string, mtu int, wirestewardURLs []string) *DeviceManager {
	config := make(map[string]*WirestewardPeerConfig, len(wirestewardURLs))
	forceRenewLease := make(chan struct{})
	for _, e := range wirestewardURLs {
		config[e] = nil
	}
	var device AgentDevice
	if *flagDeviceType == "wireguard" {
		device = newWireguardDevice(deviceName, mtu)
	} else {
		device = newTunDevice(deviceName, mtu)
	}
	return &DeviceManager{
		AgentDevice:     device,
		config:          config,
		serverURLs:      wirestewardURLs,
		healthCheck:     &healthCheck{running: false},
		forceRenewLease: forceRenewLease,
	}
}

// Run starts the AgentDevice by calling its Run() method and proceeds to
// initialise it.
func (dm *DeviceManager) Run() error {
	if err := dm.AgentDevice.Run(); err != nil {
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
		logger.Info.Printf(
			"No keys found for device `%s`, generating a new pair",
			dm.Name(),
		)
		newKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		if err := setPrivateKey(dm.Name(), newKey.String()); err != nil {
			return err
		}
	}

	if len(dm.serverURLs) > 0 {
		go dm.forceRenewLoop()
	}
	return nil
}

func (dm *DeviceManager) forceRenewLoop() {
	for {
		select {
		case <-dm.forceRenewLease:
			logger.Info.Printf("healthceck failed, renewing lease")
			if err := dm.RenewLease(dm.cachedToken); err != nil {
				logger.Error.Printf("Cannot update lease, will retry in one sec: %s", err)
				// Wait a second in a goroutine so we do not block here and try again
				go func() {
					time.Sleep(1 * time.Second)
					dm.forceRenewLease <- struct{}{}
				}()
			}
		}
	}
}

func (dm *DeviceManager) ensureHealthCheckIsStoped() {
	dm.healthCheck.Stop()
}

func (dm *DeviceManager) nextServer() string {
	return dm.serverURLs[rand.Intn(len(dm.serverURLs))]
}

// RenewLeases uses the provided oauth2 token to retrieve a new leases from one
// of the healthy wiresteward servers associated with the underlying device. If
// healthchecks are disabled then all serveres would be considered healthy. The
// received configuration is then applied to the device.
func (dm *DeviceManager) RenewLease(token string) error {
	dm.cachedToken = token
	publicKey, _, err := getKeys(dm.Name())
	if err != nil {
		return fmt.Errorf("Could not get keys from device %s: %w", dm.Name(), err)
	}

	serverURL := dm.nextServer()
	if serverURL == "" {
		return fmt.Errorf("No healthy servers found for device: %s", dm.Name())
	}
	oldConfig := dm.config[serverURL]
	peers := []wgtypes.PeerConfig{}
	config, wgServerAddr, err := requestWirestewardPeerConfig(serverURL, token, publicKey)
	if err != nil {
		logger.Error.Printf(
			"Could not get wiresteward peer config from `%s`: %v",
			serverURL,
			err,
		)
		return err
	}
	peers = append(peers, *config.PeerConfig)

	dm.configMutex.Lock()
	logger.Info.Printf(
		"Configuring offered ip address %s on device %s",
		config.LocalAddress,
		dm.Name(),
	)
	// TODO: Depending on the implementation of updateDeviceConfig, if the
	// update fails partially, we might end up with the wrong "old" config
	// and fail to cleanup properly when we update the next time.
	if err := dm.updateDeviceConfig(oldConfig, config); err != nil {
		logger.Error.Printf(
			"Could not update peer configuration for `%s`: %v",
			serverURL,
			err,
		)
	} else {
		dm.config[serverURL] = config
	}
	dm.configMutex.Unlock()
	if err := setPeers(dm.Name(), peers); err != nil {
		return fmt.Errorf("Error setting new peers for device %s: %w", dm.Name(), err)
	}

	// Start health checking if we have an address for the server wg client
	// and more servers to potentially fell over.
	if wgServerAddr != "" && len(dm.serverURLs) > 1 {
		dm.ensureHealthCheckIsStoped()
		hc, err := NewHealthCheck(wgServerAddr, time.Second, 3, dm.forceRenewLease)
		if err != nil {
			return fmt.Errorf("Cannot create healthchek: %v", err)
		}
		dm.healthCheck = hc
		go dm.healthCheck.Run()
	}
	return nil
}

// WirestewardPeerConfig embeds wgtypes.PeerConfig and additional configuration
// received from a wiresteward server.
type WirestewardPeerConfig struct {
	*wgtypes.PeerConfig
	LocalAddress *net.IPNet
}

func newWirestewardPeerConfigFromLeaseResponse(lr *leaseResponse) (*WirestewardPeerConfig, string, error) {
	ip, mask, err := net.ParseCIDR(lr.IP)
	if err != nil {
		return nil, "", err
	}
	address := &net.IPNet{IP: ip, Mask: mask.Mask}
	pc, err := newPeerConfig(lr.PubKey, "", lr.Endpoint, lr.AllowedIPs)
	if err != nil {
		return nil, "", err
	}
	return &WirestewardPeerConfig{
		PeerConfig:   pc,
		LocalAddress: address,
	}, lr.ServerWireguardIP, nil
}

func requestWirestewardPeerConfig(serverURL, token, publicKey string) (*WirestewardPeerConfig, string, error) {
	// Marshal key into json
	r, err := json.Marshal(&leaseRequest{PubKey: publicKey})
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("Response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response body: %w,", err)
	}

	response := &leaseResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		return nil, "", err
	}
	return newWirestewardPeerConfigFromLeaseResponse(response)
}
