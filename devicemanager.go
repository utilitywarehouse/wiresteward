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

func init() {
	rand.Seed(time.Now().Unix())
}

// DeviceManager embeds an AgentDevice and implements functionality related to
// configuring the device and system based on information retrieved from
// wiresteward servers.
type DeviceManager struct {
	agentDevice
	cachedToken       string // cache the token on every renew lease request in case we need to use it on a renewal triggered by healthchecks
	configMutex       sync.Mutex
	config            *WirestewardPeerConfig // To keep the current config
	serverURLs        []string
	backoff           *backoff     // backoff timer for retries to get a new lease
	healthCheck       *healthCheck // Pointer to the device manager running healthchek
	healthCheckConf   agentHealthCheckConfig
	renewLeaseChan    chan struct{}
	stopLeaseBackoff  chan struct{}
	inBackoffLoop     bool // bool to signal if there is a backoff loop in progress
	httpClientTimeout Duration
}

func newDeviceManager(deviceName string, mtu int, wirestewardURLs []string, httpClientTimeout Duration, hcc agentHealthCheckConfig) *DeviceManager {
	var device agentDevice
	if *flagDeviceType == "wireguard" {
		device = newWireguardDevice(deviceName, mtu)
	} else {
		device = newTunDevice(deviceName, mtu)
	}
	return &DeviceManager{
		agentDevice:       device,
		serverURLs:        wirestewardURLs,
		backoff:           newBackoff(1*time.Second, 64*time.Second, 2),
		healthCheck:       &healthCheck{running: false},
		healthCheckConf:   hcc,
		renewLeaseChan:    make(chan struct{}),
		stopLeaseBackoff:  make(chan struct{}),
		inBackoffLoop:     false,
		httpClientTimeout: httpClientTimeout,
	}
}

func (dm *DeviceManager) isHealthChecked() bool {
	return len(dm.serverURLs) > 1
}

// Run starts the AgentDevice by calling its Run() method and proceeds to
// initialise it.
func (dm *DeviceManager) Run() error {
	if err := dm.agentDevice.Run(); err != nil {
		return fmt.Errorf("Error starting device `%s`: %w", dm.Name(), err)
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
		logger.Verbosef(
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
		go dm.renewLoop()
	}
	return nil
}

func (dm *DeviceManager) renewLoop() {
	for {
		select {
		case <-dm.renewLeaseChan:
			logger.Verbosef("Renewing lease for device:%s\n", dm.Name())
			if err := dm.renewLease(); err != nil {
				go func() {
					dm.inBackoffLoop = true
					duration := dm.backoff.Duration()
					logger.Errorf("Cannot update lease for %s, will retry in %s: %s", dm.Name(), duration, err)
					select {
					case <-time.After(duration):
						dm.renewLeaseChan <- struct{}{}
					case <-dm.stopLeaseBackoff:
						break
					}
					dm.inBackoffLoop = false
				}()
			} else {
				dm.backoff.Reset()
			}
		}
	}
}

func (dm *DeviceManager) nextServer() string {
	return dm.serverURLs[rand.Intn(len(dm.serverURLs))]
}

// RenewTokenAndLease is called via the agent to renew the cached token data and
// trigger a lease renewal
func (dm *DeviceManager) RenewTokenAndLease(token string) {
	dm.cachedToken = token
	dm.healthCheck.Stop() // stop a running healthcheck that could also trigger renewals
	if dm.inBackoffLoop {
		dm.stopLeaseBackoff <- struct{}{} // Stop existing backoff loops
	}
	dm.backoff.Reset() // Reset backoff timer
	dm.renewLeaseChan <- struct{}{}
}

// RenewLease uses the provided oauth2 token to retrieve a new leases from one
// of the healthy wiresteward servers associated with the underlying device. If
// healthchecks are disabled then all serveres would be considered healthy. The
// received configuration is then applied to the device.
func (dm *DeviceManager) renewLease() error {
	if dm.cachedToken == "" {
		return fmt.Errorf("Empty cached token")
	}
	if err := validateJWTToken(dm.cachedToken); err != nil {
		return fmt.Errorf("Validation failed: %v", err)
	}
	publicKey, _, err := getKeys(dm.Name())
	if err != nil {
		return fmt.Errorf("Could not get keys from device %s: %w", dm.Name(), err)
	}

	serverURL := dm.nextServer()
	if serverURL == "" {
		return fmt.Errorf("No healthy servers found for device: %s", dm.Name())
	}
	oldConfig := dm.config
	peers := []wgtypes.PeerConfig{}
	config, wgServerAddr, err := requestWirestewardPeerConfig(serverURL, dm.cachedToken, publicKey, dm.httpClientTimeout)
	if err != nil {
		logger.Errorf(
			"Could not get wiresteward peer config from `%s`: %v",
			serverURL,
			err,
		)
		return err
	}
	peers = append(peers, *config.PeerConfig)

	dm.configMutex.Lock()
	logger.Verbosef(
		"Configuring offered ip address %s on device %s",
		config.LocalAddress,
		dm.Name(),
	)
	// TODO: Depending on the implementation of updateDeviceConfig, if the
	// update fails partially, we might end up with the wrong "old" config
	// and fail to cleanup properly when we update the next time.
	if err := dm.updateDeviceConfig(oldConfig, config); err != nil {
		logger.Errorf(
			"Could not update peer configuration for `%s`: %v",
			serverURL,
			err,
		)
	} else {
		dm.config = config
	}
	dm.configMutex.Unlock()
	if err := setPeers(dm.Name(), peers); err != nil {
		return fmt.Errorf("Error setting new peers for device %s: %w", dm.Name(), err)
	}

	// Start health checking if we have an address for the server wg client
	// and more servers to potentially fell over.
	if wgServerAddr != "" && len(dm.serverURLs) > 1 {
		dm.healthCheck.Stop()
		hc, err := newHealthCheck(
			dm.Name(),
			wgServerAddr,
			dm.healthCheckConf.Interval,
			dm.healthCheckConf.IntervalAfterFailure,
			dm.healthCheckConf.Timeout,
			dm.healthCheckConf.Threshold,
			dm.renewLeaseChan,
		)
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

func requestWirestewardPeerConfig(serverURL, token, publicKey string, timeout Duration) (*WirestewardPeerConfig, string, error) {
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

	client := &http.Client{Timeout: timeout.Duration}
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
