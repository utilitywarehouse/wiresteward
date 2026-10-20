package devicemanager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/utilitywarehouse/wiresteward/internal/api"
	"github.com/utilitywarehouse/wiresteward/internal/backoff"
	"github.com/utilitywarehouse/wiresteward/internal/config"
	"github.com/utilitywarehouse/wiresteward/internal/device"
	"github.com/utilitywarehouse/wiresteward/internal/healthcheck"
	"github.com/utilitywarehouse/wiresteward/internal/logging"
	"github.com/utilitywarehouse/wiresteward/internal/oauth"
	"github.com/utilitywarehouse/wiresteward/internal/wireguard"
)

var logger = logging.Logger

// Backend replaces the default device setup (netlink and wgctrl on linux). It
// owns the device key and applies the lease, including the peer, to the
// device. It can also implement healthcheck.EchoExchanger.
type Backend interface {
	device.Device
	// PublicKey returns the base64 public key that is sent to the servers.
	PublicKey() (string, error)
	// Configure applies the new lease, old is nil for the first one.
	Configure(old, new *WirestewardPeerConfig) error
}

// DeviceManager embeds an AgentDevice and implements functionality related to
// configuring the device and system based on information retrieved from
// wiresteward servers.
type DeviceManager struct {
	device.Device
	backend              Backend // optional, replaces the default device setup
	deviceID             string  // identifies this installation to the servers, can be empty
	userAgent            string
	cachedToken          string // cache the token on every renew lease request in case we need to use it on a renewal triggered by healthchecks
	tokenMutex           sync.RWMutex
	configMutex          sync.RWMutex
	config               *WirestewardPeerConfig // To keep the current config
	currentServerURL     string                 // URL of the server that last successfully provided a lease
	serverURLs           []string
	backoff              *backoff.Backoff // backoff timer for retries to get a new lease
	hcMutex              sync.RWMutex
	healthCheck          *healthcheck.HealthCheck // Pointer to the device manager running healthchek
	healthCheckConf      config.AgentHealthCheckConfig
	renewLeaseChan       chan struct{}
	healthCheckRenewChan chan struct{} // signals a health-check-triggered renewal; currentServerURL is cleared before renewing
	stopLeaseBackoff     chan struct{}
	inBackoffLoop        atomic.Bool // signals if there is a backoff loop in progress
	httpClientTimeout    config.Duration
}

func New(deviceName string, mtu int, wirestewardURLs []string, httpClientTimeout config.Duration, hcc config.AgentHealthCheckConfig, deviceType, deviceID, userAgent string) *DeviceManager {
	var dev device.Device
	if deviceType == "wireguard" {
		dev = device.NewWireguardDevice(deviceName, mtu)
	} else {
		dev = device.NewTunDevice(deviceName, mtu)
	}
	return &DeviceManager{
		Device:               dev,
		deviceID:             deviceID,
		userAgent:            userAgent,
		serverURLs:           wirestewardURLs,
		backoff:              backoff.New(1*time.Second, 64*time.Second, 2),
		healthCheck:          &healthcheck.HealthCheck{},
		healthCheckConf:      hcc,
		renewLeaseChan:       make(chan struct{}, 1),
		healthCheckRenewChan: make(chan struct{}, 1),
		stopLeaseBackoff:     make(chan struct{}, 1),
		httpClientTimeout:    httpClientTimeout,
	}
}

// NewWithBackend is like New but the device is set up through the backend.
func NewWithBackend(backend Backend, wirestewardURLs []string, httpClientTimeout config.Duration, hcc config.AgentHealthCheckConfig, deviceID, userAgent string) *DeviceManager {
	dm := New(backend.Name(), 0, wirestewardURLs, httpClientTimeout, hcc, "", deviceID, userAgent)
	dm.Device = backend
	dm.backend = backend
	return dm
}

func (dm *DeviceManager) SetCachedToken(token string) {
	dm.tokenMutex.Lock()
	dm.cachedToken = token
	dm.tokenMutex.Unlock()
}

// Config returns the currently applied configuration, nil if there is none.
func (dm *DeviceManager) Config() *WirestewardPeerConfig {
	dm.configMutex.RLock()
	defer dm.configMutex.RUnlock()
	return dm.config
}

// Healthy returns true if the health check of the current server is passing.
func (dm *DeviceManager) Healthy() bool {
	dm.hcMutex.RLock()
	defer dm.hcMutex.RUnlock()
	return dm.healthCheck.Healthy()
}

func (dm *DeviceManager) getCachedToken() string {
	dm.tokenMutex.RLock()
	defer dm.tokenMutex.RUnlock()
	return dm.cachedToken
}

func (dm *DeviceManager) IsHealthChecked() bool {
	return len(dm.serverURLs) > 1
}

// Run starts the AgentDevice by calling its Run() method and proceeds to
// initialise it.
func (dm *DeviceManager) Run() error {
	if err := dm.Device.Run(); err != nil {
		return fmt.Errorf("Error starting device `%s`: %w", dm.Name(), err)
	}
	if dm.backend == nil {
		if err := dm.initLinkAndWGKeys(); err != nil {
			return err
		}
	}

	if len(dm.serverURLs) > 0 {
		go dm.renewLoop()
	}
	return nil
}

func (dm *DeviceManager) initLinkAndWGKeys() error {
	if err := dm.ensureLinkUp(); err != nil {
		return err
	}
	// Check if there is a private key or generate one
	_, privKey, err := wireguard.GetKeys(dm.Name())
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
		if err := wireguard.SetPrivateKey(dm.Name(), newKey.String()); err != nil {
			return err
		}
	}
	return nil
}

func (dm *DeviceManager) publicKey() (string, error) {
	if dm.backend != nil {
		return dm.backend.PublicKey()
	}
	publicKey, _, err := wireguard.GetKeys(dm.Name())
	return publicKey, err
}

func (dm *DeviceManager) renewLoop() {
	for {
		select {
		case <-dm.renewLeaseChan:
			logger.Verbosef("Renewing lease for device:%s\n", dm.Name())
		case <-dm.healthCheckRenewChan:
			logger.Verbosef("Health check triggered lease renewal for device:%s, clearing current server\n", dm.Name())
			dm.currentServerURL = ""
		}
		if err := dm.renewLease(); err != nil {
			if err == jwt.ErrExpired {
				// stop retrying - token is expired, it will need manual refresh
				logger.Errorf("%v", err)
				continue
			}
			go func() {
				dm.inBackoffLoop.Store(true)
				duration := dm.backoff.Duration()
				logger.Errorf("Cannot update lease for %s, will retry in %s: %s", dm.Name(), duration, err)
				select {
				case <-time.After(duration):
					dm.renewLeaseChan <- struct{}{}
				case <-dm.stopLeaseBackoff:
					break
				}
				dm.inBackoffLoop.Store(false)
			}()
		} else {
			dm.backoff.Reset()
		}
	}
}

// nextServer returns the server URL to use for lease renewal. It prefers the
// server that last successfully provided a lease, falling back to a random
// selection when no current server is recorded.
func (dm *DeviceManager) nextServer() string {
	if dm.currentServerURL != "" {
		return dm.currentServerURL
	}
	return dm.serverURLs[rand.Intn(len(dm.serverURLs))]
}

// TriggerLeaseRenewal stops any running healthcheck and backoff loop, resets
// the backoff timer, and signals the renewLoop to perform a lease renewal.
// The caller must ensure cachedToken is up to date before calling this.
func (dm *DeviceManager) TriggerLeaseRenewal() {
	dm.hcMutex.RLock()
	dm.healthCheck.Stop() // stop a running healthcheck that could also trigger renewals
	dm.hcMutex.RUnlock()
	if dm.inBackoffLoop.Load() {
		select {
		case dm.stopLeaseBackoff <- struct{}{}:
		default:
		}
	}
	dm.backoff.Reset() // Reset backoff timer
	select {
	case dm.renewLeaseChan <- struct{}{}:
	default:
	}
}

// renewLease uses the provided oauth2 token to retrieve a new leases from one
// of the healthy wiresteward servers associated with the underlying device. If
// healthchecks are disabled then all serveres would be considered healthy. The
// received configuration is then applied to the device only if it differs from
// the current configuration.
func (dm *DeviceManager) renewLease() error {
	token := dm.getCachedToken()
	if token == "" {
		return fmt.Errorf("Empty cached token")
	}
	if _, err := oauth.ValidateJWTToken(token); err != nil {
		return err
	}
	publicKey, err := dm.publicKey()
	if err != nil {
		return fmt.Errorf("Could not get keys from device %s: %w", dm.Name(), err)
	}

	serverURL := dm.nextServer()
	if serverURL == "" {
		return fmt.Errorf("No healthy servers found for device: %s", dm.Name())
	}
	config, wgServerAddr, err := requestWirestewardPeerConfig(serverURL, token, publicKey, dm.deviceID, dm.userAgent, dm.httpClientTimeout)
	if err != nil {
		// Clear current server so the next retry picks a random one.
		dm.currentServerURL = ""
		return fmt.Errorf("requestWirestewardPeerConfig: %w", err)
	}
	dm.currentServerURL = serverURL

	dm.configMutex.RLock()
	oldConfig := dm.config
	configsEqual := wirestewardPeerConfigsEqual(oldConfig, config)
	dm.configMutex.RUnlock()

	if !configsEqual {
		dm.configMutex.Lock()
		logger.Verbosef(
			"Configuring offered ip address %s on device %s",
			config.LocalAddress,
			dm.Name(),
		)
		// TODO: Depending on the implementation of updateDeviceConfig, if the
		// update fails partially, we might end up with the wrong "old" config
		// and fail to cleanup properly when we update the next time.
		var err error
		if dm.backend != nil {
			err = dm.backend.Configure(oldConfig, config)
		} else {
			err = dm.updateDeviceConfig(oldConfig, config)
		}
		if err != nil {
			logger.Errorf(
				"Could not update peer configuration for `%s`: %v",
				serverURL,
				err,
			)
		} else {
			dm.config = config
		}
		dm.configMutex.Unlock()
		if dm.backend == nil {
			if err := wireguard.SetPeers(dm.Name(), []wgtypes.PeerConfig{*config.PeerConfig}); err != nil {
				return fmt.Errorf("Error setting new peers for device %s: %w", dm.Name(), err)
			}
		}
	} else {
		logger.Verbosef(
			"Received unchanged config from `%s`, skipping device update",
			serverURL,
		)
	}

	// (Re)start health checking if we have an address for the server wg
	// client and more servers to potentially fail over to. The health check
	// self-terminates when it fires a renewal, so we always restart it here.
	if wgServerAddr != "" && len(dm.serverURLs) > 1 {
		// A backend can optionally replace the default icmp echo exchange.
		exchanger, _ := dm.backend.(healthcheck.EchoExchanger)
		dm.hcMutex.Lock()
		dm.healthCheck.Stop()
		hc, err := healthcheck.New(
			dm.Name(),
			wgServerAddr,
			dm.healthCheckConf.Interval,
			dm.healthCheckConf.IntervalAfterFailure,
			dm.healthCheckConf.Timeout,
			dm.healthCheckConf.Threshold,
			dm.healthCheckRenewChan,
			exchanger,
		)
		if err != nil {
			dm.hcMutex.Unlock()
			return fmt.Errorf("Cannot create healthcheck: %v", err)
		}
		dm.healthCheck = hc
		go dm.healthCheck.Run()
		dm.hcMutex.Unlock()
	}
	return nil
}

// wirestewardPeerConfigsEqual returns true if both configs represent the same
// network configuration (local address, peer public key, endpoint, and allowed
// IPs). A nil config is only equal to another nil config.
func wirestewardPeerConfigsEqual(a, b *WirestewardPeerConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.LocalAddress.String() != b.LocalAddress.String() {
		return false
	}
	if a.PublicKey != b.PublicKey {
		return false
	}
	endpointA, endpointB := "", ""
	if a.Endpoint != nil {
		endpointA = a.Endpoint.String()
	}
	if b.Endpoint != nil {
		endpointB = b.Endpoint.String()
	}
	if endpointA != endpointB {
		return false
	}
	if len(a.AllowedIPs) != len(b.AllowedIPs) {
		return false
	}
	for i := range a.AllowedIPs {
		if a.AllowedIPs[i].String() != b.AllowedIPs[i].String() {
			return false
		}
	}
	return true
}

// WirestewardPeerConfig embeds wgtypes.PeerConfig and additional configuration
// received from a wiresteward server.
type WirestewardPeerConfig struct {
	*wgtypes.PeerConfig
	LocalAddress *net.IPNet
}

func newWirestewardPeerConfigFromLeaseResponse(lr *api.LeaseResponse) (*WirestewardPeerConfig, string, error) {
	ip, mask, err := net.ParseCIDR(lr.IP)
	if err != nil {
		return nil, "", err
	}
	address := &net.IPNet{IP: ip, Mask: mask.Mask}
	pc, err := wireguard.NewPeerConfig(lr.PubKey, "", lr.Endpoint, lr.AllowedIPs)
	if err != nil {
		return nil, "", err
	}
	return &WirestewardPeerConfig{
		PeerConfig:   pc,
		LocalAddress: address,
	}, lr.ServerWireguardIP, nil
}

func requestWirestewardPeerConfig(serverURL, token, publicKey, deviceID, userAgent string, timeout config.Duration) (*WirestewardPeerConfig, string, error) {
	// Marshal key into json
	r, err := json.Marshal(&api.LeaseRequest{PubKey: publicKey, DeviceID: deviceID})
	if err != nil {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): marshal request: %w", serverURL, err)
	}

	// Prepare the request
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/newPeerLease", serverURL),
		bytes.NewBuffer(r),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: timeout.Duration}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): do request: %w", serverURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): response status: %s", serverURL, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): read response body: %w", serverURL, err)
	}

	response := &api.LeaseResponse{}
	if err := json.Unmarshal(body, response); err != nil {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): unmarshal response: %w", serverURL, err)
	}
	config, wgIP, err := newWirestewardPeerConfigFromLeaseResponse(response)
	if err != nil {
		return nil, "", fmt.Errorf("requestWirestewardPeerConfig(%s): parse peer config: %w", serverURL, err)
	}
	return config, wgIP, nil
}
