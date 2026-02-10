package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultKeyFilename               = "/etc/wiresteward/key"
	defaultLeaserSyncInterval        = 1 * time.Minute
	defaultLeasesFilename            = "/var/lib/wiresteward/leases"
	defaultServerListenAddress       = "0.0.0.0:8080"
	defaultAgentHealthCheckThreshold = 3
)

var (
	defaultAgentHTTPClientTimeout               = Duration{3 * time.Second}
	defaultAgentHealthCheckInterval             = Duration{10 * time.Second}
	defaultAgentHealthCheckIntervalAfterFailure = Duration{time.Second}
	defaultAgentHealthCheckTimeout              = Duration{time.Second}
)

// agentOAuthConfig encapsulates agent-side OAuth configuration for wiresteward
type agentOAuthConfig struct {
	ClientID string `json:"clientID"`
	AuthURL  string `json:"authUrl"`
	TokenURL string `json:"tokenUrl"`
}

// agentPeerConfig contains the agent-side configuration for a wiresteward
// server.
type agentPeerConfig struct {
	URL string `json:"url"`
}

// agentDeviceConfig defines a network device and associated wiresteward
// servers.
type agentDeviceConfig struct {
	Name  string            `json:"name"`
	MTU   int               `json:"mtu"`
	Peers []agentPeerConfig `json:"peers"`
}

// agentHTTPClientConfig contains variable to set http client options for
// requests to the wiresteward servers.
type agentHTTPClientConfig struct {
	Timeout Duration `json:"timeout"`
}

var defaultAgentHTTPClientConfig = agentHTTPClientConfig{
	Timeout: defaultAgentHTTPClientTimeout,
}

// agentHealthcheckConfig contains the global config for all the healthchecks
// created by the agent against server peers.
type agentHealthCheckConfig struct {
	Interval             Duration `json:"interval"`
	IntervalAfterFailure Duration `json:"intervalAF"`
	Threshold            int      `json:"threshold"`
	Timeout              Duration `json:"timeout"`
}

var dedfaultAgentHealthCheckConfig = agentHealthCheckConfig{
	Interval:             defaultAgentHealthCheckInterval,
	IntervalAfterFailure: defaultAgentHealthCheckIntervalAfterFailure,
	Threshold:            defaultAgentHealthCheckThreshold,
	Timeout:              defaultAgentHealthCheckTimeout,
}

// AgentConfig describes the agent-side configuration of wiresteward.
type agentConfig struct {
	OAuth       agentOAuthConfig       `json:"oauth"`
	Devices     []agentDeviceConfig    `json:"devices"`
	HTTPClient  agentHTTPClientConfig  `json:"httpclient"`
	HealthCheck agentHealthCheckConfig `json:"healthcheck"`
}

func verifyAgentOAuthConfig(conf *agentConfig) error {
	if conf.OAuth.ClientID == "" {
		return fmt.Errorf("oauth config missing `clientID`")
	}
	if conf.OAuth.AuthURL == "" {
		return fmt.Errorf("oauth config missing `authUrl`")
	}
	if conf.OAuth.TokenURL == "" {
		return fmt.Errorf("oauth config missing `tokenUrl`")
	}
	return nil
}

func verifyAgentDevicesConfig(conf *agentConfig) error {
	if len(conf.Devices) == 0 {
		return fmt.Errorf("No devices defined in config")
	}
	for _, dev := range conf.Devices {
		if dev.Name == "" {
			return fmt.Errorf("Device name not specified in config")
		}
		for _, peer := range dev.Peers {
			if peer.URL == "" {
				return fmt.Errorf("Missing peer url from config")
			}
		}
	}
	return nil
}

// Add a var of the default interface used to read agent config, so that changes
// here can take effect on both this code and the tests.
var agentConfRead = &agentConfig{
	HTTPClient:  defaultAgentHTTPClientConfig,
	HealthCheck: dedfaultAgentHealthCheckConfig,
}

func readAgentConfig(path string) (*agentConfig, error) {
	conf := agentConfRead
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return conf, fmt.Errorf("error reading config file: %v", err)
	}
	if err = json.Unmarshal(fileContent, conf); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	if err = verifyAgentOAuthConfig(conf); err != nil {
		return nil, err
	}
	if err = verifyAgentDevicesConfig(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// serverConfig describes the server-side configuration of wiresteward.
type serverConfig struct {
	Address             string
	AllowedIPs          []string
	DeviceMTU           int
	DeviceName          string
	Endpoint            string
	KeyFilename         string
	LeaserSyncInterval  time.Duration
	LeasesFilename      string
	WireguardIPPrefix   netip.Prefix
	WireguardListenPort int
	OauthIntrospectURL  string
	OauthClientID       string
	ServerListenAddress string
}

func (c *serverConfig) UnmarshalJSON(data []byte) error {
	cfg := &struct {
		Address             string   `json:"address"`
		AllowedIPs          []string `json:"allowedIPs"`
		DeviceMTU           int      `json:"deviceMTU"`
		DeviceName          string   `json:"deviceName"`
		Endpoint            string   `json:"endpoint"`
		KeyFilename         string   `json:"keyFilename"`
		LeaserSyncInterval  string   `json:"leaserSyncInterval"`
		LeasesFilename      string   `json:"leasesFilename"`
		OauthIntrospectURL  string   `json:"oauthIntrospectURL"`
		OauthClientID       string   `json:"oauthClientID"`
		ServerListenAddress string   `json:"serverListenAddress"`
	}{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return err
	}
	if cfg.LeaserSyncInterval != "" {
		lsi, err := time.ParseDuration(cfg.LeaserSyncInterval)
		if err != nil {
			return err
		}
		c.LeaserSyncInterval = lsi
	}
	c.Address = cfg.Address
	c.AllowedIPs = cfg.AllowedIPs
	c.DeviceMTU = cfg.DeviceMTU
	c.DeviceName = cfg.DeviceName
	c.Endpoint = cfg.Endpoint
	c.KeyFilename = cfg.KeyFilename
	c.LeasesFilename = cfg.LeasesFilename
	c.OauthIntrospectURL = cfg.OauthIntrospectURL
	c.OauthClientID = cfg.OauthClientID
	c.ServerListenAddress = cfg.ServerListenAddress
	return nil
}

func verifyServerConfig(conf *serverConfig, allowPublicRoutes bool) error {
	if conf.Address == "" {
		return fmt.Errorf("config missing `address`")
	}
	conf.WireguardIPPrefix = netip.MustParsePrefix(conf.Address)
	if !allowPublicRoutes {
		ok, err := isPrivateCIDR(conf.Address)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf(
				"address %q is not a private CIDR: refusing to "+
					"configure a public range as the WireGuard "+
					"interface address; use -allow-public-routes "+
					"to override",
				conf.Address,
			)
		}
	}
	if len(conf.AllowedIPs) == 0 {
		logger.Verbosef("config missing `allowedIPs`, this server is not exposing any networks")
	}
	if !allowPublicRoutes {
		for _, cidr := range conf.AllowedIPs {
			ok, err := isPrivateCIDR(cidr)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf(
					"allowedIPs contains non-private CIDR %q: "+
						"refusing to route public ranges; use "+
						"-allow-public-routes to override",
					cidr,
				)
			}
		}
	}
	// Append the server wg /32 ip to the allowed ips in case the agent
	// wants to ping it for health checking
	conf.AllowedIPs = append(conf.AllowedIPs, conf.WireguardIPPrefix.String())

	if conf.DeviceName == "" {
		conf.DeviceName = defaultWireguardDeviceName
		logger.Verbosef(
			"config missing `deviceName`, using default: %s",
			defaultWireguardDeviceName,
		)
	}
	if conf.Endpoint == "" {
		return fmt.Errorf("config missing `endpoint`")
	}
	ep := strings.Split(conf.Endpoint, ":")
	if len(ep) != 2 {
		return fmt.Errorf("invalid `endpoint` value, it must be of the format `<host>:<port>`, got: %s", conf.Endpoint)
	}
	port, err := strconv.Atoi(ep[1])
	if err != nil {
		return fmt.Errorf("could not parse listen port value: %w", err)
	}
	conf.WireguardListenPort = port
	if conf.KeyFilename == "" {
		conf.KeyFilename = defaultKeyFilename
		logger.Verbosef(
			"config missing `keyFilename`, using default: %s",
			defaultKeyFilename,
		)
	}
	if conf.LeaserSyncInterval == 0 {
		conf.LeaserSyncInterval = defaultLeaserSyncInterval
		logger.Verbosef(
			"config missing `leaserSyncInterval`, using default: %s",
			defaultLeaserSyncInterval,
		)
	}
	if conf.LeasesFilename == "" {
		conf.LeasesFilename = defaultLeasesFilename
		logger.Verbosef(
			"config missing `leasesFilename`, using default: %s",
			defaultLeasesFilename,
		)
	}
	if conf.OauthIntrospectURL == "" {
		return fmt.Errorf("config missing `oauthIntrospectURL`")
	}
	if conf.OauthClientID == "" {
		return fmt.Errorf("config missing `oauthClientID`")
	}
	if conf.ServerListenAddress == "" {
		conf.ServerListenAddress = defaultServerListenAddress
		logger.Verbosef(
			"config missing `serverListenAddress`, using default: %s",
			defaultServerListenAddress,
		)
	}
	return nil
}

func readServerConfig(path string, allowPublicRoutes bool) (*serverConfig, error) {
	conf := &serverConfig{}
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	if err = json.Unmarshal(fileContent, conf); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	if err = verifyServerConfig(conf, allowPublicRoutes); err != nil {
		return nil, err
	}
	return conf, nil
}
