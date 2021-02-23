package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultKeyFilename         = "/etc/wiresteward/key"
	defaultLeaserSyncInterval  = 1 * time.Minute
	defaultLeasesFilename      = "/var/lib/wiresteward/leases"
	defaultServerListenAddress = "0.0.0.0:8080"
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

// agentPeerConfig contains the port to attempt health checking all peers for a
// device
type agentHealthCheckConfig struct {
	Port int `json:"port"`
}

// agentDeviceConfig defines a network device and associated wiresteward
// servers.
type agentDeviceConfig struct {
	Name        string                 `json:"name"`
	MTU         int                    `json:"mtu"`
	Peers       []agentPeerConfig      `json:"peers"`
	HealthCheck agentHealthCheckConfig `json: "healthcheck"`
}

// AgentConfig describes the agent-side configuration of wiresteward.
type agentConfig struct {
	OAuth   agentOAuthConfig    `json:"oauth"`
	Devices []agentDeviceConfig `json:"devices"`
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

func readAgentConfig(path string) (*agentConfig, error) {
	conf := &agentConfig{}
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
	WireguardIPAddress  net.IP
	WireguardIPNetwork  *net.IPNet
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

func verifyServerConfig(conf *serverConfig) error {
	if conf.Address == "" {
		return fmt.Errorf("config missing `address`")
	}
	ip, network, err := net.ParseCIDR(conf.Address)
	if err != nil {
		return fmt.Errorf("could not parse address as a CIDR: %w", err)
	}
	conf.WireguardIPAddress = ip
	conf.WireguardIPNetwork = network
	if len(conf.AllowedIPs) == 0 {
		logger.Info.Printf("config missing `allowedIPs`, this server is not exposing any networks")
	}
	// Append the server wg /32 ip to the allowed ips in case the agent wants to ping it for health checking
	conf.AllowedIPs = append(conf.AllowedIPs, fmt.Sprintf("%s/%s", conf.WireguardIPAddress.String(), "32"))

	if conf.DeviceName == "" {
		conf.DeviceName = defaultWireguardDeviceName
		logger.Info.Printf(
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
		logger.Info.Printf(
			"config missing `keyFilename`, using default: %s",
			defaultKeyFilename,
		)
	}
	if conf.LeaserSyncInterval == 0 {
		conf.LeaserSyncInterval = defaultLeaserSyncInterval
		logger.Info.Printf(
			"config missing `leaserSyncInterval`, using default: %s",
			defaultLeaserSyncInterval,
		)
	}
	if conf.LeasesFilename == "" {
		conf.LeasesFilename = defaultLeasesFilename
		logger.Info.Printf(
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
		logger.Info.Printf(
			"config missing `serverListenAddress`, using default: %s",
			defaultServerListenAddress,
		)
	}
	return nil
}

func readServerConfig(path string) (*serverConfig, error) {
	conf := &serverConfig{}
	fileContent, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	if err = json.Unmarshal(fileContent, conf); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	if err = verifyServerConfig(conf); err != nil {
		return nil, err
	}
	return conf, nil
}
