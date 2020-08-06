package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

const (
	defaultLeaserSyncInterval = 1 * time.Minute
	defaultLeasesFilename     = "/etc/wiresteward/leases"
	defaultLeaseTime          = 12 * time.Hour
)

// agentOidcConfig encapsulates agent-side OIDC configuration for wiresteward.
type agentOidcConfig struct {
	ClientID string `json:"clientID"`
	AuthURL  string `json:"authUrl"`
	TokenURL string `json:"tokenUrl"`
}

// agentPeerConfig contains the agent-side configuration for a wiresteward
// server.
type agentPeerConfig struct {
	URL string `json:"url"`
}

// agentInterfaceConfig defines an interface and associated wiresteward servers.
type agentInterfaceConfig struct {
	Name  string            `json:"name"`
	Peers []agentPeerConfig `json:"peers"`
}

// AgentConfig describes the agent-side configuration of wiresteward.
type agentConfig struct {
	Oidc       agentOidcConfig        `json:"oidc"`
	Interfaces []agentInterfaceConfig `json:"interfaces"`
}

func verifyAgentOidcConfig(conf *agentConfig) error {
	if conf.Oidc.ClientID == "" {
		return fmt.Errorf("oidc config missing `clientID`")
	}
	if conf.Oidc.AuthURL == "" {
		return fmt.Errorf("oidc config missing `authUrl`")
	}
	if conf.Oidc.TokenURL == "" {
		return fmt.Errorf("oidc config missing `tokenUrl`")
	}
	return nil
}

func verifyAgentInterfacesConfig(conf *agentConfig) error {
	for _, iface := range conf.Interfaces {
		if iface.Name == "" {
			return fmt.Errorf("Interface name not specified in config")
		}
		for _, peer := range iface.Peers {
			if peer.URL == "" {
				return fmt.Errorf("Missing peer url from config")
			}
		}
	}
	return nil
}

func readAgentConfig(path string) (*agentConfig, error) {
	conf := &agentConfig{}
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, fmt.Errorf("error reading config file: %v", err)
	}
	if err = json.Unmarshal(fileContent, conf); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	if err = verifyAgentOidcConfig(conf); err != nil {
		return nil, err
	}
	if err = verifyAgentInterfacesConfig(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// serverConfig describes the server-side configuration of wiresteward.
type serverConfig struct {
	Address            string
	AllowedIPs         []string
	Endpoint           string
	LeaserSyncInterval time.Duration
	LeasesFilename     string
	LeaseTime          time.Duration
	WireguardIPAddress net.IP
	WireguardIPNetwork *net.IPNet
}

func (c *serverConfig) UnmarshalJSON(data []byte) error {
	cfg := &struct {
		Address            string   `json:"address"`
		AllowedIPs         []string `json:"allowedIPs"`
		Endpoint           string   `json:"endpoint"`
		LeaserSyncInterval string   `json:"leaserSyncInterval"`
		LeasesFilename     string   `json:"leasesFilename"`
		LeaseTime          string   `json:"leaseTime"`
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
	if cfg.LeaseTime != "" {
		lt, err := time.ParseDuration(cfg.LeaseTime)
		if err != nil {
			return err
		}
		c.LeaseTime = lt
	}
	c.Address = cfg.Address
	c.AllowedIPs = cfg.AllowedIPs
	c.Endpoint = cfg.Endpoint
	c.LeasesFilename = cfg.LeasesFilename
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
		log.Printf("config missing `allowedIPs`, this server is not exposing any networks")
	}
	if conf.Endpoint == "" {
		return fmt.Errorf("config missing `endpoint`")
	}
	if conf.LeaserSyncInterval == 0 {
		conf.LeaserSyncInterval = defaultLeaserSyncInterval
		log.Printf("config missing `leaserSyncInterval`, using default: %s", defaultLeaserSyncInterval)
	}
	if conf.LeasesFilename == "" {
		conf.LeasesFilename = defaultLeasesFilename
		log.Printf("config missing `leasesFilename`, using default: %s", defaultLeasesFilename)
	}
	if conf.LeaseTime == 0 {
		conf.LeaseTime = defaultLeaseTime
		log.Printf("config missing `leaseTime`, using default: %s", defaultLeaseTime)
	}
	return nil
}

func readServerConfig(path string) (*serverConfig, error) {
	conf := &serverConfig{}
	fileContent, err := ioutil.ReadFile(path)
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
