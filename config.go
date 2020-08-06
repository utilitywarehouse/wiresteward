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
	defaultLeasesFilename = "/etc/wiresteward/leases"
	defaultLeaseTime      = 12 * time.Hour
)

// AgentOidcConfig encapsulates agent-side OIDC configuration for wiresteward.
type AgentOidcConfig struct {
	ClientID string `json:"clientID"`
	AuthURL  string `json:"authUrl"`
	TokenURL string `json:"tokenUrl"`
}

// AgentPeerConfig contains the agent-side configuration for a wiresteward
// server.
type AgentPeerConfig struct {
	URL string `json:"url"`
}

// AgentInterfaceConfig defines an interface and associated wiresteward servers.
type AgentInterfaceConfig struct {
	Name  string            `json:"name"`
	Peers []AgentPeerConfig `json:"peers"`
}

// AgentConfig describes the agent-side configuration of wiresteward.
type AgentConfig struct {
	Oidc       AgentOidcConfig        `json:"oidc"`
	Interfaces []AgentInterfaceConfig `json:"interfaces"`
}

func verifyAgentOidcConfig(conf *AgentConfig) error {
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

func verifyAgentInterfacesConfig(conf *AgentConfig) error {
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

func readAgentConfig(path string) (*AgentConfig, error) {
	conf := &AgentConfig{}
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

// ServerConfig describes the server-side configuration of wiresteward.
type ServerConfig struct {
	Address            string
	AllowedIPs         []string
	Endpoint           string
	LeasesFilename     string
	LeaseTime          time.Duration
	WireguardIPAddress net.IP
	WireguardIPNetwork *net.IPNet
}

// UnmarshalJSON decodes and parses json into a ServerConfig struct.
func (c *ServerConfig) UnmarshalJSON(data []byte) error {
	cfg := &struct {
		Address        string   `json:"address"`
		AllowedIPs     []string `json:"allowedIPs"`
		Endpoint       string   `json:"endpoint"`
		LeasesFilename string   `json:"leasesFilename"`
		LeaseTime      string   `json:"leaseTime"`
	}{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return err
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

func verifyServerConfig(conf *ServerConfig) error {
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

func readServerConfig(path string) (*ServerConfig, error) {
	conf := &ServerConfig{}
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
