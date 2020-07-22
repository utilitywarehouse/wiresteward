package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type AgentOidcConfig struct {
	ClientID string `json:"clientID"`
	AuthUrl  string `json:"authUrl"`
	TokenUrl string `json:"tokenUrl"`
}

type AgentPeerConfig struct {
	Url string `json:"url"`
}

type AgentInterfaceConfig struct {
	Name  string            `json:"name"`
	Peers []AgentPeerConfig `json:"peers"`
}

type AgentConfig struct {
	Oidc       AgentOidcConfig        `json:"oidc"`
	Interfaces []AgentInterfaceConfig `json:"interfaces"`
}

func unmarshalAgentConfig(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func verifyAgentOidcConfig(conf *AgentConfig) error {

	if conf.Oidc.ClientID == "" {
		return fmt.Errorf("oidc config missing `clientID`")
	}
	if conf.Oidc.AuthUrl == "" {
		return fmt.Errorf("oidc config missing `authUrl`")
	}
	if conf.Oidc.TokenUrl == "" {
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
			if peer.Url == "" {
				return fmt.Errorf("Missing peer url from config")
			}
		}
	}
	return nil
}

func readAgentConfig(path string) (*AgentConfig, error) {
	conf := &AgentConfig{}

	confFile, err := os.Open(path)
	if err != nil {
		return conf, fmt.Errorf("failed to open config file: %v", err)
	}

	fileContent, err := ioutil.ReadAll(confFile)
	if err != nil {
		return conf, fmt.Errorf("error reading config file: %v", err)
	}

	if err = unmarshalAgentConfig(fileContent, conf); err != nil {
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
