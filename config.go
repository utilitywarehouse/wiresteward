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

type AgentDevConfig struct {
	Name  string             `json:"name"`
	Peers *[]AgentPeerConfig `json:"peers"`
}

type AgentConfig struct {
	Oidc *AgentOidcConfig  `json:"oidc"`
	Devs *[]AgentDevConfig `json:"devs"`
}

func UnmarshallAgentConfig(data []byte, v interface{}) error {
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

func verifyAgentDevsConfig(conf *AgentConfig) error {
	for _, dev := range *conf.Devs {
		if dev.Name == "" {
			return fmt.Errorf("Device name not specified in config")
		}
		for _, peer := range *dev.Peers {
			if peer.Url == "" {
				return fmt.Errorf("Missing peer url from config")
			}
		}
	}
	return nil
}

func ReadAgentConfig(path string) (*AgentConfig, error) {
	conf := &AgentConfig{}

	confFile, err := os.Open(path)
	if err != nil {
		return conf, fmt.Errorf("failed to open config file: %v", err)
	}

	fileContent, err := ioutil.ReadAll(confFile)
	if err != nil {
		return conf, fmt.Errorf("error reading config file: %v", err)
	}

	if err = UnmarshallAgentConfig(fileContent, conf); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %v", err)
	}
	if err = verifyAgentOidcConfig(conf); err != nil {
		return nil, err
	}
	if err = verifyAgentDevsConfig(conf); err != nil {
		return nil, err
	}

	return conf, nil
}
