package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgentConfigFmt(t *testing.T) {

	oidcOnly := []byte(`
{
  "oidc": {
    "clientID": "xxxxx",
    "authUrl": "example.com/auth",
    "tokenUrl": "example.com/token"
  }
}
`)
	conf := &AgentConfig{}
	err := unmarshalAgentConfig(oidcOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthUrl, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenUrl, "example.com/token")
	err = verifyAgentOidcConfig(conf)
	if err != nil {
		t.Fatal(err)
	}

	interfacesOnly := []byte(`
{
  "interfaces": [
    {
      "name": "wg_test",
      "peers": [
        {
	  "url": "example1.com"
	},
        {
	  "url": "example2.com"
	}
      ]
    }
  ]
}
`)

	conf = &AgentConfig{}
	err = unmarshalAgentConfig(interfacesOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(conf.Interfaces), 1)
	assert.Equal(t, conf.Interfaces[0].Name, "wg_test")
	peers := (conf.Interfaces)[0].Peers
	assert.Equal(t, len(peers), 2)
	assert.Equal(t, peers[0].Url, "example1.com")
	assert.Equal(t, peers[1].Url, "example2.com")
	err = verifyAgentInterfacesConfig(conf)
	if err != nil {
		t.Fatal(err)
	}

	full := []byte(`
{
  "oidc": {
    "clientID": "xxxxx",
    "authUrl": "example.com/auth",
    "tokenUrl": "example.com/token"
  },
  "interfaces": [
    {
      "name": "wg_test",
      "peers": [
        {
	  "url": "example1.com"
	}
      ]
    }
  ]
}
`)

	conf = &AgentConfig{}
	err = unmarshalAgentConfig(full, conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthUrl, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenUrl, "example.com/token")
	assert.Equal(t, len(conf.Interfaces), 1)
	assert.Equal(t, conf.Interfaces[0].Name, "wg_test")
	peers = conf.Interfaces[0].Peers
	assert.Equal(t, len(peers), 1)
	assert.Equal(t, peers[0].Url, "example1.com")
	err = verifyAgentOidcConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentInterfacesConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
}
