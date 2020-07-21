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
	err := UnmarshallAgentConfig(oidcOnly, conf)
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

	devsOnly := []byte(`
{
  "devs": [
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
	err = UnmarshallAgentConfig(devsOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(*conf.Devs), 1)
	assert.Equal(t, (*conf.Devs)[0].Name, "wg_test")
	peers := (*conf.Devs)[0].Peers
	assert.Equal(t, len(*peers), 2)
	assert.Equal(t, (*peers)[0].Url, "example1.com")
	assert.Equal(t, (*peers)[1].Url, "example2.com")
	err = verifyAgentDevsConfig(conf)
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
  "devs": [
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
	err = UnmarshallAgentConfig(full, conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthUrl, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenUrl, "example.com/token")
	assert.Equal(t, len(*conf.Devs), 1)
	assert.Equal(t, (*conf.Devs)[0].Name, "wg_test")
	peers = (*conf.Devs)[0].Peers
	assert.Equal(t, len(*peers), 1)
	assert.Equal(t, (*peers)[0].Url, "example1.com")
	err = verifyAgentOidcConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentDevsConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
}
