package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
	err := json.Unmarshal(oidcOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthURL, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenURL, "example.com/token")
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
	err = json.Unmarshal(interfacesOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(conf.Interfaces), 1)
	assert.Equal(t, conf.Interfaces[0].Name, "wg_test")
	peers := (conf.Interfaces)[0].Peers
	assert.Equal(t, len(peers), 2)
	assert.Equal(t, peers[0].URL, "example1.com")
	assert.Equal(t, peers[1].URL, "example2.com")
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
	err = json.Unmarshal(full, conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthURL, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenURL, "example.com/token")
	assert.Equal(t, len(conf.Interfaces), 1)
	assert.Equal(t, conf.Interfaces[0].Name, "wg_test")
	peers = conf.Interfaces[0].Peers
	assert.Equal(t, len(peers), 1)
	assert.Equal(t, peers[0].URL, "example1.com")
	err = verifyAgentOidcConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentInterfacesConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerConfig(t *testing.T) {
	ip, net, _ := net.ParseCIDR("10.0.0.1/24")
	testCases := []struct {
		input []byte
		cfg   *ServerConfig
		err   bool
	}{
		{
			[]byte(`{
				"address": "10.0.0.1/24",
				"allowedIPs": ["1.2.3.4/8"],
				"endpoint": "1.2.3.4"
			}`),
			&ServerConfig{
				Address:            "10.0.0.1/24",
				AllowedIPs:         []string{"1.2.3.4/8"},
				Endpoint:           "1.2.3.4",
				LeasesFilename:     defaultLeasesFilename,
				LeaseTime:          defaultLeaseTime,
				WireguardIPAddress: ip,
				WireguardIPNetwork: net,
			},
			false,
		},
		{
			[]byte(`{
				"address": "10.0.0.1/24",
				"endpoint": "1.2.3.4",
				"leasesFilename": "foo",
				"leaseTime": "2h"
			}`),
			&ServerConfig{
				Address:            "10.0.0.1/24",
				Endpoint:           "1.2.3.4",
				LeasesFilename:     "foo",
				LeaseTime:          time.Duration(time.Hour * 2),
				WireguardIPAddress: ip,
				WireguardIPNetwork: net,
			},
			false,
		},
		{
			[]byte(`{
				"endpoint": ""
			}`),
			&ServerConfig{},
			true,
		},
	}

	for i, tc := range testCases {
		cfg := &ServerConfig{}
		if err := json.Unmarshal(tc.input, cfg); err != nil && !tc.err {
			t.Errorf("TestServerConfigFmt: test case %d produced an unexpected error, got %v, expected %v", i, err, tc.err)
			continue
		}
		if err := verifyServerConfig(cfg); err != nil && !tc.err {
			t.Errorf("TestServerConfigFmt: test case %d produced an unexpected error, got %v, expected %v", i, err, tc.err)
			continue
		}
		if diff := cmp.Diff(tc.cfg, cfg); diff != "" {
			t.Errorf("TestServerConfigFmt: test case %d produced an unexpected results:\n%s", i, diff)
		}
	}
}
