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
	setLogLevel("error")
	logger = initLogger("wiresteward-test")
	oidcOnly := []byte(`
{
  "oidc": {
    "clientID": "xxxxx",
    "authUrl": "example.com/auth",
    "tokenUrl": "example.com/token"
  }
}
`)
	conf := &agentConfig{}
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

	devicesOnly := []byte(`
{
  "devices": [
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

	conf = &agentConfig{}
	err = json.Unmarshal(devicesOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, len(conf.Devices), 1)
	assert.Equal(t, conf.Devices[0].Name, "wg_test")
	assert.Equal(t, conf.Devices[0].MTU, 0)
	peers := (conf.Devices)[0].Peers
	assert.Equal(t, len(peers), 2)
	assert.Equal(t, peers[0].URL, "example1.com")
	assert.Equal(t, peers[1].URL, "example2.com")
	err = verifyAgentDevicesConfig(conf)
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
  "devices": [
    {
      "name": "wg_test",
      "mtu": 1380,
      "peers": [
        {
            "url": "example1.com"
        }
      ]
    }
  ]
}
`)

	conf = &agentConfig{}
	err = json.Unmarshal(full, conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.Oidc.ClientID, "xxxxx")
	assert.Equal(t, conf.Oidc.AuthURL, "example.com/auth")
	assert.Equal(t, conf.Oidc.TokenURL, "example.com/token")
	assert.Equal(t, len(conf.Devices), 1)
	assert.Equal(t, conf.Devices[0].Name, "wg_test")
	assert.Equal(t, conf.Devices[0].MTU, 1380)
	peers = conf.Devices[0].Peers
	assert.Equal(t, len(peers), 1)
	assert.Equal(t, peers[0].URL, "example1.com")
	err = verifyAgentOidcConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentDevicesConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerConfig(t *testing.T) {
	setLogLevel("error")
	logger = initLogger("wiresteward-test")
	ip, net, _ := net.ParseCIDR("10.0.0.1/24")
	testCases := []struct {
		input []byte
		cfg   *serverConfig
		err   bool
	}{
		{
			[]byte(`{
				"address": "10.0.0.1/24",
				"allowedIPs": ["1.2.3.4/8"],
				"endpoint": "1.2.3.4:1234",
				"oauthIntrospectURL": "example.com",
				"oauthClientID": "client_id"
			}`),
			&serverConfig{
				Address:             "10.0.0.1/24",
				AllowedIPs:          []string{"1.2.3.4/8"},
				DeviceName:          "wg0",
				Endpoint:            "1.2.3.4:1234",
				KeyFilename:         defaultKeyFilename,
				LeaserSyncInterval:  defaultLeaserSyncInterval,
				LeasesFilename:      defaultLeasesFilename,
				WireguardIPAddress:  ip,
				WireguardIPNetwork:  net,
				WireguardListenPort: 1234,
				OauthIntrospectURL:  "example.com",
				OauthClientID:       "client_id",
				ServerListenAddress: "0.0.0.0:8080",
			},
			false,
		},
		{
			[]byte(`{
				"address": "10.0.0.1/24",
				"endpoint": "1.2.3.4:12345",
				"deviceMTU": 1300,
				"deviceName": "wg1",
				"keyFilename": "bar",
				"leaserSyncInterval": "3h",
				"leasesFilename": "foo",
				"oauthIntrospectURL": "example.com",
				"oauthClientID": "client_id"
			}`),
			&serverConfig{
				Address:             "10.0.0.1/24",
				DeviceMTU:           1300,
				DeviceName:          "wg1",
				Endpoint:            "1.2.3.4:12345",
				KeyFilename:         "bar",
				LeasesFilename:      "foo",
				LeaserSyncInterval:  time.Duration(time.Hour * 3),
				WireguardIPAddress:  ip,
				WireguardIPNetwork:  net,
				WireguardListenPort: 12345,
				OauthIntrospectURL:  "example.com",
				OauthClientID:       "client_id",
				ServerListenAddress: "0.0.0.0:8080",
			},
			false,
		},
		{
			[]byte(`{
				"endpoint": ""
			}`),
			&serverConfig{},
			true,
		},
	}

	for i, tc := range testCases {
		cfg := &serverConfig{}
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
