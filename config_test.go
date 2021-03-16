package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

func TestAgentConfigFmt(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")
	oauthOnly := []byte(`
{
  "oauth": {
    "clientID": "xxxxx",
    "authUrl": "example.com/auth",
    "tokenUrl": "example.com/token"
  }
}
`)
	conf := &agentConfig{}
	err := json.Unmarshal(oauthOnly, conf)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, conf.OAuth.ClientID, "xxxxx")
	assert.Equal(t, conf.OAuth.AuthURL, "example.com/auth")
	assert.Equal(t, conf.OAuth.TokenURL, "example.com/token")
	err = verifyAgentOAuthConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentHTTPClientConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HTTPClient.Timeout, defaultAgentHTTPClientTimeout)
	err = verifyAgentHealthCheckConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HealthCheck.Interval, defaultAgentHealthCheckInterval)
	assert.Equal(t, conf.HealthCheck.Timeout, defaultAgentHealthCheckTimeout)
	assert.Equal(t, conf.HealthCheck.Threshold, defaultAgentHealthCheckThreshold)

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
	err = verifyAgentHTTPClientConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HTTPClient.Timeout, defaultAgentHTTPClientTimeout)
	err = verifyAgentHealthCheckConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HealthCheck.Interval, defaultAgentHealthCheckInterval)
	assert.Equal(t, conf.HealthCheck.Timeout, defaultAgentHealthCheckTimeout)
	assert.Equal(t, conf.HealthCheck.Threshold, defaultAgentHealthCheckThreshold)

	full := []byte(`
{
  "oauth": {
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
  ],
  "httpclient": {
    "timeout": "5s"
  },
  "healthcheck": {
    "interval": "5s",
    "timeout": "5s",
    "threshold": 5
  }
}
`)

	conf = &agentConfig{}
	err = json.Unmarshal(full, conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.OAuth.ClientID, "xxxxx")
	assert.Equal(t, conf.OAuth.AuthURL, "example.com/auth")
	assert.Equal(t, conf.OAuth.TokenURL, "example.com/token")
	assert.Equal(t, len(conf.Devices), 1)
	assert.Equal(t, conf.Devices[0].Name, "wg_test")
	assert.Equal(t, conf.Devices[0].MTU, 1380)
	peers = conf.Devices[0].Peers
	assert.Equal(t, len(peers), 1)
	assert.Equal(t, peers[0].URL, "example1.com")
	err = verifyAgentOAuthConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentDevicesConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyAgentHTTPClientConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HTTPClient.Timeout, "5s")
	err = verifyAgentHealthCheckConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, conf.HealthCheck.Interval, "5s")
	assert.Equal(t, conf.HealthCheck.Timeout, "5s")
	assert.Equal(t, conf.HealthCheck.Threshold, 5)
}

func TestServerConfig(t *testing.T) {
	setLogLevel("error")
	logger = newLogger("wiresteward-test")
	ipPrefix := netaddr.MustParseIPPrefix("10.0.0.1/24")
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
				AllowedIPs:          []string{"1.2.3.4/8", "10.0.0.1/32"},
				DeviceName:          "wg0",
				Endpoint:            "1.2.3.4:1234",
				KeyFilename:         defaultKeyFilename,
				LeaserSyncInterval:  defaultLeaserSyncInterval,
				LeasesFilename:      defaultLeasesFilename,
				WireguardIPPrefix:   ipPrefix,
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
				AllowedIPs:          []string{"10.0.0.1/32"},
				DeviceMTU:           1300,
				DeviceName:          "wg1",
				Endpoint:            "1.2.3.4:12345",
				KeyFilename:         "bar",
				LeasesFilename:      "foo",
				LeaserSyncInterval:  time.Duration(time.Hour * 3),
				WireguardIPPrefix:   ipPrefix,
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
	}
}
