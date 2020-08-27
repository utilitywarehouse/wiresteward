**This is an experimental project and still at the very early stages.**

Table of Contents
=================

   * [Table of Contents](#table-of-contents)
   * [wiresteward](#wiresteward)
      * [Usage](#usage)
      * [Agent](#agent)
         * [Install](#install)
         * [Try](#try)
         * [Running as systemd service](#running-as-systemd-service)
         * [Run](#run)
         * [Config](#config)
         * [Dev aws config - Example](#dev-aws-config---example)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

# wiresteward

[![Docker Repository on Quay](https://quay.io/repository/utilitywarehouse/wiresteward/status "Docker Repository on Quay")](https://quay.io/repository/utilitywarehouse/wiresteward)
[![Build Status](https://travis-ci.org/utilitywarehouse/wiresteward.svg?branch=master)](https://travis-ci.org/utilitywarehouse/wiresteward)

wiresteward is a peer manager for wireguard instances. It is comprised by a
server and an agent functionality.

The agents post their public keys to the server and receive back configuration
to configure the wireguard devices on their host machine. The server updates its
peers list per agent request to add the advertised public key.

The server needs to run behind an oauth2 proxy, so that it is not "open" to the
public

## Usage

`wiresteward -server -config=path-to-config.json`
`wiresteward -agent -config=path-to-config.json`

See [server.json.example](server.json.example) and
[agent.json.example](agent.json.example) for example configuration.


## Agent

### Install

Agent binaries can be found under wiresteward releases:
https://github.com/utilitywarehouse/wiresteward/releases

To install on linux:

```
wget -O /usr/local/bin/wiresteward https://github.com/utilitywarehouse/wiresteward/releases/download/v0.1.0-rc0/wiresteward_0.1.0-rc0_linux_amd64
chmod +x /usr/local/bin/wiresteward
```

### Try
The wiresteward agent is responsible for:

- creating new network itun devices
- Generating and posting wireguard keys to the server
- Fetching oauth tokens to pass server authentication
- Configuring wireguard peers
- Configuring routes for the subnets allowed by the server
thus it needs NET_ADMIN capabilities.

To try it one can:
```
wiresteward -agent -config=path-to-config.json
```

It is recommended that the agent is run as a systemd service.

### Running as systemd service
The agent is designed to run as a systemd service. An example working service
is shown below. Typical location for user defined systemd service:
`/etc/systemd/system/wiresteward.service`

```
[Unit]
Description=wiresteward agent
After=network-online.target
Requires=network-online.target
[Service]
Restart=on-failure
ExecStart=/usr/local/bin/wiresteward -agent
[Install]
WantedBy=multi-user.target
```

then:
```
systemctl enable wiresteward.service
systemctl start wiresteward.service
```

To look at it's logs:
```
journalctl -u  wiresteward.service
```

### Run

The agent runs a local server on port 7773 and expects the user to visit
`localhost:7773/` to trigger all the actions described above (under #Usage)

Opening `localhost:7773/` on a browser will trigger the oauth process, if
necessary, and ask the configured remote server peers for details to configure
them as wg peers under the respective device (defined in configuration file,
see below)

### Config

Agent can takes a config file as an argument or look for it under the default
location `/etc/wiresteward/config.json`, chosen to suit the systemd service.
The config contains details about the oidc server and the local devices that
we need the agent to manage.

An example, where the config format can be found is here:
https://github.com/utilitywarehouse/wiresteward/blob/master/agent.json.example

### MTU

The default mtu for the interfaces created via the agent is `1420` and it comes
from the default value of wireguard-go package.
(https://git.zx2c4.com/wireguard-go/tree/device/tun.go#n14)
Optionally, mtu can be set explicitly per wg device created by the agent via the
configuration file (using the "mtu" key under device config)

### Dev config - Example

A config file to talk to the dev-aws wiresteward servers:

```
{
  "oidc": {
    "clientID": "0oa5lj5deYlDCe8Es416",
    "authUrl": "https://login.uw.systems/oauth2/v1/authorize",
    "tokenUrl": "https://login.uw.systems/oauth2/v1/token"
  },
  "devices": [
    {
      "name": "wg-uw-dev-aws",
      "peers": [
        {
	  "url": "https://wiresteward.dev.aws.uw.systems"
	}
      ]
    },
    {
      "name": "wg-uw-dev-gcp",
      "mtu": 1380,
      "peers": [
        {
	  "url": "https://wiresteward.dev.gcp.uw.systems"
	}
      ]
    }
  ]
}
```
