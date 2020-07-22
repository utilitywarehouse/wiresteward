**This is an experimental project and still at the very early stages.**

Table of Contents
=================

   * [wiresteward](#wiresteward)
      * [Usage](#usage)
      * [Agent](#agent)
         * [Getting and running the agent](#getting-and-running-the-agent)
         * [Agent config](#agent-config)
         * [Dev aws config - Example](#dev-aws-config---example)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

# wiresteward

[![Docker Repository on Quay](https://quay.io/repository/utilitywarehouse/wiresteward/status "Docker Repository on Quay")](https://quay.io/repository/utilitywarehouse/wiresteward)

wiresteward is a peer manager for wireguard instances. It is comprised by a
server and an agent functionality.

The agents post their public keys to the server and receive back configuration
to configure the wireguard interfaces on their host machine. The server updates
its peers list per agent request to add the advertised public key.

The server needs to run behind an oauth2 proxy, so that it is not "open" to the
public

## Usage

`wiresteward server`

| environment variable | description | default
| --- | --- | ---
| `WGS_USER_PEER_SUBNET` | subnet from which to allocate user peer addresses |
| `WGS_SERVER_PEER_CONFIG_PATH` | path to the JSON file containing server configuration | `server.json`

`wiresteward agent --config=path-to-config.json`

## Agent

### Getting and running the agent

Agent binaries can be found under wiresteward releases:
https://github.com/utilitywarehouse/wiresteward/releases

to install on linux simply:

```
wget -O /usr/bin/wiresteward https://github.com/utilitywarehouse/wiresteward/releases/download/v0.1.0-rc0/wiresteward_0.1.0-rc0_linux_amd64
chmod +x /usr/bin/wiresteward
```

A successful wiresteward agent run will:

- create new network devices
- Generate and post wireguard keys
- Configure wireguard peers
- Configure routes for the subnets advertised by the server

thus it needs NET_ADMIN capabilities.

To run simply:
```
wiresteward agent --config=path-to-config.json
```

### Agent config

Agent takes a config file as an argument (or `~/wiresteward.json` if not
specified), from where it gets all the details needed to get a token from okta
and create/update the wg interfaces and routes after talking to the remote
wiresteward peers.

An example, where the config format can be found is here:
https://github.com/utilitywarehouse/wiresteward/blob/master/agent.json.example


### Dev aws config - Example

A config file to talk to the dev-aws wiresteward servers:

```
{
  "oidc": {
    "clientID": "0oa5lj5deYlDCe8Es416",
    "authUrl": "https://login.uw.systems/oauth2/v1/authorize",
    "tokenUrl": "https://login.uw.systems/oauth2/v1/token"
  },
  "devs": [
    {
      "name": "wg-dev-aws",
      "peers": [
        {
          "url": "https://wireguard.dev.aws.uw.systems"
        }
      ]
    }
  ]
}
```
