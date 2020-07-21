**This is an experimental project and still at the very early stages.**

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
