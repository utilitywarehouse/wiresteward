# Wiresteward

Wiresteward is a wireguard peer manager with oauth2 authentication. It is
comprised of two components: server and agent.

The design is for wiresteward server to run on a remote machine in a private
network, to which users will connect with wireguard in order to access the
private network.

The agent runs on the user's machine and is responsible for authenticating with
the server and retrieving wireguard configuration.

Both components will configure their local wireguard devices and route tables as
needed to enable access to a private network.

## Installation

Binaries found under wiresteward releases include the agent and server modes:
https://github.com/utilitywarehouse/wiresteward/releases

To install on AMD64:

```
os=$(uname | awk '{print tolower($0)}')
wget -O /usr/local/bin/wiresteward https://github.com/utilitywarehouse/wiresteward/releases/download/v0.2.3/wiresteward_0.2.3_${os}_amd64
chmod +x /usr/local/bin/wiresteward
```

## Usage

You can simply run wiresteward on your terminal:

```
wiresteward -server -config=path-to-config.json
```

```
wiresteward -agent -config=path-to-config.json
```

Please note that because `wiresteward` will create and manage network devices
and network routes, it requires `NET_ADMIN` capabilities. You can simply run it
as root with `sudo`.

See [`examples/server.json`](./examples/server.json) and
[`examples/agent.json`](./examples/agent.json) for example configuration.

## Agent

The wiresteward agent is responsible for:

- creating new network tun devices
- fetching oauth tokens to pass server authentication
- registering wireguard keys with the wiresteward server and retrieving configuration
- configuring wireguard peers
- configuring routes for the subnets allowed by the server

It is recommended that the agent is run as a system service.

### Configuration

The agent can take a config file as an argument or look for it under the default
location `/etc/wiresteward/config.json`. The config contains details about the
oauth server and the local devices that we need the agent to manage.

An example, where the config format can be found in
[`examples/agent.json`](./examples/agent.json).

#### MTU

The default mtu for the interfaces created via the agent is `1420` and it comes
from the [default value of wireguard-go package](https://git.zx2c4.com/wireguard-go/tree/device/tun.go#n14).
Optionally, the mtu can be set explicitly per wg device created by the agent via
the configuration file (using the "mtu" key under device config)

### Running as systemd service (Linux)

The agent is designed to run as a systemd service. An example working service
is described in [`examples/wiresteward.service`](./examples/wiresteward.service).

A typical location for user defined systemd service is
`/etc/systemd/system/wiresteward.service` so you'll need to copy the unit file
to that location and then:

```
systemctl daemon-reload
systemctl enable wiresteward.service
systemctl start wiresteward.service
```

To look at its logs:

```
journalctl -u  wiresteward.service
```

### Running as launchd service (macOS)

An example working service for launchd is described in
[`examples/uk.co.uw.wiresteward.plist`](./examples/uk.co.uw.wiresteward.plist).

You need to copy the file under `/Library/LaunchDaemons/` and then set the
ownership to root:

```
chown root:admin /Library/LaunchDaemons/uk.co.uw.wiresteward.plist
```

Finally, you need to load the service:

```
sudo launchctl load /Library/LaunchDaemons/uk.co.uw.wiresteward.plist
```

This will allow the service to run as root, which is required to operate on the
network devices and routing table.

Logs are stored in `/var/log/wirestward.log` as defined in the service file. To
view the logs you can simply:

```
tail -f /var/log/wiresteward.log
```

You might want to setup log rotation as well if you find that the log file
grows too large.

### Authentication

The agent runs a local server on port 7773 and expects the user to visit
`http://localhost:7773/` in order to authenticate. Once authenticated, the agent
will be able to continue operating until the token retrieved is expired, at
which point the user needs to authenticate again.

Visiting `http://localhost:7773/` will cause the agent to immediately configure
the local wireguard devices. If it already has a valid token, it will not prompt
the user to re-authenticate but it will re-configure the system.

## Server

The wiresteward server is responsible for:

- creating new network wireguard device
- registering new peers and allocating ip addresses for them
- configuring wireguard peers
- revoking access for expired address leases

It is recommended that the agent is run as a systemd service.

### Configuration

The server can take a config file as an argument or look for it under the
default location `/etc/wiresteward/config.json`. The config contains details
about the oauth server and the network subnets that need to be exposed, as well
as the network subnet from which peer addresses are leased to agents.

An example, where the config format can be found in
[`examples/server.json`](./examples/server.json).

### Running

There are Terraform modules defined under [`terraform/`](./terraform) which
describe the recommended deployment method in AWS and GCP. See the more specific
[README](./terraform/README.md) file for details.
