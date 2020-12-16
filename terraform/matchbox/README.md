# Opinionated matchbox provider terrafrom module for wiresteward

This module assumes that wiresteward will be deployed on bare metal nodes via
matchbox on flatcar os.
The assumed topology includes:
- 2 NICs per node that will set up a port-channel.
- 2 existing vlans on the network, one for public traffic and one for pivate on
  subnet 10.0.0.0/8.
- The ability to assign and route public ips on host interfaces.

This does not implement a load balancer between the deployed wiresteward servers
but since ignition systemd services and files are passed in as input variables
one could include the necessary configuration in order to work with different
solutions (e.t.c. cloudflare argo tunnels)

## Example usage

```
module "wiresteward_ignition" {
  source = "github.com/utilitywarehouse/wiresteward//terraform/ignition?ref=master"

  oauth2_client_id           = "xxxxxxxxxxxxxxxxxxxxx"
  oauth2_introspect_url      = "https://login.uw.systems/oauth2/default/v1/introspect"
  ssh_key_agent_uri          = "https://s3-eu-west-1.amazonaws.com/ssh-keys/authmap"
  ssh_key_agent_groups       = ["people@example.com"]
  wireguard_cidrs            = ["10.10.0.1/24", "10.10.0.2/24"]
  wireguard_endpoint_base    = local.hostname_base
  wireguard_exposed_subnets  = ["10.20.0.0/16"]
}

variable "wiresteward_server_peers" {
  type = list(object({
    private_ip_address = string
    public_ip_address  = string
    mac_addresses      = list(string)
  }))

  default = [
    {
      private_ip_address = "10.0.0.2"
      public_ip_address  = "85.0.0.2"
      mac_addresses      = ["aa:aa:aa:aa:aa:aa", ""aa:aa:aa:aa:aa:ab"]
    },
    {
      private_ip_address = "10.0.0.3"
      public_ip_address  = "85.0.0.3"
      mac_addresses      = ["bb:bb:bb:bb:bb:bb", "bb:bb:bb:bb:bb:bc"]
    },
  ]
}

module "wiresteward" {
  source = "github.com/utilitywarehouse/wiresteward//terraform/matchbox?ref=master"

  matchbox_http_endpoint          = "https://matchbox.example.com"
  ignition_files                  = module.wiresteward_ignition.ignition_files
  ignition_systemd                = module.wiresteward_ignition.ignition_systemd
  wireguard_endpoints             = module.wiresteward_ignition.endpoints
  private_vlan_id                 = "100"
  private_vlan_gw                 = "10.0.0.1"
  public_vlan_id                  = "200"
  public_vlan_gw                  = "85.0.0.1"
  wireguard_cidrs                 = ["10.10.0.1/24", "10.10.0.2/24"]
  wireguard_exposed_subnets       = ["10.20.0.0/16"]
  wiresteward_server_peers        = var.wiresteward_server_peers
  ssh_address_range               = "10.0.0.0/8"
  metrics_subnet_cidr             = "10.0.0.0/8"
}
```
