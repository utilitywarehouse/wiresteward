variable "oauth2_proxy_client_id" {
  type        = string
  description = "The client id of the oauth application used by oauth2-proxy"
}

variable "oauth2_proxy_cookie_secret" {
  type        = string
  description = "A random value used for secure cookies"
}

variable "oauth2_proxy_issuer_url" {
  type        = string
  description = "The issuer URL for the oauth application"
}

variable "oauth2_proxy_version" {
  type        = string
  description = "Version of the oauth2-proxy image (see https://quay.io/oauth2-proxy/oauth2-proxy)"
  default     = "v6.0.0"
}

variable "ssh_key_agent_uri" {
  type        = string
  description = "URI from where to get the ssh-key-agent authmap"
}

variable "ssh_key_agent_version" {
  type        = string
  description = "The version of ssh-key-agent to deploy (see https://github.com/utilitywarehouse/ssh-key-agent/)"
  default     = "1.0.4"
}

variable "ssh_key_agent_groups" {
  type        = list(string)
  description = "A list of google groups that ssh-key-agent will pull SSH keys from"
}

variable "wireguard_cidrs" {
  type        = list(string)
  description = "The IP addresses and associated wireguard peer subnets in CIDR notation. The length of this list determines how many ignition configs will be generated"
}

variable "wireguard_endpoints" {
  type        = list(string)
  description = "The hostnames to which wireguard peers can connect. Should be of the same length as 'wireguard_cidrs'"
}

variable "wireguard_exposed_subnets" {
  type        = list(string)
  description = "The subnets that are exposed to wireguard peers in CIDR notation"
}

variable "wiresteward_address_lease_time" {
  type        = string
  description = "Lifetime of wiresteward address leases"
  default     = "12h"
}

variable "wiresteward_version" {
  type        = string
  description = "The version of wiresteward to deploy (see https://github.com/utilitywarehouse/wiresteward/)"
  default     = "latest"
}

locals {
  instance_count = length(var.wireguard_cidrs)
}

output "ignition" {
  value = data.ignition_config.wiresteward.*.rendered
}
