variable "role_name" {
  default = "wiresteward"
}

variable "dns_zone_name" {}

variable "dns_zone_id" {}

variable "vpc_id" {
  description = "The id of the AWS VPC in which to deploy the wiresteward instance."
}

variable "subnet_ids" {
  type        = list(string)
  description = "AWS VPC subnet IDs in which the wiresteward instances will be deployed"
}

// The variables below are duplicated from the ignition module and are simply
// passed down internally.

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

variable "ssh_key_agent_uri" {
  type        = string
  description = "URI from where to get the ssh-key-agent authmap"
}

variable "ssh_key_agent_groups" {
  type        = list(string)
  description = "A list of google groups that ssh-key-agent will pull SSH keys from"
}

variable "wireguard_cidrs" {
  type        = list(string)
  description = "The IP addresses and associated wireguard peer subnets in CIDR notation. The length of this list determines how many ignition configs will be generated"
}

variable "wireguard_exposed_subnets" {
  type        = list(string)
  description = "The subnets that are exposed to wireguard peers in CIDR notation"
}

locals {
  instance_count = length(var.wireguard_cidrs)
  name           = "${var.role_name}"
}

output "public_ipv4_addresses" {
  value = [aws_eip.peer.*.public_ip]
}

output "security_group_id" {
  value = aws_security_group.wiresteward.id
}
