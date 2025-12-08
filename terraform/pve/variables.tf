variable "role" {
  type        = string
  description = "role to be used when naming matchbox profiles and groups"
  default     = "wiresteward"
}

variable "flatcar_kernel_address" {
  type        = string
  description = "Location of the http endpoint that serves the kernel vmlinuz file"
}

variable "flatcar_initrd_addresses" {
  type        = list(string)
  description = "List of http endpoint locations the serve the flatcar initrd assets"
}

variable "proxmox_api_url" {
  description = "ProxMox Api Endpoint location"
}

variable "ignition_files" {
  type        = list(list(string))
  description = "The ignition files configuration for the wiresteward instances. Output of the ignition module."
}

variable "ignition_systemd" {
  type        = list(list(string))
  description = "The ignition systemd configuration for the wiresteward instances. Output of the ignition module."
}

variable "matchbox_http_endpoint" {
  description = "http endpoint of matchbox server"
}

variable "private_vlan_gw" {
  description = "Gateway ip for the public vlan"
}

variable "public_vlan_id" {
  description = "Vlan id of the wireguard instances' public network interfaces"
}

variable "public_vlan_gw" {
  description = "Gateway ip for the public vlan"
}

variable "wireguard_endpoints" {
  type        = list(string)
  description = "A list of wireguard endpoints for the instances. Output of the ignition module."
}

variable "wireguard_exposed_subnets" {
  type        = list(string)
  description = "The subnets that are exposed to wireguard peers in CIDR notation. Needed to allow packet forwarding on iptables"
}

variable "wiresteward_server_peers" {
  type = list(object({
    private_ip_address = string
    public_ip_address  = string
    wireguard_cidr     = string
    mac_address        = string
    pve_host           = string
  }))
  description = "The list of the wiresteweard server peers to create."
}

variable "ssh_address_range" {
  description = "cidr to accept ssh connections from"
}

variable "metrics_subnet_cidr" {
  description = "cidr to accept connections for node exporter"
}

variable "wiresteward_metrics_port" {
  description = "Port to scrape wiresteward metrics"
  default     = "8081"
}

variable "dns_nameservers" {
  type        = list(string)
  description = "A list of DNS servers"
  default = [
    "1.1.1.1",
    "1.0.0.1",
  ]
}
