variable "role_name" {
  type        = string
  default     = "wiresteward"
  description = "An identifier for the resources created by this module."
}

variable "dns_zone" {
  type        = string
  description = "The GCP managed zone in which records will be created"
}

variable "ignition" {
  type        = list(string)
  description = "The ignition configuration for the wiresteward instances. The length of this list determines the number of instances launched. Output of the ignition module."
}

variable "subnet_link" {
  type        = string
  description = "GCP subnet link in which the wiresteward instances will be deployed"
}

variable "vpc_link" {
  type        = string
  description = "The link of the GCP VPC in which to deploy the wiresteward instance."
}

variable "wireguard_endpoints" {
  type        = list(string)
  description = "A list of wireguard endpoints for the instances. Output of the ignition module."
}

variable "wiresteward_endpoint" {
  type        = string
  description = "The endpoint for wiresteward where clients connect."
}

locals {
  instance_count       = length(var.ignition)
  name                 = var.role_name
  wiresteward_endpoint = trim(var.wiresteward_endpoint, ".")
  wireguard_endpoint   = [for e in var.wireguard_endpoints : trim(e, ".")]
}

output "public_ipv4_addresses" {
  value = google_compute_instance.wiresteward.*.network_interface.0.access_config.0.nat_ip
}

output "private_ipv4_addresses" {
  value = google_compute_instance.wiresteward.*.network_interface.0.network_ip
}

output "instances_target_tag" {
  value = local.name
}
