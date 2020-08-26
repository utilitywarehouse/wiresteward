variable "role_name" {
  type        = string
  default     = "wiresteward"
  description = "An identifier for the resources created by this module."
}

variable "dns_zone_id" {
  type        = string
  description = "The Route53 hosted zone ID in which records will be created"
}

variable "ignition" {
  type        = list(string)
  description = "The ignition configuration for the wiresteward instances. The length of this list determines the number of instances launched. Output of the ignition module."
}

variable "subnet_ids" {
  type        = list(string)
  description = "AWS VPC subnet IDs in which the wiresteward instances will be deployed"
}

variable "vpc_id" {
  type        = string
  description = "The id of the AWS VPC in which to deploy the wiresteward instance."
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
  instance_count = length(var.ignition)
  name           = "${var.role_name}"
}

output "public_ipv4_addresses" {
  value = [aws_eip.peer.*.public_ip]
}

output "private_ipv4_addresses" {
  value = [aws_eip.peer.*.private_ip]
}

output "security_group_id" {
  value = aws_security_group.wiresteward.id
}
