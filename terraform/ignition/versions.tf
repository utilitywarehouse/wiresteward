terraform {
  required_providers {
    ignition = {
      source  = "community-terraform-providers/ignition"
      version = "< 2.0.0"
    }
  }
  required_version = ">= 0.13"
}
