terraform {
  required_providers {
    ignition = {
      source  = "community-terraform-providers/ignition"
    }
    matchbox = {
      source = "poseidon/matchbox"
    }
  }
  required_version = ">= 0.13"
}
