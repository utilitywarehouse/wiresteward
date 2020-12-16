terraform {
  required_providers {
    ignition = {
      source = "terraform-providers/ignition"
    }
    matchbox = {
      source = "poseidon/matchbox"
    }
  }
  required_version = ">= 0.13"
}
