terraform {
  required_providers {
    ignition = {
      source = "community-terraform-providers/ignition"
    }
    matchbox = {
      source = "poseidon/matchbox"
    }
    proxmox = {
      source = "bpg/proxmox"
    }
  }
}
