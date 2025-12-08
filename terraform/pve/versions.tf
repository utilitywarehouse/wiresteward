terraform {
  required_providers {
    ignition = {
      source = "community-terraform-providers/ignition"
    }
    matchbox = {
      source = "poseidon/matchbox"
    }
    proxmox = {
      source  = "telmate/proxmox"
      version = "3.0.2-rc05"
    }
  }
}
