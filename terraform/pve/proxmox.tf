provider "proxmox" {
  pm_tls_insecure = true
  pm_api_url      = var.proxmox_api_url
}
