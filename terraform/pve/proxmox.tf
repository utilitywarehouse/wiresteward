provider "proxmox" {
  # Credentials expected via PROXMOX_VE_USERNAME/PROXMOX_VE_PASSWORD or PROXMOX_VE_API_TOKEN.
  endpoint = var.proxmox_api_url
  insecure = true
}
