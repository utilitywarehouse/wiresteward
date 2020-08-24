module "ssh_key_agent" {
  source = "github.com/utilitywarehouse/tf_ssh_key_agent?ref=2.0.0"

  groups                = var.ssh_key_agent_groups
  ssh_key_agent_version = var.ssh_key_agent_version
  uri                   = var.ssh_key_agent_uri
}

data "ignition_systemd_unit" "sshd_service" {
  name    = "sshd.service"
  enabled = "true"
}

data "ignition_systemd_unit" "sshd_socket" {
  name = "sshd.socket"
  mask = "true"
}

data "ignition_file" "sshd_config" {
  filesystem = "root"
  path       = "/etc/ssh/sshd_config"
  mode       = 384

  content {
    content = file("${path.module}/resources/sshd_config")
  }
}

# wiresteward
data "ignition_file" "wiresteward_config" {
  count      = local.instance_count
  filesystem = "root"
  path       = "/etc/wiresteward/config.json"
  mode       = 256

  content {
    content = templatefile("${path.module}/resources/wiresteward-config.json.tmpl", {
      wireguard_cidr                 = var.wireguard_cidrs[count.index]
      wireguard_endpoint             = local.wireguard_endpoints[count.index]
      wireguard_exposed_subnets      = var.wireguard_exposed_subnets
      wiresteward_address_lease_time = var.wiresteward_address_lease_time
    })
  }
}

data "ignition_systemd_unit" "wiresteward_service" {
  name = "wiresteward.service"

  content = templatefile("${path.module}/resources/wiresteward.service.tmpl", {
    wiresteward_version = var.wiresteward_version
  })
}

# Oauth2-proxy
data "ignition_file" "oauth2_proxy_config" {
  filesystem = "root"
  path       = "/etc/oauth2-proxy/config.cfg"
  mode       = 420

  content {
    content = templatefile("${path.module}/resources/oauth2-proxy-config.cfg.tmpl", {
      oauth2_email_domain        = var.oauth2_email_domain
      oauth2_proxy_client_id     = var.oauth2_proxy_client_id
      oauth2_proxy_cookie_secret = var.oauth2_proxy_cookie_secret
      oauth2_proxy_issuer_url    = var.oauth2_proxy_issuer_url
    })
  }
}

data "ignition_systemd_unit" "oauth2_proxy_service" {
  name = "oauth2-proxy.service"

  content = templatefile("${path.module}/resources/oauth2-proxy.service.tmpl", {
    oauth2_proxy_version = var.oauth2_proxy_version
  })
}

data "ignition_config" "wiresteward" {
  count = local.instance_count

  files = [
    data.ignition_file.sshd_config.id,
    data.ignition_file.oauth2_proxy_config.id,
    data.ignition_file.wiresteward_config[count.index].id,
  ]

  systemd = [
    data.ignition_systemd_unit.oauth2_proxy_service.id,
    data.ignition_systemd_unit.sshd_service.id,
    data.ignition_systemd_unit.sshd_socket.id,
    data.ignition_systemd_unit.wiresteward_service.id,
    module.ssh_key_agent.id,
  ]
}
