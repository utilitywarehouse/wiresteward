# wiresteward
data "ignition_file" "wiresteward_config" {
  count      = local.instance_count
  filesystem = "root"
  path       = "/etc/wiresteward/config.json"
  mode       = 256

  content {
    content = templatefile("${path.module}/resources/wiresteward-config.json.tmpl", {
      wireguard_cidr            = var.wireguard_cidrs[count.index]
      wireguard_endpoint        = local.wireguard_endpoints[count.index]
      wireguard_exposed_subnets = var.wireguard_exposed_subnets
      oauth2_introspect_url     = var.oauth2_introspect_url
      oauth2_client_id          = var.oauth2_client_id
    })
  }
}

data "ignition_systemd_unit" "wiresteward_service" {
  name = "wiresteward.service"

  content = templatefile("${path.module}/resources/wiresteward.service.tmpl", {
    wiresteward_version = var.wiresteward_version
  })
}

# traefik
data "ignition_file" "traefik_config" {
  count      = local.instance_count
  filesystem = "root"
  path       = "/etc/traefik/wiresteward-proxy.toml"
  mode       = 256

  content {
    content = templatefile("${path.module}/resources/wiresteward-proxy.toml.tmpl", {
      wireguard_endpoint = local.wireguard_endpoints[count.index]
    })
  }
}

data "ignition_systemd_unit" "traefik" {
  name = "traefik.service"

  content = templatefile("${path.module}/resources/traefik.service.tmpl", {
    traefik_image = var.traefik_image
  })
}


data "ignition_config" "wiresteward" {
  count = local.instance_count

  files = concat([
    data.ignition_file.traefik_config[count.index].rendered,
    data.ignition_file.wiresteward_config[count.index].rendered,
  ], var.additional_ignition_files)

  systemd = concat([
    data.ignition_systemd_unit.traefik.rendered,
    data.ignition_systemd_unit.wiresteward_service.rendered,
  ], var.additional_systemd_units)
}
