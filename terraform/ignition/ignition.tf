# wiresteward
data "ignition_file" "wiresteward_config" {
  count = local.instance_count
  path  = "/etc/wiresteward/config.json"
  mode  = 256

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

# s3fs for traefik certificate storage
data "ignition_systemd_unit" "s3fs" {
  count = local.instance_count
  name  = "s3fs.service"

  content = templatefile("${path.module}/resources/s3fs.service.tmpl", {
    s3fs_access_key    = var.s3fs_access_key,
    s3fs_access_secret = var.s3fs_access_secret,
    s3fs_bucket        = var.s3fs_bucket,
    s3fs_image         = var.s3fs_image,
    host_mount_point   = "/var/lib/traefik/ssl/",
    instance_count     = count.index
  })
}


# traefik
data "ignition_file" "traefik_config" {
  count = local.instance_count
  path  = "/etc/traefik/wiresteward-proxy.toml"
  mode  = 256

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

data "ignition_systemd_unit" "locksmithd" {
  count = local.instance_count

  name = "locksmithd.service"

  dropin {
    name = "10-custom-options.conf"
    # Daily update windows, with a 1h buffer to prevent overlaps
    # and give time to react to any problems.
    #   wiresteward-0: 10:00-11:00
    #   < 1h free >
    #   wiresteward-1: 12:00-13:00
    #   < 1h free >
    content = <<-EOF
[Service]
Environment=LOCKSMITHD_REBOOT_WINDOW_START=${formatdate("hh:mm", timeadd("0000-01-01T10:00:00Z", "${count.index * 2}h"))}
Environment=LOCKSMITHD_REBOOT_WINDOW_LENGTH=1h
EOF
  }
}

data "ignition_config" "wiresteward" {
  count = local.instance_count

  files = concat([
    data.ignition_file.traefik_config[count.index].rendered,
    data.ignition_file.wiresteward_config[count.index].rendered,
  ], var.additional_ignition_files)

  systemd = concat([
    data.ignition_systemd_unit.locksmithd[count.index].rendered,
    data.ignition_systemd_unit.s3fs[count.index].rendered,
    data.ignition_systemd_unit.traefik.rendered,
    data.ignition_systemd_unit.wiresteward_service.rendered,
  ], var.additional_systemd_units)
}
