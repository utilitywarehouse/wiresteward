data "ignition_disk" "sda" {
  device     = "/dev/sda"
  wipe_table = true

  partition {
    label  = "ROOT"
    number = 1
  }
}

data "ignition_disk" "nvme" {
  device     = "/dev/nvme0n1"
  wipe_table = true

  partition {
    label  = "ROOT"
    number = 1
  }
}

data "ignition_filesystem" "root" {
  device          = "/dev/disk/by-partlabel/ROOT"
  format          = "ext4"
  wipe_filesystem = true
  label           = "ROOT"
}

data "ignition_file" "hostname" {
  count     = length(var.wiresteward_server_peers)
  path      = "/etc/hostname"
  mode      = 420
  overwrite = true

  content {
    content = <<EOS
${var.wireguard_endpoints[count.index]}
EOS
  }
}

data "ignition_config" "wiresteward" {
  count = length(var.wiresteward_server_peers)

  disks = [
    var.wiresteward_server_peers[count.index].disk_type == "nvme" ? data.ignition_disk.nvme.rendered : data.ignition_disk.sda.rendered,
  ]

  filesystems = [
    data.ignition_filesystem.root.rendered,
  ]

  systemd = concat(
    tolist([
      data.ignition_systemd_unit.iptables-rule-load.rendered,
    ]),
    var.ignition_systemd[count.index],
  )

  files = concat(
    tolist([
      data.ignition_file.bond_net_eno.rendered,
      data.ignition_file.bond_netdev.rendered,
      data.ignition_file.bond_public_vlan_netdev[count.index].rendered,
      data.ignition_file.bond0[count.index].rendered,
      data.ignition_file.bond0_public_vlan[count.index].rendered,
      data.ignition_file.hostname[count.index].rendered,
      data.ignition_file.iptables_rules[count.index].rendered,
      data.ignition_file.resolved_conf.rendered,
    ]),
    var.ignition_files[count.index],
  )
}

resource "matchbox_profile" "wiresteward" {
  count  = length(var.wiresteward_server_peers)
  name   = "${var.role}-${count.index}"
  kernel = var.flatcar_kernel_address
  initrd = var.flatcar_initrd_addresses
  args = [
    "initrd=flatcar_production_pxe_image.cpio.gz",
    "ignition.config.url=${var.matchbox_http_endpoint}/ignition?uuid=$${uuid}&mac=$${mac:hexhyp}",
    "flatcar.first_boot=yes",
    "root=LABEL=ROOT",
    "console=tty0",
    "console=ttyS0",
  ]

  raw_ignition = data.ignition_config.wiresteward[count.index].rendered
}

locals {
  groups = flatten([
    for index, _ in var.wiresteward_server_peers : [
      for _, mac_address in var.wiresteward_server_peers[index].mac_addresses : {
        mac     = mac_address
        profile = matchbox_profile.wiresteward[index]
      }
    ]
  ])
}

resource "matchbox_group" "wiresteward" {
  count = length(local.groups)
  name  = "${var.role}-${count.index}"

  profile = local.groups[count.index].profile.name

  selector = {
    mac = local.groups[count.index].mac
  }

  metadata = {
    ignition_endpoint = "${var.matchbox_http_endpoint}/ignition"
  }
}
