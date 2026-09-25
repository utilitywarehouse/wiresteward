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
    data.ignition_disk.devsda.rendered,
  ]

  filesystems = [
    data.ignition_filesystem.root_scsi0.rendered,
  ]

  systemd = concat(
    tolist([
      data.ignition_systemd_unit.iptables-rule-load.rendered,
    ]),
    var.ignition_systemd[count.index],
  )

  files = concat(
    tolist([
      data.ignition_file.eth0_private_network[count.index].rendered,
      data.ignition_file.eth1_public_network[count.index].rendered,
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
  ]
  raw_ignition = data.ignition_config.wiresteward[count.index].rendered
}

resource "matchbox_group" "wiresteward" {
  count = length(var.wiresteward_server_peers)
  name  = "${var.role}-${count.index}"

  profile = matchbox_profile.wiresteward[count.index].name

  selector = {
    mac = var.wiresteward_server_peers[count.index].private_iface_mac_address
  }

  metadata = {
    ignition_endpoint = "${var.matchbox_http_endpoint}/ignition"
  }
}

resource "proxmox_virtual_environment_vm" "wiresteward" {
  count         = length(var.wiresteward_server_peers)
  name          = "${var.role}-${count.index}"
  node_name     = var.wiresteward_server_peers[count.index].pve_host
  description   = "Wiresteward box"
  boot_order    = ["net0"]
  hotplug       = "network,disk,usb"
  on_boot       = true
  started       = true
  scsi_hardware = "virtio-scsi-pci"

  cpu {
    cores   = 2
    sockets = 1
    type    = "host" # inherited from telmate provider default value
  }

  memory {
    dedicated = 4096
  }

  disk {
    interface    = "scsi0"
    datastore_id = "local-lvm"
    size         = 20
    file_format  = "raw"
    cache        = "none"
    discard      = "ignore"
    iothread     = false
    replicate    = false
    backup       = true
  }

  network_device {
    bridge      = "vmbr0"
    mac_address = upper(var.wiresteward_server_peers[count.index].private_iface_mac_address)
    model       = "virtio"
    mtu         = 9000
    firewall    = false
  }

  network_device {
    bridge      = "vmbr0"
    mac_address = upper(var.wiresteward_server_peers[count.index].public_iface_mac_address)
    model       = "virtio"
    mtu         = 9000
    vlan_id     = var.public_vlan_id
    firewall    = false
  }
}

