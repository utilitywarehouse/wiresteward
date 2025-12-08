# Every interface is attached to a VLAN via proxmox, so all we have to do here
# is assign statically a public IP address to the interface attached to our
# public VLAN. This is because there is no DHCP to manage IP addresses on
# the public VLAN
data "ignition_file" "eth1_public_network" {
  count     = length(var.wiresteward_server_peers)
  path      = "/etc/systemd/network/11-eth1.network"
  mode      = 420
  overwrite = true

  content {
    content = <<EOS
[Match]
Name=eth1

[Network]
DHCP=no

[Address]
Address=${var.wiresteward_server_peers[count.index].public_ip_address}/32
EOS
  }
}
