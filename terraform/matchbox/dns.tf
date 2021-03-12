data "ignition_file" "resolved_conf" {
  filesystem = "root"
  path       = "/etc/systemd/resolved.conf"
  mode       = 420

  content {
    content = <<-EOF
[Resolve]
DNS=${join(" ", var.dns_nameservers)}
EOF
  }
}
