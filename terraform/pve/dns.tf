data "ignition_file" "resolved_conf" {
  path      = "/etc/systemd/resolved.conf"
  mode      = 420
  overwrite = true

  content {
    content = <<-EOF
[Resolve]
DNS=${join(" ", var.dns_nameservers)}
EOF
  }
}
