// Firewall via iptables
data "ignition_systemd_unit" "iptables-rule-load" {
  name = "iptables-rule-load.service"

  content = <<EOS
[Unit]
Description=Loads presaved iptables rules from /var/lib/iptables/rules-save
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /var/lib/iptables/rules-save
[Install]
WantedBy=multi-user.target
EOS

}

data "ignition_file" "iptables_rules" {
  count = length(var.wiresteward_server_peers)

  filesystem = "root"
  path       = "/var/lib/iptables/rules-save"
  mode       = 420

  content {
    content = <<EOS
*filter
# Default Policies: Drop all incoming and forward attempts, allow outgoing
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
# Allow eveything on localhost
-A INPUT -i lo -j ACCEPT
# Allow all connections initiated by the host
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# Allow ssh from jumpbox
-A INPUT -p tcp -m tcp -s "${var.ssh_address_range}" --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
# Allow nodes subnet to talk to node exporter
-A INPUT -p tcp -m tcp -s "${var.metrics_subnet_cidr}" --dport 9100 -j ACCEPT
# Allow scraping wiresteward metrics port
-A INPUT -p tcp -m tcp -s "${var.metrics_subnet_cidr}" --dport "${var.wiresteward_metrics_port}" -j ACCEPT
# Allow all to traefik ports 80 and 443
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
# Allow udp traffic to wireguard
-A INPUT -p udp -m udp -d "${var.wiresteward_server_peers[count.index].public_ip_address}/32" --dport 51820 -j ACCEPT
# Allow forwarding traffic on wg subnets
-A FORWARD -s "${var.wiresteward_server_peers[count.index].wireguard_cidr}" -j ACCEPT
-A FORWARD -s "${join(", ", var.wireguard_exposed_subnets)}" -j ACCEPT
# Allow incoming ICMP for echo replies, unreachable destination messages, and time exceeded
-A INPUT -p icmp -m icmp -s 10.0.0.0/8 --icmp-type 0 -j ACCEPT
-A INPUT -p icmp -m icmp -s 10.0.0.0/8 --icmp-type 3 -j ACCEPT
-A INPUT -p icmp -m icmp -s 10.0.0.0/8 --icmp-type 8 -j ACCEPT
-A INPUT -p icmp -m icmp -s 10.0.0.0/8 --icmp-type 11 -j ACCEPT
COMMIT
EOS
  }
}
