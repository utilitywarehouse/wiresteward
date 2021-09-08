data "google_compute_zones" "available" {}

resource "random_string" "instance_name_suffix" {
  count   = local.instance_count
  length  = 4
  special = false
  upper   = false

  keepers = {
    userdata = var.ignition[count.index]
  }
}

resource "google_compute_instance" "wiresteward" {
  count                     = local.instance_count
  name                      = "${local.name}-${count.index}-${random_string.instance_name_suffix.*.result[count.index]}"
  machine_type              = "e2-micro"
  can_ip_forward            = true
  zone                      = data.google_compute_zones.available.names[count.index]
  allow_stopping_for_update = true

  tags = [local.name]

  boot_disk {
    initialize_params {
      image = var.container_linux_image
    }
  }

  lifecycle {
    ignore_changes = [boot_disk.0.initialize_params.0.image]
  }

  network_interface {
    subnetwork = var.subnet_link

    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    user-data = var.ignition[count.index]
  }
}

resource "google_compute_instance_group" "wiresteward" {
  count = local.instance_count
  name  = "${local.name}-${count.index}"

  instances = [
    google_compute_instance.wiresteward.*.self_link[count.index],
  ]

  zone = data.google_compute_zones.available.names[count.index]
}

resource "google_dns_record_set" "wiresteward" {
  count = local.instance_count
  name  = "${local.wireguard_endpoint[count.index]}."
  type  = "A"
  ttl   = 30 # TODO increase the value once happy with setup

  managed_zone = var.dns_zone

  # ephemeral ips could change via manual operations on the instance and leave this not updated
  rrdatas = [google_compute_instance.wiresteward[count.index].network_interface.0.access_config.0.nat_ip]
}

resource "google_compute_firewall" "wiresteward-udp" {
  name      = "${local.name}-udp"
  network   = var.vpc_link
  direction = "INGRESS"
  allow {
    protocol = "udp"
    ports    = ["51820"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.name]
}

resource "google_compute_firewall" "wiresteward-tcp" {
  name      = "${local.name}-tcp"
  network   = var.vpc_link
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.name]
}

resource "google_compute_firewall" "wiresteward-ssh" {
  name    = "${local.name}-ssh"
  network = var.vpc_link

  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = [local.name]
  target_tags = [local.name]
}
