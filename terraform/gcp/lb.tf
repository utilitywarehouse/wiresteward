resource "google_compute_managed_ssl_certificate" "wiresteward" {
  provider = google-beta
  name     = "${local.name}-cert"

  managed {
    domains = [var.wiresteward_endpoint]
  }
}

resource "google_compute_target_https_proxy" "wiresteward" {
  name             = local.name
  url_map          = google_compute_url_map.wiresteward.id
  ssl_certificates = [google_compute_managed_ssl_certificate.wiresteward.id]
}

resource "google_compute_url_map" "wiresteward" {
  name            = local.name
  default_service = google_compute_backend_service.wiresteward.id

  host_rule {
    hosts        = [var.wiresteward_endpoint]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.wiresteward.id

    path_rule {
      paths   = ["/*"]
      service = google_compute_backend_service.wiresteward.id
    }
  }
}

resource "google_compute_backend_service" "wiresteward" {
  name        = local.name
  port_name   = "oauth2-http"
  protocol    = "HTTP"
  timeout_sec = 10

  health_checks = [google_compute_health_check.wiresteward-tcp.id]

  dynamic "backend" {
    for_each = [for b in google_compute_instance_group.wiresteward.*.self_link : b]
    content {
      group = backend.value
    }
  }
}

resource "google_compute_health_check" "wiresteward-tcp" {
  name               = "${local.name}-health-check"
  timeout_sec        = 1
  check_interval_sec = 1

  tcp_health_check {
    port = 4180
  }
}

resource "google_compute_global_forwarding_rule" "wiresteward" {
  name       = local.name
  target     = google_compute_target_https_proxy.wiresteward.id
  port_range = 443
}

resource "google_dns_record_set" "wiresteward_lb" {
  name         = var.wiresteward_endpoint
  type         = "A"
  ttl          = 30
  managed_zone = var.dns_zone
  rrdatas      = [google_compute_global_forwarding_rule.wiresteward.ip_address]
}
