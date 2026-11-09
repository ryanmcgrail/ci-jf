# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ==============================================================================
# Isolated network: no default route, no Cloud Router/NAT. The only egress path
# is the private.googleapis.com VIP (199.36.153.8/30), enforced by both routing
# and firewall rules.
# ==============================================================================

resource "google_compute_network" "vpc" {
  project                         = var.project_id
  name                            = "${var.name_prefix}-vpc"
  auto_create_subnetworks         = false
  delete_default_routes_on_create = true

  depends_on = [google_project_service.required]
}

resource "google_compute_subnetwork" "subnet" {
  project                  = var.project_id
  name                     = "${var.name_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_route" "private_googleapis" {
  project          = var.project_id
  name             = "${var.name_prefix}-route-private-googleapis"
  network          = google_compute_network.vpc.id
  dest_range       = "199.36.153.8/30"
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
}

# ------------------------------------------------------------------------------
# Private DNS: resolve every *.googleapis.com name to the private VIP.
# ------------------------------------------------------------------------------

resource "google_dns_managed_zone" "googleapis" {
  project     = var.project_id
  name        = "${var.name_prefix}-googleapis"
  dns_name    = "googleapis.com."
  description = "Maps *.googleapis.com to private.googleapis.com for ${var.name_prefix}-vpc."
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_dns_record_set" "googleapis_cname" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["private.googleapis.com."]
}

resource "google_dns_record_set" "private_googleapis_a" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "private.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
}

# ------------------------------------------------------------------------------
# Egress firewall allowlist plus deny-all.
# ------------------------------------------------------------------------------

resource "google_compute_firewall" "allow_private_googleapis_egress" {
  project            = var.project_id
  name               = "${var.name_prefix}-allow-private-googleapis-egress"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["199.36.153.8/30"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "allow_metadata_egress" {
  project            = var.project_id
  name               = "${var.name_prefix}-allow-metadata-egress"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["169.254.169.254/32"]

  allow {
    protocol = "tcp"
    ports    = ["53", "80"]
  }

  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  project            = var.project_id
  name               = "${var.name_prefix}-deny-all-egress"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}
