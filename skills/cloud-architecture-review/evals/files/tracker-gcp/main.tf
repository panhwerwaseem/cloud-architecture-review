# Issue tracker on Google Cloud. Eval fixture: the weaknesses are planted.
# Every password-like value in this folder is a made-up placeholder.

provider "google" {
  project = var.project
  region  = "europe-west1"
}

variable "project" {
  type = string
}

variable "node_count" {
  type    = number
  default = 3
}

resource "google_compute_network" "main" {
  name                    = "tracker"
  auto_create_subnetworks = false
}

resource "google_sql_database_instance" "tracker" {
  name                = "tracker-db"
  database_version    = "POSTGRES_15"
  region              = "europe-west1"
  deletion_protection = false
  root_password       = "example-only-not-a-real-password"

  settings {
    tier              = "db-custom-2-7680"
    availability_type = "ZONAL"

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "anywhere"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_redis_instance" "cache" {
  name           = "tracker-cache"
  memory_size_gb = 1
}

resource "google_storage_bucket" "attachments" {
  name     = "tracker-attachments-example"
  location = "EU"
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.attachments.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "web" {
  name          = "tracker-web"
  network       = google_compute_network.main.name
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "ssh" {
  name          = "tracker-ssh"
  network       = google_compute_network.main.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "debug" {
  name          = "tracker-debug"
  network       = google_compute_network.main.name
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}

resource "google_compute_instance" "mailer" {
  name         = "tracker-mailer"
  machine_type = "e2-medium"
  zone         = "europe-west1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = google_compute_network.main.name
  }
}

resource "google_service_account" "api" {
  account_id = "tracker-api"
}

resource "google_container_cluster" "tracker" {
  name               = "tracker"
  location           = "europe-west1"
  initial_node_count = var.node_count
}
