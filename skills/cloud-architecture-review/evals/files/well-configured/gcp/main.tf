# Clean fixture: this folder must produce no finding.

resource "google_compute_network" "main" {
  name                    = "tracker"
  auto_create_subnetworks = false
}

resource "google_sql_database_instance" "tracker" {
  name             = "tracker-db"
  database_version = "POSTGRES_15"
  region           = "europe-west1"

  settings {
    tier              = "db-custom-2-7680"
    availability_type = "REGIONAL"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }
  }
}

resource "google_redis_instance" "cache" {
  name           = "tracker-cache"
  tier           = "STANDARD_HA"
  memory_size_gb = 1
}

resource "google_storage_bucket" "attachments" {
  name     = "tracker-attachments-example"
  location = "EU"
}

resource "google_service_account" "api" {
  account_id = "tracker-api"
}

resource "google_storage_bucket_iam_member" "api_read" {
  bucket = google_storage_bucket.attachments.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.api.email}"
}

resource "google_compute_firewall" "web" {
  name          = "tracker-web"
  network       = google_compute_network.main.name
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "ssh_from_office" {
  name          = "tracker-ssh-office"
  network       = google_compute_network.main.name
  source_ranges = ["203.0.113.0/24"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_instance_template" "worker" {
  name_prefix  = "tracker-worker-"
  machine_type = "e2-medium"

  disk {
    source_image = "debian-cloud/debian-12"
  }

  network_interface {
    network = google_compute_network.main.name
  }
}

resource "google_compute_region_instance_group_manager" "workers" {
  name               = "tracker-workers"
  region             = "europe-west1"
  base_instance_name = "tracker-worker"
  target_size        = 3

  version {
    instance_template = google_compute_instance_template.worker.id
  }
}

resource "google_monitoring_alert_policy" "db_cpu" {
  display_name = "tracker db cpu"
  combiner     = "OR"

  conditions {
    display_name = "cpu above 80 percent"

    condition_threshold {
      filter          = "metric.type=\"cloudsql.googleapis.com/database/cpu/utilization\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8
      duration        = "300s"
    }
  }
}
