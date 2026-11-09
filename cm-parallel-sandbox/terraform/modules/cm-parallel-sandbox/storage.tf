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
# Stage-isolated buckets (one-way data diode) and the runner image repository.
# ==============================================================================

resource "google_storage_bucket" "payload" {
  project                     = var.project_id
  name                        = "${var.project_id}-cm-payload"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket" "results" {
  for_each                    = local.stages
  project                     = var.project_id
  name                        = each.value.results_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  dynamic "lifecycle_rule" {
    for_each = var.results_retention_days == null ? [] : [var.results_retention_days]
    content {
      condition {
        age = lifecycle_rule.value
      }
      action {
        type = "Delete"
      }
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_artifact_registry_repository" "runner" {
  project       = var.project_id
  location      = var.region
  repository_id = "cm-parallel-sandbox"
  description   = "Runner images for the cm-parallel-sandbox find, verify, and fix jobs."
  format        = "DOCKER"

  depends_on = [google_project_service.required]
}

# Default `gcloud builds submit` staging bucket. GCP creates it lazily on the
# first build, which is too late for the source-viewer grant in iam.tf.
resource "google_storage_bucket" "cloudbuild" {
  count                       = var.create_cloudbuild_bucket ? 1 : 0
  project                     = var.project_id
  name                        = "${var.project_id}_cloudbuild"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  depends_on = [google_project_service.required]
}
