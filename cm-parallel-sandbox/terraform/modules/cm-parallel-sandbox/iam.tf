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
# Stage service accounts
# ==============================================================================

resource "google_service_account" "stage" {
  for_each     = local.stages
  project      = var.project_id
  account_id   = each.value.sa_account_id
  display_name = each.value.display_name

  depends_on = [google_project_service.required]
}

resource "google_project_iam_member" "stage_project" {
  for_each = local.stage_project_roles
  project  = var.project_id
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.stage[each.value.stage].email}"
}

# ------------------------------------------------------------------------------
# Data diode: read-only inputs, create-only outputs.
# ------------------------------------------------------------------------------

# Every stage can read the staged task payload repository tarballs and manifests.
resource "google_storage_bucket_iam_member" "stage_payload_viewer" {
  for_each = local.stages
  bucket   = google_storage_bucket.payload.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${google_service_account.stage[each.key].email}"
}

# Every stage can create (write-once) results in its dedicated results bucket.
resource "google_storage_bucket_iam_member" "stage_results_creator" {
  for_each = local.stages
  bucket   = google_storage_bucket.results[each.key].name
  role     = "roles/storage.objectCreator"
  member   = "serviceAccount:${google_service_account.stage[each.key].email}"
}

# Read-down: each stage may read every prior stage's results. Derived from
# local.stage_order, so the edge set cannot drift from the pipeline order.
resource "google_storage_bucket_iam_member" "stage_reads" {
  for_each = local.stage_reads
  bucket   = google_storage_bucket.results[each.value.source].name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${google_service_account.stage[each.value.stage].email}"
}

# ------------------------------------------------------------------------------
# Image pushes (repo-scoped) & Cloud Build Service Accounts.
# ------------------------------------------------------------------------------

locals {
  # Deduplicated set covering the configured SA, legacy Cloud Build SA, and Compute SA
  build_service_accounts = toset(compact([
    local.cloud_build_sa_email,
    "${data.google_project.this.number}@cloudbuild.gserviceaccount.com",
    "${data.google_project.this.number}-compute@developer.gserviceaccount.com"
  ]))
}

# Grant Artifact Registry write permissions
resource "google_artifact_registry_repository_iam_member" "cloud_build_writer" {
  for_each   = local.build_service_accounts
  project    = var.project_id
  location   = google_artifact_registry_repository.runner.location
  repository = google_artifact_registry_repository.runner.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${each.value}"

  depends_on = [google_project_service.required]
}

# The Cloud Build SA must read its uploaded source tarball from the default
# `<project>_cloudbuild` bucket to run `gcloud builds submit`.
resource "google_storage_bucket_iam_member" "cloud_build_source_viewer" {
  for_each = local.build_service_accounts
  bucket   = coalesce(one(google_storage_bucket.cloudbuild[*].name), "${var.project_id}_cloudbuild")
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${each.value}"

  depends_on = [google_project_service.required]
}

# Cloud Build writes build logs to Cloud Logging
resource "google_project_iam_member" "cloud_build_log_writer" {
  for_each = local.build_service_accounts
  project  = var.project_id
  role     = "roles/logging.logWriter"
  member   = "serviceAccount:${each.value}"

  depends_on = [google_project_service.required]
}

# Cloud Build builder execution role (required for the Compute SA to run builds)
resource "google_project_iam_member" "cloud_build_builder" {
  for_each = local.build_service_accounts
  project  = var.project_id
  role     = "roles/cloudbuild.builds.builder"
  member   = "serviceAccount:${each.value}"

  depends_on = [google_project_service.required]
}

# ------------------------------------------------------------------------------
# Operators: stage payloads and dispatch runs.
# ------------------------------------------------------------------------------

resource "google_project_iam_member" "operator_run_developer" {
  for_each = toset(local.operators)
  project  = var.project_id
  role     = "roles/run.developer"
  member   = each.value
}

resource "google_service_account_iam_member" "operator_sa_user" {
  for_each           = local.operator_stages
  service_account_id = google_service_account.stage[each.value.stage].name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value.member
}

resource "google_storage_bucket_iam_member" "operator_payload_admin" {
  for_each = toset(local.operators)
  bucket   = google_storage_bucket.payload.name
  role     = "roles/storage.objectAdmin"
  member   = each.value
}

resource "google_storage_bucket_iam_member" "operator_results_viewer" {
  for_each = local.operator_stages
  bucket   = google_storage_bucket.results[each.value.stage].name
  role     = "roles/storage.objectViewer"
  member   = each.value.member
}
