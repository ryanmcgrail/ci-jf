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

output "network_name" {
  description = "Name of the isolated VPC network."
  value       = google_compute_network.vpc.name
}

output "subnet_name" {
  description = "Name of the Direct VPC egress subnet."
  value       = google_compute_subnetwork.subnet.name
}

output "payload_bucket" {
  description = "Payload bucket (repo tarballs, cached cm binaries, task manifests)."
  value       = google_storage_bucket.payload.name
}

output "find_results_bucket" {
  description = "Create-only results bucket for the find stage."
  value       = google_storage_bucket.results["find"].name
}

output "verify_results_bucket" {
  description = "Create-only results bucket for the verify stage."
  value       = google_storage_bucket.results["verify"].name
}

output "fix_results_bucket" {
  description = "Create-only results bucket for the fix stage."
  value       = google_storage_bucket.results["fix"].name
}

output "artifact_registry_repo" {
  description = "Full Docker path of the runner image repository."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runner.repository_id}"
}

output "find_sa_email" {
  description = "Service account email of the find stage."
  value       = google_service_account.stage["find"].email
}

output "verify_sa_email" {
  description = "Service account email of the verify stage."
  value       = google_service_account.stage["verify"].email
}

output "fix_sa_email" {
  description = "Service account email of the fix stage."
  value       = google_service_account.stage["fix"].email
}

output "find_job_name" {
  description = "Cloud Run job name of the find stage."
  value       = google_cloud_run_v2_job.stage["find"].name
}

output "verify_job_name" {
  description = "Cloud Run job name of the verify stage."
  value       = google_cloud_run_v2_job.stage["verify"].name
}

output "fix_job_name" {
  description = "Cloud Run job name of the fix stage."
  value       = google_cloud_run_v2_job.stage["fix"].name
}

output "stage_jobs" {
  description = "Map of pipeline stage name to Cloud Run job name."
  value       = { for k, j in google_cloud_run_v2_job.stage : k => j.name }
}

output "stage_sas" {
  description = "Map of pipeline stage name to service account email."
  value       = { for k, s in google_service_account.stage : k => s.email }
}

output "stage_buckets" {
  description = "Map of pipeline stage name to dedicated results bucket name."
  value       = { for k, b in google_storage_bucket.results : k => b.name }
}

output "operators" {
  description = "Effective list of operator IAM principals granted access to dispatch runs."
  value       = local.operators
}
