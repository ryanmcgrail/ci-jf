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
# State migration: maps unrolled 3-stage resources to DRY stage maps.
# ==============================================================================

# Service Accounts
moved {
  from = google_service_account.find
  to   = google_service_account.stage["find"]
}

moved {
  from = google_service_account.verify
  to   = google_service_account.stage["verify"]
}

moved {
  from = google_service_account.fix
  to   = google_service_account.stage["fix"]
}

# Results Buckets
moved {
  from = google_storage_bucket.find_results
  to   = google_storage_bucket.results["find"]
}

moved {
  from = google_storage_bucket.verify_results
  to   = google_storage_bucket.results["verify"]
}

moved {
  from = google_storage_bucket.fix_results
  to   = google_storage_bucket.results["fix"]
}

# Cloud Run Jobs
moved {
  from = google_cloud_run_v2_job.find
  to   = google_cloud_run_v2_job.stage["find"]
}

moved {
  from = google_cloud_run_v2_job.verify
  to   = google_cloud_run_v2_job.stage["verify"]
}

moved {
  from = google_cloud_run_v2_job.fix
  to   = google_cloud_run_v2_job.stage["fix"]
}

# Project Roles
moved {
  from = google_project_iam_member.find_project["roles/aiplatform.user"]
  to   = google_project_iam_member.stage_project["find:roles/aiplatform.user"]
}

moved {
  from = google_project_iam_member.find_project["roles/logging.logWriter"]
  to   = google_project_iam_member.stage_project["find:roles/logging.logWriter"]
}

moved {
  from = google_project_iam_member.verify_project["roles/aiplatform.user"]
  to   = google_project_iam_member.stage_project["verify:roles/aiplatform.user"]
}

moved {
  from = google_project_iam_member.verify_project["roles/logging.logWriter"]
  to   = google_project_iam_member.stage_project["verify:roles/logging.logWriter"]
}

moved {
  from = google_project_iam_member.fix_project["roles/aiplatform.user"]
  to   = google_project_iam_member.stage_project["fix:roles/aiplatform.user"]
}

moved {
  from = google_project_iam_member.fix_project["roles/logging.logWriter"]
  to   = google_project_iam_member.stage_project["fix:roles/logging.logWriter"]
}

# Payload Viewers
moved {
  from = google_storage_bucket_iam_member.find_payload_viewer
  to   = google_storage_bucket_iam_member.stage_payload_viewer["find"]
}

moved {
  from = google_storage_bucket_iam_member.verify_payload_viewer
  to   = google_storage_bucket_iam_member.stage_payload_viewer["verify"]
}

moved {
  from = google_storage_bucket_iam_member.fix_payload_viewer
  to   = google_storage_bucket_iam_member.stage_payload_viewer["fix"]
}

# Results Creators
moved {
  from = google_storage_bucket_iam_member.find_results_creator
  to   = google_storage_bucket_iam_member.stage_results_creator["find"]
}

moved {
  from = google_storage_bucket_iam_member.verify_results_creator
  to   = google_storage_bucket_iam_member.stage_results_creator["verify"]
}

moved {
  from = google_storage_bucket_iam_member.fix_results_creator
  to   = google_storage_bucket_iam_member.stage_results_creator["fix"]
}

# Cross-Stage Read Grants
moved {
  from = google_storage_bucket_iam_member.verify_find_results_viewer
  to   = google_storage_bucket_iam_member.stage_reads["verify:find"]
}

moved {
  from = google_storage_bucket_iam_member.fix_find_results_viewer
  to   = google_storage_bucket_iam_member.stage_reads["fix:find"]
}

moved {
  from = google_storage_bucket_iam_member.fix_verify_results_viewer
  to   = google_storage_bucket_iam_member.stage_reads["fix:verify"]
}
