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

data "google_project" "this" {
  project_id = var.project_id
}

data "google_client_openid_userinfo" "me" {
  count = var.operators == null ? 1 : 0
}

locals {
  # Auto-detect applying operator identity if var.operators is null.
  detected_operator = one(data.google_client_openid_userinfo.me[*].email) == null ? [] : [
    endswith(one(data.google_client_openid_userinfo.me[*].email), ".gserviceaccount.com")
    ? "serviceAccount:${one(data.google_client_openid_userinfo.me[*].email)}"
    : "user:${one(data.google_client_openid_userinfo.me[*].email)}"
  ]
  operators = var.operators == null ? local.detected_operator : var.operators

  cloud_build_sa_email = coalesce(var.cloud_build_sa_email, "${data.google_project.this.number}-compute@developer.gserviceaccount.com")

  # --- DYNAMIC RUNNER IMAGE (Replaces placeholder_image) ---
  runner_image = "${google_artifact_registry_repository.runner.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runner.name}/cm-runner:latest"

  job_env = {
    PROJECT_ID                                         = var.project_id
    PAYLOAD_BUCKET                                     = google_storage_bucket.payload.name
    FIND_RESULTS_BUCKET                                = google_storage_bucket.results["find"].name
    VERIFY_RESULTS_BUCKET                              = google_storage_bucket.results["verify"].name
    FIX_RESULTS_BUCKET                                 = google_storage_bucket.results["fix"].name
    CLOUDSDK_STORAGE_PARALLEL_COMPOSITE_UPLOAD_ENABLED = "False"
  }

  # Ordered pipeline. Stage N reads payload + results of prior stages,
  # and writes to its own results bucket.
  #
  # Resource names are an explicit contract with cmrun/common.py:
  # - FIND_JOB = "cm-find-runner", VERIFY_JOB = "cm-verify-runner", FIX_JOB = "cm-fix-runner"
  # - Bucket naming: {project}-cm-{payload,find-results,verify-results,fix-results}
  stage_order = ["find", "verify", "fix"]

  stages = {
    for i, name in local.stage_order : name => {
      reads_results  = slice(local.stage_order, 0, i)
      job_name       = "cm-${name}-runner"
      sa_account_id  = "cm-${name}-sa"
      display_name   = "cm-parallel-sandbox ${name} stage"
      results_bucket = "${var.project_id}-cm-${name}-results"
    }
  }

  # Cross-stage read grants derived from stage_order:
  # {"verify:find" => ..., "fix:find" => ..., "fix:verify" => ...}
  stage_reads = merge([
    for name, s in local.stages : {
      for src in s.reads_results : "${name}:${src}" => {
        stage  = name
        source = src
      }
    }
  ]...)

  stage_project_roles = merge([
    for name, _ in local.stages : {
      for role in ["roles/aiplatform.user", "roles/logging.logWriter"] :
      "${name}:${role}" => {
        stage = name
        role  = role
      }
    }
  ]...)

  operator_stages = merge([
    for m in local.operators : {
      for name, _ in local.stages : "${name}:${m}" => {
        stage  = name
        member = m
      }
    }
  ]...)
}
