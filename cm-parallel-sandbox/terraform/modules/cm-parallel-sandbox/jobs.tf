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
# Cloud Run jobs sharing one image, each bound to its own stage SA and
# dedicated results bucket.
# deploy.sh owns the image and run.py owns per-run parallelism, so Terraform
# ignores drift on both.
# ==============================================================================

resource "google_cloud_run_v2_job" "stage" {
  for_each            = local.stages
  project             = var.project_id
  location            = var.region
  name                = each.value.job_name
  launch_stage        = "GA"
  deletion_protection = false

  template {
    template {
      service_account       = google_service_account.stage[each.key].email
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
      max_retries           = var.max_retries
      timeout               = var.task_timeout

      vpc_access {
        egress = "ALL_TRAFFIC"
        network_interfaces {
          network    = google_compute_network.vpc.id
          subnetwork = google_compute_subnetwork.subnet.id
        }
      }

      containers {
        # Dynamically point to the built Artifact Registry image
        image = local.runner_image
        resources {
          limits = {
            cpu    = var.task_cpu
            memory = var.task_memory
          }
        }

        env {
          name  = "OPERATION"
          value = each.key
        }

        dynamic "env" {
          for_each = local.job_env
          content {
            name  = env.key
            value = env.value
          }
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].template[0].containers[0].image,
      template[0].parallelism,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_storage_bucket_iam_member.stage_payload_viewer,
    google_storage_bucket_iam_member.stage_results_creator,
    google_storage_bucket_iam_member.stage_reads,
  ]
}
