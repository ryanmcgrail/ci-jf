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

output "payload_bucket" {
  description = "Bucket for task payload uploads."
  value       = module.sandbox.payload_bucket
}

output "find_results_bucket" {
  description = "Bucket for find stage results."
  value       = module.sandbox.find_results_bucket
}

output "verify_results_bucket" {
  description = "Bucket for verify stage results."
  value       = module.sandbox.verify_results_bucket
}

output "fix_results_bucket" {
  description = "Bucket for fix stage results."
  value       = module.sandbox.fix_results_bucket
}

output "artifact_registry_repo" {
  description = "Artifact Registry Docker repository path."
  value       = module.sandbox.artifact_registry_repo
}

output "stage_jobs" {
  description = "Cloud Run job names for find, verify, and fix."
  value       = module.sandbox.stage_jobs
}
