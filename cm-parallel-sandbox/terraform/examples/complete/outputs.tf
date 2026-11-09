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
  value = module.sandbox.network_name
}

output "subnet_name" {
  value = module.sandbox.subnet_name
}

output "payload_bucket" {
  value = module.sandbox.payload_bucket
}

output "find_results_bucket" {
  value = module.sandbox.find_results_bucket
}

output "verify_results_bucket" {
  value = module.sandbox.verify_results_bucket
}

output "fix_results_bucket" {
  value = module.sandbox.fix_results_bucket
}

output "artifact_registry_repo" {
  value = module.sandbox.artifact_registry_repo
}

output "stage_jobs" {
  value = module.sandbox.stage_jobs
}

output "stage_sas" {
  value = module.sandbox.stage_sas
}

output "stage_buckets" {
  value = module.sandbox.stage_buckets
}

output "operators" {
  value = module.sandbox.operators
}
