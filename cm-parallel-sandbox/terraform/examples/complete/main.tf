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

provider "google" {
  project = var.project_id
  region  = var.region
}

module "sandbox" {
  source                   = "../../modules/cm-parallel-sandbox"
  project_id               = var.project_id
  region                   = var.region
  enable_apis              = var.enable_apis
  name_prefix              = var.name_prefix
  subnet_cidr              = var.subnet_cidr
  task_cpu                 = var.task_cpu
  task_memory              = var.task_memory
  task_timeout             = var.task_timeout
  max_retries              = 0
  results_retention_days   = var.results_retention_days
  operators                = var.operators
  create_cloudbuild_bucket = var.create_cloudbuild_bucket
}
