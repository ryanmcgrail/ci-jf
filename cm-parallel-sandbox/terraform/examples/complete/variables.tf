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

variable "project_id" {
  type        = string
  description = "The GCP project ID to deploy the sandbox into."
}

variable "region" {
  type        = string
  description = "The GCP region for sandbox resources."
  default     = "us-central1"
}

variable "enable_apis" {
  type        = bool
  description = "Whether to enable required GCP service APIs. Set false when managed externally."
  default     = false
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the VPC, subnet, route, DNS zone, and firewall rule names."
  default     = "cm-test"
}

variable "subnet_cidr" {
  type        = string
  description = "CIDR range of the dedicated Direct VPC egress subnet."
  default     = "10.30.0.0/22"
}

variable "task_cpu" {
  type        = string
  description = "vCPU limit per Cloud Run task."
  default     = "4"
}

variable "task_memory" {
  type        = string
  description = "Memory limit per Cloud Run task."
  default     = "16Gi"
}

variable "task_timeout" {
  type        = string
  description = "Default Cloud Run task timeout in seconds."
  default     = "86400s"
}

variable "results_retention_days" {
  type        = number
  description = "Age in days after which objects in results buckets are deleted."
  default     = 30
}

variable "operators" {
  type        = list(string)
  description = "Explicit list of operator IAM principals. Required; supply via terraform.tfvars."
  # Example:
  # operators = ["user:alice@example.com", "group:team@example.com"]
}

variable "create_cloudbuild_bucket" {
  type        = bool
  description = "Whether to create the `<project_id>_cloudbuild` bucket. Set false if it already exists."
  default     = true
}
