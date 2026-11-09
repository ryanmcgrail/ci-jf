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
  description = "The GCP project ID where the cm-parallel-sandbox infrastructure is created."
}

variable "region" {
  type        = string
  description = "The GCP region for the subnet, buckets, Artifact Registry repository, and Cloud Run jobs."
  default     = "us-central1"
}

variable "enable_apis" {
  type        = bool
  description = "Whether to enable required GCP service APIs. Set to false if APIs are managed externally."
  default     = true
}

variable "required_services" {
  type        = list(string)
  description = "List of GCP API services enabled when enable_apis is true."
  default = [
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
  ]
}

variable "name_prefix" {
  type        = string
  description = "Prefix for the VPC, subnet, route, DNS zone, and firewall rule names."
  default     = "cm-run"
}

variable "subnet_cidr" {
  type        = string
  description = "CIDR range of the dedicated Direct VPC egress subnet (a /22 supports approximately 500 concurrent tasks)."
  default     = "10.20.0.0/22"
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
  description = "Default Cloud Run task timeout in seconds (default: 48h / 172800s)."
  default     = "172800s"
}

variable "max_retries" {
  type        = number
  description = "Max retries per task. Must stay 0 so create-only (objectCreator) result writes never need to overwrite."
  default     = 0
}

variable "results_retention_days" {
  type        = number
  description = "Optional age in days after which objects in the results buckets are deleted. null disables the lifecycle rule."
  default     = null
}

variable "operators" {
  type        = list(string)
  description = "IAM principals that stage payloads and dispatch runs (run.developer, serviceAccountUser on stage SAs, objectAdmin on payload, objectViewer on results). If null, defaults to the caller identity running Terraform. Set to [] to grant no operators."
  default     = null
}

variable "cloud_build_sa_email" {
  type        = string
  description = "Service account used by Cloud Build to push runner images. null resolves to the Compute Engine default SA (<project_number>-compute@developer.gserviceaccount.com)."
  default     = null
}

variable "create_cloudbuild_bucket" {
  type        = bool
  description = "Whether to create the default `<project_id>_cloudbuild` source bucket. GCP only creates it on the first `gcloud builds submit`, so fresh projects need it created before the Cloud Build SA can be granted read access. Set to false when the bucket already exists."
  default     = true
}
