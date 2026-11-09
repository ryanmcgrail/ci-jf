# cm-parallel-sandbox Terraform Module

## Overview

Provisions an isolated GCP environment for running CodeMender `find`, `verify`, and `fix` pipeline stages on Cloud Run. It configures a dedicated VPC with private Google API egress, stage-isolated Cloud Storage buckets enforcing a one-way data diode, per-stage service accounts, and Cloud Run jobs.

## Prerequisites

- Terraform >= 1.5.0
- Google Cloud provider >= 5.0, ~> 6.0
- GCP project with billing enabled
- GCP IAM role `roles/owner` or `roles/resourcemanager.projectIamAdmin` + `roles/editor` on the target project

## Usage

```hcl
module "cm_parallel_sandbox" {
  source     = "./modules/cm-parallel-sandbox"
  project_id = "your-gcp-project-id"
}
```

To integrate into an existing configuration that already enables GCP APIs externally:

```hcl
module "cm_parallel_sandbox" {
  source      = "./modules/cm-parallel-sandbox"
  project_id  = "your-gcp-project-id"
  enable_apis = false
  operators   = ["user:developer@example.com"]
}
```

## Configuration

### Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| `project_id` | `string` | **required** | The GCP project ID where sandbox resources are created. |
| `region` | `string` | `"us-central1"` | GCP region for subnet, buckets, Artifact Registry, and Cloud Run jobs. |
| `enable_apis` | `bool` | `true` | Whether to automatically enable required GCP APIs. Set `false` if APIs are managed outside this module. |
| `required_services` | `list(string)` | *(see `variables.tf`)* | List of GCP APIs enabled when `enable_apis = true`. |
| `name_prefix` | `string` | `"cm-run"` | Prefix for VPC, subnet, route, DNS zone, and firewall rule names. |
| `subnet_cidr` | `string` | `"10.20.0.0/22"` | CIDR range for the Direct VPC egress subnet. Supports ~500 concurrent tasks. |
| `task_cpu` | `string` | `"4"` | vCPU limit per Cloud Run task. |
| `task_memory` | `string` | `"16Gi"` | Memory limit per Cloud Run task. |
| `task_timeout` | `string` | `"172800s"` | Cloud Run task timeout (48 hours). |
| `max_retries` | `number` | `0` | Task retries. Must stay `0` to prevent overwriting write-once results. |
| `results_retention_days` | `number` | `null` | Lifecycle deletion age in days for results buckets. `null` disables lifecycle deletion. |
| `operators` | `list(string)` | `null` | IAM principals granted run dispatch and bucket access. If `null`, auto-detects caller identity running Terraform. Pass `[]` for none. |
| `cloud_build_sa_email` | `string` | `null` | Service account used by Cloud Build to push runner images. `null` resolves to `<project_number>-compute@developer.gserviceaccount.com`. |
| `create_cloudbuild_bucket` | `bool` | `true` | Creates the `<project_id>_cloudbuild` bucket that `gcloud builds submit` stages source in. GCP only creates it on the first build. Set to `false` when the bucket already exists. |

### Outputs

| Name | Type | Description |
|---|---|---|
| `network_name` | `string` | Name of the isolated VPC network. |
| `subnet_name` | `string` | Name of the Direct VPC egress subnet. |
| `payload_bucket` | `string` | Name of the payload bucket. |
| `find_results_bucket` | `string` | Name of the find stage results bucket. |
| `verify_results_bucket` | `string` | Name of the verify stage results bucket. |
| `fix_results_bucket` | `string` | Name of the fix stage results bucket. |
| `artifact_registry_repo` | `string` | Full Docker path to the Artifact Registry runner repository. |
| `find_sa_email` | `string` | Service account email of the find stage. |
| `verify_sa_email` | `string` | Service account email of the verify stage. |
| `fix_sa_email` | `string` | Service account email of the fix stage. |
| `find_job_name` | `string` | Cloud Run job name for the find stage (`cm-find-runner`). |
| `verify_job_name` | `string` | Cloud Run job name for the verify stage (`cm-verify-runner`). |
| `fix_job_name` | `string` | Cloud Run job name for the fix stage (`cm-fix-runner`). |
| `stage_jobs` | `map(string)` | Map of stage name to Cloud Run job name. |
| `stage_sas` | `map(string)` | Map of stage name to service account email. |
| `stage_buckets` | `map(string)` | Map of stage name to results bucket name. |
| `operators` | `list(string)` | Effective list of operator IAM principals granted access. |

### Resource Naming Contract

The runtime runner (`cmrun/common.py`, `run.py`, `deploy.sh`) references fixed names derived from `project_id`. This module preserves these names:

| Resource | Terraform Resource | Name Pattern | Python Reference |
|---|---|---|---|
| Find Job | `google_cloud_run_v2_job.stage["find"]` | `cm-find-runner` | `cmrun.common.FIND_JOB` |
| Verify Job | `google_cloud_run_v2_job.stage["verify"]` | `cm-verify-runner` | `cmrun.common.VERIFY_JOB` |
| Fix Job | `google_cloud_run_v2_job.stage["fix"]` | `cm-fix-runner` | `cmrun.common.FIX_JOB` |
| Payload Bucket | `google_storage_bucket.payload` | `<project_id>-cm-payload` | `cmrun.common.payload_bucket()` |
| Find Results Bucket | `google_storage_bucket.results["find"]` | `<project_id>-cm-find-results` | `cmrun.common.find_results_bucket()` |
| Verify Results Bucket | `google_storage_bucket.results["verify"]` | `<project_id>-cm-verify-results` | `cmrun.common.verify_results_bucket()` |
| Fix Results Bucket | `google_storage_bucket.results["fix"]` | `<project_id>-cm-fix-results` | `cmrun.common.fix_results_bucket()` |
| Artifact Registry Repo | `google_artifact_registry_repository.runner` | `cm-parallel-sandbox` | `cmrun.common.IMAGE_NAME` |

## Limitations / Known Issues

- **Isolated VPC creation**: The module creates a dedicated VPC with default route deletion and private Google API routing. It does not attach to an existing shared or external VPC.
- **Fixed naming contract**: Bucket and job names follow the contract expected by `run.py`. Changing these names requires updating `cmrun/common.py`.
- **Zero task retries**: `max_retries` defaults to `0`. Increasing `max_retries` causes tasks to fail on retry if results have already been partially written to create-only buckets.
- **Caller identity auto-detection**: When `operators = null`, the module inspects `data.google_client_openid_userinfo`. In automated environments without OpenID userinfo tokens, pass `operators` explicitly as a list of `user:...` or `serviceAccount:...` strings.
