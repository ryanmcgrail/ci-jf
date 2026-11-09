# cm-parallel-sandbox Terraform

## Overview

Provisions the GCP infrastructure required to run parallel CodeMender `find`, `verify`, and `fix` tasks on Cloud Run. It sets up an isolated VPC with private Google API egress, stage-isolated Cloud Storage buckets enforcing a one-way data diode, stage service accounts, and Cloud Run jobs.

## Prerequisites

- Terraform >= 1.5.0
- Google Cloud SDK (`gcloud`) authenticated via `gcloud auth application-default login`
- A GCP project with billing enabled
- GCP IAM role `roles/owner` or `roles/editor` + `roles/resourcemanager.projectIamAdmin` on the target project

## Installation / Setup

Clone this repository and verify required command-line tools:

```bash
git clone https://github.com/cloud-gtm/cm-parallel-sandbox.git
cd cm-parallel-sandbox
terraform version
gcloud version
```

## Usage

### Option 1: Bootstrap script (recommended)

Runs Terraform apply in `examples/dev-sandbox`, builds the runner container image with Cloud Build via `deploy.sh`, and validates the deployment with `scripts/selftest.sh`:

> [!WARNING]
> `bootstrap.sh` runs `terraform apply -auto-approve` with local state in the selected configuration directory. Do not point it at a project whose infrastructure is already managed by another Terraform root. Resources that already exist fail with 409 errors, and additive IAM grants that succeed are recorded in the new local state, where a later `terraform destroy` removes them.

```bash
./terraform/bootstrap.sh --project <PROJECT_ID> [--region us-central1]
```

To apply `examples/complete` instead, supply its required variables in a tfvars file:

```bash
cat > complete.tfvars <<'EOF'
operators = ["user:alice@example.com", "group:team@example.com"]
EOF
./terraform/bootstrap.sh --project <PROJECT_ID> \
  --config-dir terraform/examples/complete --var-file complete.tfvars
```

### Option 2: Step-by-step manual deployment

#### 1. Apply Terraform infrastructure

Navigate to the `dev-sandbox` example directory and apply:

```bash
cd terraform/examples/dev-sandbox
terraform init
terraform apply -var="project_id=<PROJECT_ID>" -var="region=us-central1"
cd ../../..
```

#### 2. Build the runner image

Use `deploy.sh` to submit a Cloud Build job and update Cloud Run job definitions:

```bash
./deploy.sh --project <PROJECT_ID> --region us-central1
```

#### 3. Run the data-diode self-test

Verify that stage service accounts can only read permitted inputs and write to their designated results buckets:

```bash
./scripts/selftest.sh --project <PROJECT_ID> --region us-central1
```

#### 4. Execute a pipeline run

Dispatch an end-to-end smoke test on a sample repository:

```bash
python3 run.py --operation find-verify-fix --repos o04-vampi --experiment-id smoke --verify-limit 1 --fix-limit 1 --wait --project <PROJECT_ID>
```

## Configuration / Flags

### `bootstrap.sh` Flags

| Flag | Required | Default | Description |
|---|---|---|---|
| `--project <project>` | Yes | None | GCP project ID to deploy into. |
| `--region <region>` | No | `us-central1` | GCP region for resources. |
| `--no-enable-apis` | No | `false` | Skips enabling GCP APIs if they are managed externally. |
| `--config-dir <dir>` | No | `terraform/examples/dev-sandbox` | Terraform root to apply. It must declare the variables `project_id`, `region`, and `enable_apis`, because `bootstrap.sh` always passes them. |
| `--var-file <path>` | No | None | tfvars file passed to `terraform apply`. Use it for any other required variables in the chosen root (for example, `operators` in `examples/complete`). `--project`, `--region`, and `--no-enable-apis` take precedence over values in this file. |
| `-h`, `--help` | No | None | Prints usage instructions. |

### Module Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `project_id` | `string` | *(required)* | GCP project ID. |
| `region` | `string` | `"us-central1"` | GCP region. |
| `enable_apis` | `bool` | `true` | Automatically enables required GCP APIs. Set to `false` when managing APIs externally. |
| `name_prefix` | `string` | `"cm-run"` | Prefix for network resources (VPC, subnet, firewall, DNS). |
| `subnet_cidr` | `string` | `"10.20.0.0/22"` | CIDR range for Direct VPC egress subnet. |
| `task_cpu` | `string` | `"4"` | vCPU allocation per task. |
| `task_memory` | `string` | `"16Gi"` | Memory allocation per task. |
| `task_timeout` | `string` | `"172800s"` | Cloud Run task timeout in seconds (48h). |
| `max_retries` | `number` | `0` | Task retry limit. Must remain 0 for write-once buckets. |
| `results_retention_days` | `number` | `null` | Bucket object retention in days before automatic deletion. |
| `operators` | `list(string)` | `null` | IAM members granted execution rights. Defaults to current authenticated caller identity. |
| `cloud_build_sa_email` | `string` | `null` | Cloud Build service account email. Defaults to Compute Engine default SA. |
| `create_cloudbuild_bucket` | `bool` | `true` | Creates the `<project_id>_cloudbuild` source bucket so the Cloud Build SA can be granted read access before the first build. Set to `false` if the bucket already exists. |

### State Storage

The examples default to local state (`terraform.tfstate`). For team deployments or CI/CD pipelines, configure a remote backend in `backend.tf`:

```hcl
terraform {
  backend "gcs" {
    bucket = "<PROJECT_ID>-tfstate"
    prefix = "terraform/state"
  }
}
```

The GCS bucket must be created prior to initializing the backend.

## Limitations / Known Issues

- **Network topology**: The module provisions a new dedicated VPC network with default routes deleted. It does not support attaching to an existing Shared VPC or custom network.
- **Fixed naming convention**: Cloud Run job names (`cm-find-runner`, `cm-verify-runner`, `cm-fix-runner`) and bucket names (`<project>-cm-payload`, `<project>-cm-*-results`) are hardcoded to match the contract expected by `run.py` and `cmrun/common.py`.
- **Task retries**: Setting `max_retries` greater than 0 will cause retried tasks to fail because stage service accounts have `roles/storage.objectCreator` permissions, which prohibit overwriting existing objects.
- **Operator resolution**: When `operators` is null, caller identity is detected via `data.google_client_openid_userinfo`. In non-interactive environments without userinfo access, supply `operators` explicitly.
- **Test coverage**: The module has been checked with a read-only `terraform plan` against an existing deployment (0 to add, 0 to change, 0 to destroy). A full `bootstrap.sh` run on a fresh project has not been done yet.
