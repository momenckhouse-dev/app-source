# secure-event-api

[![ci](https://github.com/momenckhouse-dev/app-source/actions/workflows/ci.yml/badge.svg)](https://github.com/momenckhouse-dev/app-source/actions/workflows/ci.yml)

Security-event ingestion API for the Secure GitOps Platform. Accepts events over HTTP, validates
them, archives them to an S3 bucket provisioned through the platform's `SecureService` API, and
exposes Prometheus metrics.

Platform overview, architecture and runbooks: [gitops-config](https://github.com/momenckhouse-dev/gitops-config).

## Run locally

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -q
PYTHONPATH=src python -m secure_event_api         # http://127.0.0.1:8080
curl -XPOST localhost:8080/v1/events -H 'content-type: application/json' \
  -d '{"source":"fw-gw-01","severity":"high","message":"blocked C2 beacon"}'
```

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/events` | Accept an event (`source`, `severity` low/medium/high/critical, `message`, optional `attributes`) |
| `GET /v1/events/stats` | Counts by severity |
| `GET /healthz`, `/readyz` | Liveness / readiness probes |
| `GET /metrics` | Prometheus metrics |
| `GET /version` | Build version and commit |

## CI/CD

`.github/workflows/ci.yml`: ruff + pytest → hadolint → build → Trivy gate (HIGH/CRITICAL) → CycloneDX SBOM →
push `<git-sha>` to ECR via GitHub OIDC → pull request to `gitops-config` pinning the new image in staging.
The AWS and GitOps steps run once the `AWS_CI_ROLE_ARN` and `GITOPS_BOT_APP_ID` repository variables exist.

`FAULT_MODE` (`errors`, `latency`, `memory_leak`) exists only for the platform's incident exercises.
