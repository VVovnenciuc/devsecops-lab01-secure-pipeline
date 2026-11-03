# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A DevSecOps portfolio lab: the pipeline is the product. `src/notes_api` is a deliberately small FastAPI app (in-memory storage) that exists to be built, scanned, signed and published. Most changes touch the workflows, `tools/` or the policy rather than the app.

Comments, docs, the PR template and the gate's Markdown summary are written in Romanian; match that when editing them. Log and error messages in code are in English.

## Commands

Requires `uv`, `make` and bash. The Makefile and `tools/install-scanners.sh` assume Linux (the installer fetches Linux amd64 binaries only).

```bash
make install        # uv sync --all-groups + pre-commit install
make check          # lint + typecheck + test + audit (CI also runs actions-lint)
make fmt            # ruff fix + format
make run            # uvicorn with reload on :8000 (NOTES_ENABLE_DOCS=true enables /docs)
make actions-lint   # zizmor on .github/workflows/

# Single test: --no-cov is needed, otherwise --cov-fail-under=80 in addopts fails the partial run
uv run pytest tests/test_api.py::test_healthz --no-cov

# Security scans, reproducing the security-gate job locally
make scanners       # install pinned trivy/gitleaks/syft/cosign into ~/.local/bin
make scan           # sast + secrets + sca + dockerlint, writes reports/*.sarif (dockerlint needs Docker)
make gate           # evaluate reports/*.sarif against .security-gate.toml
make image image-scan   # optional: adds reports/trivy-image.sarif
make clean          # remove reports/
```

`make gate` reads every file in `reports/`, so run `make clean` first if old reports could skew the result.

## Architecture

### Scanners report, the gate decides

This is the central design rule. Every scanner runs in non-blocking mode (`--exit-code 0`, `--exit-zero`, `--no-fail`) and writes SARIF to `reports/`. `tools/security_gate.py` is the **only** pass/fail decision point:

- Exit codes: `0` pass, `1` blocking findings, `2` error. A missing or invalid report or policy fails closed.
- Severity comes from the SARIF `security-severity` score (CVSS), falling back to the SARIF level. `[tool_severity]` in `.security-gate.toml` overrides it per tool, keyed on the lowercased SARIF driver name.
- Waivers in `.security-gate.toml` require `rule_id`, `reason` and `expires`; expired ones stop applying automatically. A waiver without `path` applies to that rule everywhere.
- Findings carrying SARIF `suppressions` (for example `# nosemgrep`) are skipped.

To add a scanner: run it in report-only mode from a new Makefile target, write to `reports/`, then add the step and a matching `upload-sarif` step to `security.yml`. Do not let a scanner fail the job on its own.

### Workflows

- `ci.yml` (PR, main) runs the `quality` job: lint, mypy, pytest, pip-audit, zizmor.
- `security.yml` (PR, main, weekly cron) runs the `security-gate` job over the source-level scanners, using full git history for gitleaks.
- `release.yml` (main only) runs build → Trivy image scan → gate → push to GHCR → Syft SBOM → cosign keyless signing → SLSA and SBOM attestations. Ordering matters: the image is gated before it is pushed, and signing and attestation target the pushed digest, never a tag.

Consequences that are easy to miss:

- The built image is only scanned in `release.yml`, so an image-level finding surfaces after merge to main, not on the PR.
- `release.yml` runs the gate with bare `python3` and no `uv sync`, so `tools/security_gate.py` must stay **standard library only**.
- `mypy` only covers `src` (`files = ["src"]`). `tools/` is linted and tested but not type-checked by `make typecheck`.

### Pinning

Everything is pinned, and each kind has its own location:

| What | Where | Form |
|---|---|---|
| Scanner versions | `tools/versions.env` | Read by both make and bash, so no inline comments on value lines |
| GitHub Actions | `.github/workflows/*.yml` | Full commit SHA plus `# vX.Y.Z` comment |
| Base images | `Dockerfile` | Tag plus `@sha256:` digest |
| pre-commit hooks | `.pre-commit-config.yaml` | Commit SHA plus `# frozen: vX.Y.Z` comment |
| Python dependencies | `uv.lock` | CI and Docker install with `--locked`, so update the lock with `pyproject.toml` |

`install-scanners.sh` verifies a checksum for each binary and refuses Trivy 0.69.4–0.69.6, which are compromised releases. Dependabot covers uv, Actions and Docker with a 7-day cooldown; `tools/versions.env` is updated by hand.

Workflows follow zizmor-enforced hardening: least-privilege `permissions` per job, `persist-credentials: false`, and `${{ }}` values passed through `env:` rather than interpolated into `run:` scripts.

### Application

All of it is in `src/notes_api/main.py`. Security properties the tests assert or the module docstring promises: security headers on every response including 404s (via middleware), length limits on input through Pydantic, and OpenAPI/docs disabled unless `NOTES_ENABLE_DOCS=true`.

Notes live in a module-level dict that is never reset, so state is shared between tests; don't write tests that assume an empty store.

The Dockerfile's runtime stage has no `uv`, runs as uid 10001, and leaves the venv owned by root so the process can't modify its own code.

## Conventions

- Ruff's `S` (bandit) rules are on for all code; only `S101` is ignored, and only under `tests/`.
- `tools/` is on the pytest `pythonpath` and counts toward the 80% coverage threshold, so tests import `security_gate` directly.
- Changes reach `main` through PRs using `.github/pull_request_template.md`, with conventional-commit style titles.
