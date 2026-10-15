.RECIPEPREFIX = >
include tools/versions.env

REPORTS        := reports
IMAGE          ?= notes-api:local
HADOLINT_IMAGE := hadolint/hadolint:$(HADOLINT_VERSION)

.PHONY: install fmt lint typecheck test audit actions-lint check run \
        scanners sast secrets sca dockerlint image image-scan scan gate clean

install:
> uv sync --all-groups
> pre-commit install

fmt:
> uv run ruff check --fix .
> uv run ruff format .

lint:
> uv run ruff check .
> uv run ruff format --check .

typecheck:
> uv run mypy

test:
> uv run pytest

audit:
> uv export --format requirements-txt --no-emit-project -o .audit-requirements.txt
> uv run pip-audit -r .audit-requirements.txt --disable-pip
> rm -f .audit-requirements.txt

actions-lint:
> uv run zizmor .github/workflows/

check: lint typecheck test audit

run:
> uv run uvicorn notes_api.main:app --reload --port 8000

# ---------- Securitate (toate scanerele RAPORTEAZĂ; gate-ul DECIDE) ----------
scanners:
> bash tools/install-scanners.sh

$(REPORTS):
> mkdir -p $(REPORTS)

sast: | $(REPORTS)
> uvx --from semgrep==$(SEMGREP_VERSION) semgrep scan --metrics=off \
    --config p/python --config p/owasp-top-ten \
    --sarif --output $(REPORTS)/semgrep.sarif
> uv run bandit -q -r src tools -f sarif -o $(REPORTS)/bandit.sarif --exit-zero

secrets: | $(REPORTS)
> gitleaks git --redact --exit-code 0 \
    --report-format sarif --report-path $(REPORTS)/gitleaks.sarif .

sca: | $(REPORTS)
> trivy fs --scanners vuln,misconfig --skip-dirs .venv --exit-code 0 \
    --format sarif --output $(REPORTS)/trivy-fs.sarif .

dockerlint: | $(REPORTS)
> docker run --rm -v "$(CURDIR):/work:ro" -w /work $(HADOLINT_IMAGE) \
    hadolint --no-fail --format sarif Dockerfile > $(REPORTS)/hadolint.sarif

image:
> docker build --pull -t $(IMAGE) .

image-scan: | $(REPORTS)
> trivy image --scanners vuln --ignore-unfixed --exit-code 0 \
    --format sarif --output $(REPORTS)/trivy-image.sarif $(IMAGE)

scan: sast secrets sca dockerlint

gate:
> uv run python tools/security_gate.py --policy .security-gate.toml $(REPORTS)/*.sarif

clean:
> rm -rf $(REPORTS)
