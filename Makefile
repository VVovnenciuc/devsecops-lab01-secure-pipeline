.RECIPEPREFIX = >
.PHONY: install fmt lint typecheck test audit actions-lint check

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
