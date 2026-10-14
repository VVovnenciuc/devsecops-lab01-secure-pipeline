# DevSecOps Lab 00 — Secure Foundation

![CI](https://github.com/VVovnenciuc/devsecops-lab00-foundation/actions/workflows/ci.yml/badge.svg)

Repo de bază pentru portofoliul DevSecOps: un CLI Python (`headercheck`) care verifică
header-ele HTTP de securitate, construit cu controale de securitate „shift-left”.

## Controale de securitate implementate
- Commit-uri semnate (SSH) + regulă de branch care le impune
- Pre-commit: gitleaks (secrete), ruff (lint/format), detect-private-key
- CI GitHub Actions cu `permissions: contents: read`, acțiuni fixate pe SHA
- Audit de dependențe (pip-audit) pe lock file cu hash-uri
- Lint de securitate pentru workflow-uri (zizmor)
- Dependabot (Python + GitHub Actions), secret scanning + push protection

## Utilizare

uv sync
uv run headercheck https://example.com

Exit codes: `0` = toate header-ele prezente, `1` = lipsesc header-e, `2` = eroare.

## Ce aș face diferit în producție
- aprobări obligatorii de la cel puțin 1 reviewer
- runner-e self-hosted efemere
- semnarea artefactelor (Lab 1)
- scanare de secrete pe toată organizația
