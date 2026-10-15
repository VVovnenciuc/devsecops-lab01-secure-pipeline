# DevSecOps Lab 01 — Secure CI/CD Pipeline & Software Supply Chain

![CI](https://github.com/VVovnenciuc/devsecops-lab01-secure-pipeline/actions/workflows/ci.yml/badge.svg)
![Security](https://github.com/VVovnenciuc/devsecops-lab01-secure-pipeline/actions/workflows/security.yml/badge.svg)
![Release](https://github.com/VVovnenciuc/devsecops-lab01-secure-pipeline/actions/workflows/release.yml/badge.svg)

O aplicație FastAPI livrată printr-un pipeline care blochează automat cod vulnerabil
și publică doar imagini **scanate, semnate și cu proveniență verificabilă**.

## Arhitectura pipeline-ului

PR ─► quality (ruff+S rules, mypy, pytest, pip-audit, zizmor)
└► security-gate (Semgrep, Bandit, gitleaks, Trivy fs, Hadolint ─► SARIF ─► gate Python)
main ─► release: build ─► Trivy image ─► gate ─► push GHCR ─► Syft SBOM
─► cosign keyless sign ─► SLSA provenance + SBOM attestations


## Ce problemă de securitate rezolvă fiecare control
| Control | Risc acoperit |
|---|---|
| Semgrep + Bandit (SAST) | Injection, deserializare nesigură, crypto slab în cod |
| gitleaks (istoric complet) | Secrete comise în Git |
| Trivy fs + pip-audit (SCA) | Dependențe cu CVE-uri cunoscute |
| Hadolint + Trivy misconfig | Dockerfile nesigur (root, tag-uri mutabile) |
| Trivy image + gate înainte de push | Imagini vulnerabile publicate |
| Imagini de bază pe digest, scanere pe versiune + checksum | Tag-uri mutate de atacatori (ex. incidentul Trivy, mar. 2026) |
| cosign keyless + SLSA provenance + SBOM | Imagini falsificate/înlocuite în registry; inventar pentru CVE-uri noi |
| Security gate cu waivers care expiră | Excepții permanente uitate; politică unică, versionată |

## Verifică singur o imagine
```bash
cosign verify ghcr.io/vvovnenciuc/devsecops-lab01-secure-pipeline@9c7d39b213df4262c85c2893c09c2d9c026e9794840d442f9939997ef67a929d \
  --certificate-identity "https://github.com/VVovnenciuc/devsecops-lab01-secure-pipeline/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/vvovnenciuc/devsecops-lab01-secure-pipeline@9c7d39b213df4262c85c2893c09c2d9c026e9794840d442f9939997ef67a929d --owner VVovnenciuc
```

## Demonstrație: PR vulnerabil blocat
_(capturi de ecran: checks roșii, tabelul gate-ului, adnotarea pe linie)_

## Ce aș face diferit în producție
- Build în reusable workflow izolat → SLSA Build L3
- Admission control în Kubernetes care acceptă doar imagini semnate de acest workflow (Lab 3)
- DAST pe un mediu efemer (Lab 5) și centralizarea findings-urilor în DefectDojo
- Imagini de bază distroless/Chainguard; rebuild automat la CVE-uri noi în imaginea de bază
- Runner-e efemere cu egress restricționat (ex. Harden-Runner) — ar fi detectat exfiltrarea din incidentul Trivy
