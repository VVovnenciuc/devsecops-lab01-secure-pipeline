#!/usr/bin/env bash
# Instalează scanerele la versiuni FIXATE, verificând checksum-ul fiecărui binar.
# Rulat identic pe VM și în CI → aceleași versiuni peste tot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/versions.env"

case "${TRIVY_VERSION}" in
  0.69.4|0.69.5|0.69.6)
    echo "EROARE: Trivy ${TRIVY_VERSION} este o versiune COMPROMISĂ (CVE-2026-33634)" >&2
    exit 1 ;;
esac

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "${BIN_DIR}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fetch() { # $1=owner/repo $2=tag $3=fișier
  curl -sSfL --retry 3 -o "$3" "https://github.com/$1/releases/download/$2/$3"
}

install_tool() { # $1=nume $2=owner/repo $3=tag $4=arhivă/binar $5=fișier checksums $6=tar|bin
  local dir="${WORK}/$1"
  mkdir -p "${dir}" && cd "${dir}"
  fetch "$2" "$3" "$4"
  fetch "$2" "$3" "$5"
  sha256sum --ignore-missing -c "$5"          # pică dacă hash-ul nu se potrivește
  if [[ "$6" == "tar" ]]; then
    tar -xzf "$4" "$1"
    install -m 0755 "$1" "${BIN_DIR}/$1"
  else
    install -m 0755 "$4" "${BIN_DIR}/$1"
  fi
  echo "✔ $1 $3"
}

install_tool trivy    aquasecurity/trivy "v${TRIVY_VERSION}" \
  "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" tar
install_tool gitleaks gitleaks/gitleaks "v${GITLEAKS_VERSION}" \
  "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" tar
install_tool syft     anchore/syft "v${SYFT_VERSION}" \
  "syft_${SYFT_VERSION}_linux_amd64.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" tar
install_tool cosign   sigstore/cosign "v${COSIGN_VERSION}" \
  "cosign-linux-amd64" "cosign_checksums.txt" bin
