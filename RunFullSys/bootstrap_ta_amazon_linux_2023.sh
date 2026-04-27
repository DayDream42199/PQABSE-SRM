#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

bash "${SCRIPT_DIR}/bootstrap_amazon_linux_2023.sh" ta "${REPO_ROOT}"
