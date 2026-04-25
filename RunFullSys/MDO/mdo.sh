#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDGE_URL="${PQ_ABSE_EDGE_URL:-http://127.0.0.1:8082}"

submit_encrypt() {
  local bundle="${1:?usage: mdo.sh encrypt-upload <scenario-bundle-name> [id]}"
  local id="${2:-$(date +%s%N)}"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -d "{\"bundle\":\"$bundle\",\"request_id\":\"$id\"}" \
    "$EDGE_URL/encrypt"
  printf '\n'
}

cmd="${1:-}"
case "$cmd" in
  encrypt-upload)
    submit_encrypt "${2:?}" "${3:-}"
    ;;
  *)
    echo "Usage: $0 {encrypt-upload <bundle> [id]}" >&2
    exit 1
    ;;
esac
