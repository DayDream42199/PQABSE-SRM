#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$ROLE_DIR/.." && pwd)"
BUS_DIR="${PQ_ABSE_BUS_DIR:-$ROOT_DIR/service_bus}"

submit_encrypt() {
  local bundle="${1:?usage: mdo.sh encrypt-upload <scenario-bundle-name> [id]}"
  local id="${2:-$(date +%s%N)}"
  mkdir -p "$BUS_DIR/edge/encrypt"
  printf '%s\n' "$bundle" > "$BUS_DIR/edge/encrypt/$id.req"
  echo "$id"
}

wait_ack() {
  local id="${1:?}"
  local timeout="${2:-60}"
  local waited=0
  while (( waited < timeout )); do
    if [[ -f "$BUS_DIR/edge/acks/$id/status.txt" ]]; then
      cat "$BUS_DIR/edge/acks/$id/status.txt"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

cmd="${1:-}"
case "$cmd" in
  encrypt-upload)
    submit_encrypt "${2:?}" "${3:-}"
    ;;
  wait-edge)
    wait_ack "${2:?}" "${3:-60}"
    ;;
  scp-example)
    local_path="${2:?usage: mdo.sh scp-example <local-file> <user@host:/remote/path>}"
    remote_path="${3:?usage: mdo.sh scp-example <local-file> <user@host:/remote/path>}"
    echo "scp -i /path/to/key.pem \"$local_path\" \"$remote_path\""
    ;;
  *)
    echo "Usage: $0 {encrypt-upload <bundle> [id]|wait-edge <id> [timeout]|scp-example <local-file> <user@host:/remote/path>}" >&2
    exit 1
    ;;
esac
