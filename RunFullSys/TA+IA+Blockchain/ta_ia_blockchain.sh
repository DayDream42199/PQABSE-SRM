#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
SCENARIO_PATH="$APP_DIR/config/test_demo_1.conf"
HTTP_HOST="${PQ_ABSE_HTTP_HOST:-0.0.0.0}"
HTTP_PORT="${PQ_ABSE_TA_PORT:-8081}"

tee_args=()
if [[ "${PQ_ABSE_TEE_MODE:-software}" == "nitro" ]]; then
  tee_args+=(
    --tee-mode nitro
    --nitro-cid "${PQ_ABSE_NITRO_CID:-16}"
    --nitro-port "${PQ_ABSE_NITRO_PORT:-5005}"
    --nitro-timeout-ms "${PQ_ABSE_NITRO_TIMEOUT_MS:-30000}"
  )
fi

require_build() {
  if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Missing build directory: $BUILD_DIR" >&2
    exit 1
  fi
}

run_setup() {
  require_build
  "$BUILD_DIR/phase1_setup"
}

run_register() {
  require_build
  local user="${1:?usage: ta_ia_blockchain.sh register <scenario-user-name>}"
  "$BUILD_DIR/phase2_keygen" --scenario "$SCENARIO_PATH" --user "$user" "${tee_args[@]}"
}

run_refresh() {
  require_build
  local user="${1:?usage: ta_ia_blockchain.sh refresh <scenario-user-name>}"
  "$BUILD_DIR/phase2_keygen" --scenario "$SCENARIO_PATH" --user "$user" --refresh-existing "${tee_args[@]}"
}

run_revoke() {
  require_build
  local revocation="${1:?usage: ta_ia_blockchain.sh revoke <scenario-revocation-name>}"
  "$BUILD_DIR/phase5_revoke" --scenario "$SCENARIO_PATH" --revocation "$revocation"
}

serve_http() {
  exec python3 "$ROLE_DIR/http_server.py" \
    --host "${2:-$HTTP_HOST}" \
    --port "${3:-$HTTP_PORT}" \
    --role-dir "$ROLE_DIR"
}

cmd="${1:-}"
case "$cmd" in
  setup) run_setup ;;
  register) run_register "${2:-}" ;;
  refresh) run_refresh "${2:-}" ;;
  revoke) run_revoke "${2:-}" ;;
  serve-http) serve_http "$@" ;;
  *)
    echo "Usage: $0 {setup|register <user>|refresh <user>|revoke <revocation>|serve-http [host] [port]}" >&2
    exit 1
    ;;
esac
