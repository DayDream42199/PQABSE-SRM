#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
SCENARIO_PATH="$APP_DIR/config/test_demo_1.conf"
TA_URL="${PQ_ABSE_TA_URL:-http://127.0.0.1:8081}"
CS_URL="${PQ_ABSE_CS_URL:-http://127.0.0.1:8083}"
HTTP_HOST="${PQ_ABSE_HTTP_HOST:-0.0.0.0}"
HTTP_PORT="${PQ_ABSE_EDGE_PORT:-8082}"

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

sync_state_from_ta() {
  local archive
  local sync_dir
  archive="$(mktemp)"
  sync_dir="$(mktemp -d)"
  curl -fsS "$TA_URL/state/latest.tar.gz" -o "$archive"
  tar -xzf "$archive" -C "$sync_dir"
  mkdir -p "$APP_DIR/runtime"
  rm -rf "$APP_DIR/runtime/abse" "$APP_DIR/runtime/state" "$APP_DIR/runtime/cloud"
  [[ -d "$sync_dir/abse" ]] && cp -a "$sync_dir/abse" "$APP_DIR/runtime/"
  [[ -d "$sync_dir/state" ]] && cp -a "$sync_dir/state" "$APP_DIR/runtime/"
  [[ -d "$sync_dir/cloud" ]] && cp -a "$sync_dir/cloud" "$APP_DIR/runtime/"
  rm -rf "$sync_dir"
  rm -f "$archive"
}

run_encrypt() {
  require_build
  local bundle="${1:?usage: edge_node.sh encrypt <scenario-bundle-name>}"
  "$BUILD_DIR/phase3_encrypt" --scenario "$SCENARIO_PATH" --bundle "$bundle" "${tee_args[@]}"
}

run_encrypt_raw() {
  require_build
  local owner_gid="${1:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local label="${2:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local plaintext="${3:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local policy_type="${4:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local threshold="${5:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local keyword_csv="${6:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local policy_attr_csv="${7:?usage: edge_node.sh encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]}"
  local policy_expression="${8:-}"

  local args=(
    "$BUILD_DIR/phase3_encrypt"
    --owner-gid "$owner_gid"
    --label "$label"
    --plaintext "$plaintext"
    --policy-type "$policy_type"
    --threshold "$threshold"
  )

  local item
  IFS=',' read -r -a keyword_array <<< "$keyword_csv"
  for item in "${keyword_array[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "$item" ]] && args+=(--keyword "$item")
  done

  IFS=',' read -r -a policy_attr_array <<< "$policy_attr_csv"
  for item in "${policy_attr_array[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "$item" ]] && args+=(--policy-attr "$item")
  done

  if [[ -n "$policy_expression" ]]; then
    args+=(--policy-expression "$policy_expression")
  fi

  args+=("${tee_args[@]}")
  "${args[@]}"
}

serve_http() {
  exec python3 "$ROLE_DIR/http_server.py" \
    --host "${2:-$HTTP_HOST}" \
    --port "${3:-$HTTP_PORT}" \
    --role-dir "$ROLE_DIR"
}

cmd="${1:-}"
case "$cmd" in
  sync-state) sync_state_from_ta ;;
  encrypt) run_encrypt "${2:-}" ;;
  encrypt-raw) shift; run_encrypt_raw "$@" ;;
  serve-http) serve_http "$@" ;;
  *)
    echo "Usage: $0 {sync-state|encrypt <bundle>|encrypt-raw <owner-gid> <label> <plaintext> <policy-type> <threshold> <keyword-csv> <policy-attr-csv> [policy-expression]|serve-http [host] [port]}" >&2
    exit 1
    ;;
esac
