#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$ROLE_DIR/.." && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
SCENARIO_PATH="$APP_DIR/config/test_demo_1.conf"
BUS_DIR="${PQ_ABSE_BUS_DIR:-$ROOT_DIR/service_bus}"
TA_EXPORT_DIR="${PQ_ABSE_TA_EXPORT_DIR:-$ROOT_DIR/shared_exports}"

ensure_bus() {
  mkdir -p "$BUS_DIR/edge/encrypt" "$BUS_DIR/edge/acks" "$BUS_DIR/edge/archive" "$BUS_DIR/cs/uploads"
}

sync_state_from_ta() {
  local latest_dir="$TA_EXPORT_DIR/shared_state/latest"
  [[ -d "$latest_dir/abse" && -d "$latest_dir/state" ]] || return 0
  local sync_dir="$APP_DIR/runtime/.sync.$$"
  rm -rf "$sync_dir"
  mkdir -p "$sync_dir"
  cp -a "$latest_dir/abse" "$sync_dir/" || { rm -rf "$sync_dir"; return 0; }
  cp -a "$latest_dir/state" "$sync_dir/" || { rm -rf "$sync_dir"; return 0; }
  if [[ -d "$latest_dir/cloud" ]]; then
    cp -a "$latest_dir/cloud" "$sync_dir/" || true
  fi
  mkdir -p "$APP_DIR/runtime"
  rm -rf "$APP_DIR/runtime/abse" "$APP_DIR/runtime/state" "$APP_DIR/runtime/cloud"
  cp -a "$sync_dir/abse" "$APP_DIR/runtime/"
  cp -a "$sync_dir/state" "$APP_DIR/runtime/"
  if [[ -d "$sync_dir/cloud" ]]; then
    cp -a "$sync_dir/cloud" "$APP_DIR/runtime/"
  fi
  rm -rf "$sync_dir"
}

run_encrypt() {
  local bundle="${1:?usage: edge_node.sh encrypt <scenario-bundle-name>}"
  "$BUILD_DIR/phase3_encrypt" --scenario "$SCENARIO_PATH" --bundle "$bundle"
}

process_once() {
  ensure_bus
  sync_state_from_ta
  shopt -s nullglob
  for req in "$BUS_DIR/edge/encrypt"/*.req; do
    local id bundle upload_dir
    id="$(basename "$req" .req)"
    bundle="$(cat "$req")"
    run_encrypt "$bundle"
    upload_dir="$BUS_DIR/cs/uploads/$id"
    mkdir -p "$upload_dir"
    cp -f "$APP_DIR/runtime/ciphertexts/${bundle}_bundle.bin" "$upload_dir/"
    cp -f "$APP_DIR/runtime/ciphertexts/${bundle}_bundle.meta" "$upload_dir/"
    mkdir -p "$BUS_DIR/edge/acks/$id"
    printf 'ok\n' > "$BUS_DIR/edge/acks/$id/status.txt"
    printf '%s\n' "$bundle" > "$BUS_DIR/edge/acks/$id/bundle.txt"
    mv "$req" "$BUS_DIR/edge/archive/$id.encrypt.req.done"
  done
}

serve() {
  ensure_bus
  while true; do
    process_once
    sleep 1
  done
}

submit_encrypt() {
  ensure_bus
  local bundle="${1:?}"
  local id="${2:-$(date +%s%N)}"
  printf '%s\n' "$bundle" > "$BUS_DIR/edge/encrypt/$id.req"
  echo "$id"
}

cmd="${1:-}"
case "$cmd" in
  sync-state) sync_state_from_ta ;;
  encrypt) run_encrypt "${2:-}" ;;
  process-once) process_once ;;
  serve) serve ;;
  submit-encrypt) submit_encrypt "${2:?}" "${3:-}" ;;
  *)
    echo "Usage: $0 {sync-state|encrypt <bundle>|process-once|serve|submit-encrypt <bundle> [id]}" >&2
    exit 1
    ;;
esac
