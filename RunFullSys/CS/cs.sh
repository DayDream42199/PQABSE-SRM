#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$ROLE_DIR/.." && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
BUS_DIR="${PQ_ABSE_BUS_DIR:-$ROOT_DIR/service_bus}"
TA_EXPORT_DIR="${PQ_ABSE_TA_EXPORT_DIR:-$ROOT_DIR/shared_exports}"

ensure_bus() {
  mkdir -p "$BUS_DIR/cs/uploads" "$BUS_DIR/cs/queries" "$BUS_DIR/cs/acks" "$BUS_DIR/cs/archive" "$BUS_DIR/mdu/responses"
}

rewrite_bundle_metadata() {
  local meta_path="${1:?}"
  local label
  label="$(basename "$meta_path" _bundle.meta)"
  python3 - "$meta_path" "$APP_DIR/runtime/ciphertexts/${label}_bundle.bin" <<'PY'
from pathlib import Path
import sys

meta_path = Path(sys.argv[1])
bundle_path = sys.argv[2]
lines = meta_path.read_text().splitlines()
updated = []
replaced = False
for line in lines:
    if line.startswith("bundle_path="):
        updated.append(f"bundle_path={bundle_path}")
        replaced = True
    else:
        updated.append(line)
if not replaced:
    updated.append(f"bundle_path={bundle_path}")
meta_path.write_text("\n".join(updated) + "\n")
PY
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

import_upload() {
  local upload_dir="${1:?}"
  mkdir -p "$APP_DIR/runtime/ciphertexts"
  cp -f "$upload_dir"/*_bundle.bin "$APP_DIR/runtime/ciphertexts/" 2>/dev/null || true
  cp -f "$upload_dir"/*_bundle.meta "$APP_DIR/runtime/ciphertexts/" 2>/dev/null || true
  local meta
  for meta in "$APP_DIR"/runtime/ciphertexts/*_bundle.meta; do
    [[ -f "$meta" ]] || continue
    rewrite_bundle_metadata "$meta"
  done
  rm -f "$APP_DIR"/runtime/search/bitmap_index_epoch_*.bin 2>/dev/null || true
}

process_once() {
  ensure_bus
  sync_state_from_ta
  shopt -s nullglob
  for upload_dir in "$BUS_DIR/cs/uploads"/*; do
    [[ -d "$upload_dir" ]] || continue
    [[ "$(basename "$upload_dir")" == *.done ]] && continue
    import_upload "$upload_dir"
    rm -rf "$upload_dir"
  done
  for req_dir in "$BUS_DIR/cs/queries"/*; do
    [[ -d "$req_dir" ]] || continue
    [[ "$(basename "$req_dir")" == *.done ]] && continue
    local id response_dir
    id="$(basename "$req_dir")"
    response_dir="$BUS_DIR/mdu/responses/$id"
    rm -rf "$response_dir"
    mkdir -p "$response_dir"
    if "$BUILD_DIR/cs_process_query" --request-dir "$req_dir" --response-dir "$response_dir"; then
      mkdir -p "$BUS_DIR/cs/acks/$id"
      printf 'ok\n' > "$BUS_DIR/cs/acks/$id/status.txt"
    else
      mkdir -p "$BUS_DIR/cs/acks/$id"
      printf 'fail\n' > "$BUS_DIR/cs/acks/$id/status.txt"
    fi
    mv "$req_dir" "$BUS_DIR/cs/archive/$id.query.done"
  done
}

serve() {
  ensure_bus
  while true; do
    process_once
    sleep 1
  done
}

cmd="${1:-}"
case "$cmd" in
  sync-state) sync_state_from_ta ;;
  process-once) process_once ;;
  serve) serve ;;
  *)
    echo "Usage: $0 {sync-state|process-once|serve}" >&2
    exit 1
    ;;
esac
