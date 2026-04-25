#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
TA_URL="${PQ_ABSE_TA_URL:-http://127.0.0.1:8081}"
HTTP_HOST="${PQ_ABSE_HTTP_HOST:-0.0.0.0}"
HTTP_PORT="${PQ_ABSE_CS_PORT:-8083}"

require_build() {
  if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Missing build directory: $BUILD_DIR" >&2
    exit 1
  fi
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

import_upload_dir() {
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

process_query_dir() {
  require_build
  local req_dir="${1:?}"
  local response_dir="${2:?}"
  sync_state_from_ta
  "$BUILD_DIR/cs_process_query" --request-dir "$req_dir" --response-dir "$response_dir"
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
  import-upload-dir) import_upload_dir "${2:?}" ;;
  process-query-dir) process_query_dir "${2:?}" "${3:?}" ;;
  serve-http) serve_http "$@" ;;
  *)
    echo "Usage: $0 {sync-state|import-upload-dir <dir>|process-query-dir <request-dir> <response-dir>|serve-http [host] [port]}" >&2
    exit 1
    ;;
esac
