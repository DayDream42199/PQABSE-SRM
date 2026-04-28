#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
SCENARIO_PATH="$APP_DIR/config/test_demo_1.conf"
TA_URL="${PQ_ABSE_TA_URL:-http://127.0.0.1:8081}"
CS_URL="${PQ_ABSE_CS_URL:-http://127.0.0.1:8083}"
HTTP_HOST="${PQ_ABSE_HTTP_HOST:-0.0.0.0}"
HTTP_PORT="${PQ_ABSE_MDU_PORT:-8084}"

ensure_runtime_dirs() {
  mkdir -p "$APP_DIR/runtime/service/requests" "$APP_DIR/runtime/service/responses" "$APP_DIR/runtime/users" "$APP_DIR/runtime/state/update_tokens"
}

rewrite_local_credential() {
  local cred_path="${1:?}"
  local gid
  gid="$(basename "$cred_path" .cred)"
  python3 - "$cred_path" "$APP_DIR/runtime/users/${gid}_userkey.bin" <<'PY'
from pathlib import Path
import sys

cred_path = Path(sys.argv[1])
user_key_path = sys.argv[2]
lines = cred_path.read_text().splitlines()
updated = []
replaced = False
for line in lines:
    if line.startswith("user_key_path="):
        updated.append(f"user_key_path={user_key_path}")
        replaced = True
    else:
        updated.append(line)
if not replaced:
    updated.append(f"user_key_path={user_key_path}")
cred_path.write_text("\n".join(updated) + "\n")
PY
}

query_gid() {
  local query="${1:?}"
  local gid
  gid="$(grep "^query.$query.gid=" "$SCENARIO_PATH" | cut -d= -f2- || true)"
  if [[ -z "$gid" ]]; then
    echo "Unknown query gid for $query" >&2
    return 1
  fi
  printf '%s\n' "$gid"
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

sync_user_materials() {
  local archive
  local sync_dir
  archive="$(mktemp)"
  sync_dir="$(mktemp -d)"
  ensure_runtime_dirs
  curl -fsS "$TA_URL/users/all.tar.gz" -o "$archive"
  tar -xzf "$archive" -C "$sync_dir"
  [[ -d "$sync_dir/users" ]] && cp -f "$sync_dir"/users/* "$APP_DIR/runtime/users/" 2>/dev/null || true
  [[ -d "$sync_dir/state/update_tokens" ]] && cp -f "$sync_dir"/state/update_tokens/*.token "$APP_DIR/runtime/state/update_tokens/" 2>/dev/null || true
  local cred
  for cred in "$APP_DIR"/runtime/users/*.cred; do
    [[ -f "$cred" ]] || continue
    rewrite_local_credential "$cred"
  done
  rm -rf "$sync_dir"
  rm -f "$archive"
}

refresh_request() {
  local user="${1:?}"
  curl -fsS \
    -H 'Content-Type: application/json' \
    -d "{\"user\":\"$user\"}" \
    "$TA_URL/refresh"
  printf '\n'
}

submit_search() {
  ensure_runtime_dirs
  sync_state_from_ta
  sync_user_materials
  local query="${1:?usage: mdu.sh submit-search <scenario-query-name> [id]}"
  local id="${2:-$(date +%s%N)}"
  local local_request_dir="$APP_DIR/runtime/service/requests/$id"
  local local_response_dir="$APP_DIR/runtime/service/responses/$id"
  local archive
  local response_archive
  archive="$(mktemp)"
  response_archive="$(mktemp)"
  rm -rf "$local_request_dir" "$local_response_dir"
  mkdir -p "$local_request_dir" "$local_response_dir"
  "$BUILD_DIR/mdu_prepare_query" --scenario "$SCENARIO_PATH" --query "$query" --out-dir "$local_request_dir" >&2
  tar -C "$local_request_dir" -czf "$archive" .
  curl -fsS \
    -H 'Content-Type: application/gzip' \
    --data-binary "@$archive" \
    "$CS_URL/query/$id" \
    -o "$response_archive"
  tar -xzf "$response_archive" -C "$local_response_dir"
  rm -f "$archive" "$response_archive"
  printf '%s\n' "$id"
}

collect_response() {
  ensure_runtime_dirs
  sync_state_from_ta
  sync_user_materials
  local gid="${1:?usage: mdu.sh collect-response <gid> <id>}"
  local id="${2:?usage: mdu.sh collect-response <gid> <id>}"
  local local_request_dir="$APP_DIR/runtime/service/requests/$id"
  local local_response_dir="$APP_DIR/runtime/service/responses/$id"
  "$BUILD_DIR/mdu_decrypt_response" --gid "$gid" --request-dir "$local_request_dir" --response-dir "$local_response_dir"
}

search_and_decrypt() {
  local query="${1:?usage: mdu.sh search <scenario-query-name> [id]}"
  local id="${2:-$(date +%s%N)}"
  local gid
  gid="$(query_gid "$query")"
  submit_search "$query" "$id" >/dev/null
  collect_response "$gid" "$id"
}

wait_response() {
  local id="${1:?}"
  [[ -f "$APP_DIR/runtime/service/responses/$id/exact_match_count.txt" ]]
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
  sync-users) sync_user_materials ;;
  refresh) refresh_request "${2:?}" ;;
  submit-search) submit_search "${2:?}" "${3:-}" ;;
  collect-response) collect_response "${2:?}" "${3:?}" ;;
  wait-response) wait_response "${2:?}" ;;
  search) search_and_decrypt "${2:?}" "${3:-}" ;;
  serve-http) serve_http "$@" ;;
  *)
    echo "Usage: $0 {sync-state|sync-users|refresh <user>|submit-search <query> [id]|collect-response <gid> <id>|wait-response <id>|search <query> [id]|serve-http [host] [port]}" >&2
    exit 1
    ;;
esac
