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
  mkdir -p "$BUS_DIR/cs/queries" "$BUS_DIR/mdu/responses"
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

sync_user_materials() {
  local users_root="$TA_EXPORT_DIR/users"
  [[ -d "$users_root" ]] || return 0
  mkdir -p "$APP_DIR/runtime/users" "$APP_DIR/runtime/state/update_tokens"
  for user_dir in "$users_root"/*; do
    [[ -d "$user_dir" ]] || continue
    cp -f "$user_dir"/*.cred "$APP_DIR/runtime/users/" 2>/dev/null || true
    cp -f "$user_dir"/*_userkey.bin "$APP_DIR/runtime/users/" 2>/dev/null || true
    cp -f "$user_dir"/update_tokens/*.token "$APP_DIR/runtime/state/update_tokens/" 2>/dev/null || true
  done
  local cred
  for cred in "$APP_DIR"/runtime/users/*.cred; do
    [[ -f "$cred" ]] || continue
    rewrite_local_credential "$cred"
  done
}

refresh_request() {
  local user="${1:?}"
  local id="${2:-$(date +%s%N)}"
  mkdir -p "$BUS_DIR/ta/refresh"
  printf '%s\n' "$user" > "$BUS_DIR/ta/refresh/$id.req"
  echo "$id"
}

submit_search() {
  ensure_bus
  sync_state_from_ta
  sync_user_materials
  local query="${1:?usage: mdu.sh submit-search <scenario-query-name> [id]}"
  local id="${2:-$(date +%s%N)}"
  local local_request_dir="$APP_DIR/runtime/service/requests/$id"
  rm -rf "$local_request_dir" "$BUS_DIR/cs/queries/$id"
  mkdir -p "$APP_DIR/runtime/service/requests"
  "$BUILD_DIR/mdu_prepare_query" --scenario "$SCENARIO_PATH" --query "$query" --out-dir "$local_request_dir" >&2
  cp -a "$local_request_dir" "$BUS_DIR/cs/queries/$id"
  echo "$id"
}

collect_response() {
  ensure_bus
  sync_state_from_ta
  sync_user_materials
  local gid="${1:?usage: mdu.sh collect-response <gid> <id>}"
  local id="${2:?usage: mdu.sh collect-response <gid> <id>}"
  local local_request_dir="$APP_DIR/runtime/service/requests/$id"
  local local_response_dir="$APP_DIR/runtime/service/responses/$id"
  if [[ ! -d "$BUS_DIR/mdu/responses/$id" ]]; then
    echo "Missing response for $id" >&2
    return 1
  fi
  mkdir -p "$APP_DIR/runtime/service/responses"
  rm -rf "$local_response_dir"
  cp -a "$BUS_DIR/mdu/responses/$id" "$local_response_dir"
  "$BUILD_DIR/mdu_decrypt_response" --gid "$gid" --request-dir "$local_request_dir" --response-dir "$local_response_dir"
}

wait_response() {
  local id="${1:?}"
  local timeout="${2:-60}"
  local waited=0
  while (( waited < timeout )); do
    if [[ -f "$BUS_DIR/mdu/responses/$id/exact_match_count.txt" ]]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

cmd="${1:-}"
case "$cmd" in
  sync-state) sync_state_from_ta ;;
  sync-users) sync_user_materials ;;
  refresh) refresh_request "${2:?}" "${3:-}" ;;
  submit-search) submit_search "${2:?}" "${3:-}" ;;
  collect-response) collect_response "${2:?}" "${3:?}" ;;
  wait-response) wait_response "${2:?}" "${3:-60}" ;;
  *)
    echo "Usage: $0 {sync-state|sync-users|refresh <user> [id]|submit-search <query> [id]|wait-response <id> [timeout]|collect-response <gid> <id>}" >&2
    exit 1
    ;;
esac
