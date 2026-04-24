#!/usr/bin/env bash
set -euo pipefail

ROLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$ROLE_DIR/.." && pwd)"
APP_DIR="$ROLE_DIR/app"
BUILD_DIR="$APP_DIR/build-wsl"
SCENARIO_PATH="$APP_DIR/config/test_demo_1.conf"
BUS_DIR="${PQ_ABSE_BUS_DIR:-$ROOT_DIR/service_bus}"
EXPORT_DIR="${PQ_ABSE_TA_EXPORT_DIR:-$ROOT_DIR/shared_exports}"

require_build() {
  if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Missing build directory: $BUILD_DIR" >&2
    exit 1
  fi
}

ensure_bus() {
  mkdir -p "$BUS_DIR/ta/register" "$BUS_DIR/ta/refresh" "$BUS_DIR/ta/revoke" "$BUS_DIR/ta/acks" "$BUS_DIR/ta/archive"
}

export_shared_state() {
  local snapshots_dir="$EXPORT_DIR/shared_state/snapshots"
  local snapshot_name="snapshot_$(date +%s%N)"
  local snapshot_dir="$snapshots_dir/$snapshot_name"
  mkdir -p "$EXPORT_DIR/shared_state"
  mkdir -p "$snapshots_dir"
  rm -rf "$snapshot_dir"
  mkdir -p "$snapshot_dir"
  cp -a "$APP_DIR/runtime/abse" "$snapshot_dir/"
  cp -a "$APP_DIR/runtime/state" "$snapshot_dir/"
  if [[ -d "$APP_DIR/runtime/cloud" ]]; then
    cp -a "$APP_DIR/runtime/cloud" "$snapshot_dir/"
  fi
  ln -sfn "snapshots/$snapshot_name" "$EXPORT_DIR/shared_state/latest"
}

export_user_materials() {
  local gid="$1"
  local user_dir="$EXPORT_DIR/users/$gid"
  mkdir -p "$user_dir" "$user_dir/update_tokens"
  cp -f "$APP_DIR/runtime/users/$gid.cred" "$user_dir/"
  cp -f "$APP_DIR/runtime/users/${gid}_userkey.bin" "$user_dir/"
  if compgen -G "$APP_DIR/runtime/state/update_tokens/${gid}_epoch_"'*'.token > /dev/null; then
    cp -f "$APP_DIR"/runtime/state/update_tokens/${gid}_epoch_*.token "$user_dir/update_tokens/" || true
  fi
}

run_setup() {
  require_build
  "$BUILD_DIR/phase1_setup"
  export_shared_state
}

run_register() {
  require_build
  local user="${1:?usage: ta_ia_blockchain.sh register <scenario-user-name>}"
  "$BUILD_DIR/phase2_keygen" --scenario "$SCENARIO_PATH" --user "$user"
  local gid
  gid="$(grep "^user.$user.gid=" "$SCENARIO_PATH" | cut -d= -f2- || true)"
  if [[ -z "$gid" ]]; then
    gid="$user"
  fi
  export_user_materials "$gid"
  export_shared_state
}

run_refresh() {
  require_build
  local user="${1:?usage: ta_ia_blockchain.sh refresh <scenario-user-name>}"
  "$BUILD_DIR/phase2_keygen" --scenario "$SCENARIO_PATH" --user "$user" --refresh-existing
  local gid
  gid="$(grep "^user.$user.gid=" "$SCENARIO_PATH" | cut -d= -f2- || true)"
  if [[ -z "$gid" ]]; then
    gid="$user"
  fi
  export_user_materials "$gid"
  export_shared_state
}

run_revoke() {
  require_build
  local revocation="${1:?usage: ta_ia_blockchain.sh revoke <scenario-revocation-name>}"
  "$BUILD_DIR/phase5_revoke" --scenario "$SCENARIO_PATH" --revocation "$revocation"
  for cred in "$APP_DIR"/runtime/users/*.cred; do
    [[ -e "$cred" ]] || continue
    local gid
    gid="$(basename "$cred" .cred)"
    export_user_materials "$gid"
  done
  export_shared_state
}

ack() {
  local id="$1"
  local status="$2"
  local detail="$3"
  mkdir -p "$BUS_DIR/ta/acks/$id"
  printf '%s\n' "$status" > "$BUS_DIR/ta/acks/$id/status.txt"
  printf '%s\n' "$detail" > "$BUS_DIR/ta/acks/$id/detail.txt"
}

process_once() {
  ensure_bus
  shopt -s nullglob
  for req in "$BUS_DIR/ta/register"/*.req; do
    local id action
    id="$(basename "$req" .req)"
    action="$(cat "$req")"
    if run_register "$action"; then ack "$id" ok "registered $action"; else ack "$id" fail "register failed for $action"; fi
    mv "$req" "$BUS_DIR/ta/archive/$id.register.req.done"
  done
  for req in "$BUS_DIR/ta/register"/*.req.done; do :; done
  for req in "$BUS_DIR/ta/refresh"/*.req; do
    local id action
    id="$(basename "$req" .req)"
    action="$(cat "$req")"
    if run_refresh "$action"; then ack "$id" ok "refreshed $action"; else ack "$id" fail "refresh failed for $action"; fi
    mv "$req" "$BUS_DIR/ta/archive/$id.refresh.req.done"
  done
  for req in "$BUS_DIR/ta/refresh"/*.req.done; do :; done
  for req in "$BUS_DIR/ta/revoke"/*.req; do
    local id action
    id="$(basename "$req" .req)"
    action="$(cat "$req")"
    if run_revoke "$action"; then ack "$id" ok "revoked $action"; else ack "$id" fail "revoke failed for $action"; fi
    mv "$req" "$BUS_DIR/ta/archive/$id.revoke.req.done"
  done
}

serve() {
  ensure_bus
  while true; do
    process_once
    sleep 1
  done
}

submit() {
  ensure_bus
  local queue="$1"
  local value="$2"
  local id="${3:-$(date +%s%N)}"
  printf '%s\n' "$value" > "$BUS_DIR/ta/$queue/$id.req"
  echo "$id"
}

cmd="${1:-}"
case "$cmd" in
  setup) run_setup ;;
  register) run_register "${2:-}" ;;
  refresh) run_refresh "${2:-}" ;;
  revoke) run_revoke "${2:-}" ;;
  process-once) process_once ;;
  serve) serve ;;
  export-state) export_shared_state ;;
  export-user) export_user_materials "${2:?}" ;;
  submit-register) submit register "${2:?}" "${3:-}" ;;
  submit-refresh) submit refresh "${2:?}" "${3:-}" ;;
  submit-revoke) submit revoke "${2:?}" "${3:-}" ;;
  *)
    echo "Usage: $0 {setup|register <user>|refresh <user>|revoke <revocation>|process-once|serve|export-state|export-user <gid>|submit-register <user> [id]|submit-refresh <user> [id]|submit-revoke <revocation> [id]}" >&2
    exit 1
    ;;
esac
