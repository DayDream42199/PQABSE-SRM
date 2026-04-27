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

run_register_raw() {
  require_build
  local gid="${1:?usage: ta_ia_blockchain.sh register-raw <gid> <attr> [attr ...]}"
  shift
  if [[ "$#" -eq 0 ]]; then
    echo "register-raw requires at least one attribute" >&2
    exit 1
  fi

  local args=("$BUILD_DIR/phase2_keygen" --gid "$gid")
  local attr
  for attr in "$@"; do
    args+=(--attr "$attr")
  done
  args+=("${tee_args[@]}")
  "${args[@]}"
}

run_refresh() {
  require_build
  local user="${1:?usage: ta_ia_blockchain.sh refresh <scenario-user-name>}"
  "$BUILD_DIR/phase2_keygen" --scenario "$SCENARIO_PATH" --user "$user" --refresh-existing "${tee_args[@]}"
}

run_refresh_raw() {
  require_build
  local gid="${1:?usage: ta_ia_blockchain.sh refresh-raw <gid>}"
  local cred_path="$APP_DIR/runtime/users/${gid}.cred"
  if [[ ! -f "$cred_path" ]]; then
    echo "Missing credential record for $gid" >&2
    exit 1
  fi

  mapfile -t attrs < <(python3 - "$cred_path" <<'PY'
from pathlib import Path
import sys

values = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if "=" not in line:
        continue
    key, value = line.split("=", 1)
    values[key.strip()] = value.strip()

for attr in values.get("attributes", "").split(","):
    attr = attr.strip()
    if attr:
        print(attr)
PY
)

  local args=("$BUILD_DIR/phase2_keygen" --gid "$gid" --refresh-existing)
  local attr
  for attr in "${attrs[@]}"; do
    args+=(--attr "$attr")
  done
  args+=("${tee_args[@]}")
  "${args[@]}"
}

run_revoke() {
  require_build
  local revocation="${1:?usage: ta_ia_blockchain.sh revoke <scenario-revocation-name>}"
  "$BUILD_DIR/phase5_revoke" --scenario "$SCENARIO_PATH" --revocation "$revocation"
}

run_revoke_raw() {
  require_build
  local gid="${1:?usage: ta_ia_blockchain.sh revoke-raw <gid>}"
  shift
  "$BUILD_DIR/phase5_revoke" --gid "$gid" "$@"
}

prepare_query_dir() {
  require_build
  local gid="${1:?usage: ta_ia_blockchain.sh prepare-query-dir <gid> <out-dir> [label] <keyword> [keyword ...]}"
  local out_dir="${2:?usage: ta_ia_blockchain.sh prepare-query-dir <gid> <out-dir> [label] <keyword> [keyword ...]}"
  shift 2

  local label=""
  local extras=()
  local keywords=()
  if [[ "$#" -gt 0 ]]; then
    label="${1:-}"
    shift
  fi
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == --* ]]; then
      extras+=("$1")
      shift
      if [[ "$#" -gt 0 && "$1" != --* ]]; then
        extras+=("$1")
        shift
      fi
    else
      keywords+=("$1")
      shift
    fi
  done
  if [[ "${#keywords[@]}" -eq 0 ]]; then
    echo "prepare-query-dir requires at least one keyword" >&2
    exit 1
  fi

  local args=("$BUILD_DIR/mdu_prepare_query" --gid "$gid" --out-dir "$out_dir")
  if [[ -n "$label" ]]; then
    args+=(--label "$label")
  fi

  local keyword
  for keyword in "${keywords[@]}"; do
    args+=(--query-keyword "$keyword")
  done
  args+=("${extras[@]}")
  "${args[@]}"
}

prepare_auth_dir() {
  require_build
  local gid="${1:?usage: ta_ia_blockchain.sh prepare-auth-dir <gid> <out-dir> [label]}"
  local out_dir="${2:?usage: ta_ia_blockchain.sh prepare-auth-dir <gid> <out-dir> [label]}"
  local label="${3:-}"

  local args=("$BUILD_DIR/mdu_prepare_auth" --gid "$gid" --out-dir "$out_dir")
  if [[ -n "$label" ]]; then
    args+=(--label "$label")
  fi
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
  setup) run_setup ;;
  register) run_register "${2:-}" ;;
  register-raw) shift; run_register_raw "$@" ;;
  refresh) run_refresh "${2:-}" ;;
  refresh-raw) run_refresh_raw "${2:-}" ;;
  revoke) run_revoke "${2:-}" ;;
  revoke-raw) run_revoke_raw "${2:-}" ;;
  prepare-query-dir) shift; prepare_query_dir "$@" ;;
  prepare-auth-dir) shift; prepare_auth_dir "$@" ;;
  serve-http) serve_http "$@" ;;
  *)
    echo "Usage: $0 {setup|register <user>|register-raw <gid> <attr> [attr ...]|refresh <user>|refresh-raw <gid>|revoke <revocation>|revoke-raw <gid>|prepare-query-dir <gid> <out-dir> [label] <keyword> [keyword ...]|prepare-auth-dir <gid> <out-dir> [label]|serve-http [host] [port]}" >&2
    exit 1
    ;;
esac
