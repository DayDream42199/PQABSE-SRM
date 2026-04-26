#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build-wsl"
RUNTIME_DIR="$ROOT_DIR/runtime"
ZK_RUNTIME_DIR="$ROOT_DIR/zk/build/runtime_cpp"
SCENARIO_PATH="$ROOT_DIR/config/test_demo_1.conf"
BLOCKCHAIN_CONF="$ROOT_DIR/config/blockchain.local.conf"
FRESH=0

if [[ "${1:-}" == "--fresh" ]]; then
  FRESH=1
fi

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "Missing build directory: $BUILD_DIR" >&2
  echo "Build first with: cmake -S . -B build-wsl && cmake --build build-wsl -j"$(nproc)"" >&2
  exit 1
fi

ORIGINAL_BLOCKCHAIN_CONF="$(cat "$BLOCKCHAIN_CONF")"
restore_blockchain_conf() {
  printf '%s\n' "$ORIGINAL_BLOCKCHAIN_CONF" > "$BLOCKCHAIN_CONF"
}
trap restore_blockchain_conf EXIT
ROOT_DIR_ENV="$ROOT_DIR" python3 - <<'PY'
import os
from pathlib import Path
path = Path(os.environ['ROOT_DIR_ENV']) / 'config' / 'blockchain.local.conf'
lines = []
for line in path.read_text().splitlines():
    if line.startswith('contract_address='):
        lines.append('contract_address=')
    else:
        lines.append(line)
path.write_text('\n'.join(lines) + '\n')
PY

if [[ $FRESH -eq 1 ]]; then
  rm -rf "$RUNTIME_DIR" "$ZK_RUNTIME_DIR"
  echo "Removed existing runtime and ZK cache state for a fresh demo run."
elif [[ -d "$RUNTIME_DIR/users" || -d "$RUNTIME_DIR/state" || -d "$RUNTIME_DIR/ciphertexts" ]]; then
  cat <<'EOF'
Existing runtime state detected.

If you want a clean demo run, use:
  ./test_demo_1.sh --fresh

Or manually run:
  rm -rf /home/chees/Work/ABSE_ZKP/runtime
EOF
  echo
fi

cd "$BUILD_DIR"

echo "[1/9] phase1_setup"
./phase1_setup

echo
echo "[2/9] phase2_keygen Alice"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Alice

echo
echo "[3/9] phase2_keygen Bob"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Bob

echo
echo "[4/9] phase3_encrypt demo1"
./phase3_encrypt --scenario "$SCENARIO_PATH" --bundle demo1

echo
echo "[5/9] phase4_search Bob before revocation"
./phase4_search --scenario "$SCENARIO_PATH" --query bob_before_revoke

echo
echo "[6/9] phase5_revoke Alice"
./phase5_revoke --scenario "$SCENARIO_PATH" --revocation revoke_alice

echo
echo "[7/9] phase2_keygen Bob refresh"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Bob --refresh-existing

echo
echo "[8/9] phase4_search Bob after revocation"
./phase4_search --scenario "$SCENARIO_PATH" --query bob_after_revoke

echo
echo "[9/9] phase4_search Alice after revocation (expected to fail)"
set +e
alice_output="$(./phase4_search --scenario "$SCENARIO_PATH" --query alice_after_revoke 2>&1)"
status=$?
set -e
printf '%s\n' "$alice_output"
if [[ $status -eq 0 ]]; then
  echo "Unexpected success: Alice should be blocked after revocation." >&2
  exit 1
fi

echo
echo "Demo completed successfully. Bob refreshed key material and Alice was correctly blocked after revocation."
