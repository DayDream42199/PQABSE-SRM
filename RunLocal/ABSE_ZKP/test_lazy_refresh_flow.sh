#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/build-wsl"
RUNTIME_DIR="$ROOT_DIR/runtime"
ZK_RUNTIME_DIR="$ROOT_DIR/zk/build/runtime_cpp"
SCENARIO_PATH="$ROOT_DIR/config/test_demo_1.conf"
BLOCKCHAIN_CONF="$ROOT_DIR/config/blockchain.local.conf"
BUNDLE_META="$RUNTIME_DIR/ciphertexts/demo1_bundle.meta"

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "Missing build directory: $BUILD_DIR" >&2
  echo "Build first with: cmake -S . -B build-wsl && cmake --build build-wsl -j$(nproc)" >&2
  exit 1
fi

ORIGINAL_BLOCKCHAIN_CONF="$(cat "$BLOCKCHAIN_CONF")"
restore_blockchain_conf() {
  printf '%s
' "$ORIGINAL_BLOCKCHAIN_CONF" > "$BLOCKCHAIN_CONF"
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

rm -rf "$RUNTIME_DIR" "$ZK_RUNTIME_DIR"
echo "Removed existing runtime and ZK cache state for a fresh lazy-refresh test run."

assert_meta() {
  local expected_epoch="$1"
  local expected_reencrypted="$2"
  if [[ ! -f "$BUNDLE_META" ]]; then
    echo "Missing bundle metadata: $BUNDLE_META" >&2
    exit 1
  fi
  local actual_epoch
  local actual_reencrypted
  actual_epoch="$(grep '^epoch=' "$BUNDLE_META" | cut -d= -f2-)"
  actual_reencrypted="$(grep '^is_reencrypted=' "$BUNDLE_META" | cut -d= -f2-)"
  if [[ "$actual_epoch" != "$expected_epoch" || "$actual_reencrypted" != "$expected_reencrypted" ]]; then
    echo "Unexpected bundle metadata state." >&2
    echo "Expected epoch=$expected_epoch is_reencrypted=$expected_reencrypted" >&2
    echo "Actual metadata:" >&2
    cat "$BUNDLE_META" >&2
    exit 1
  fi
}

cd "$BUILD_DIR"

echo "[1/10] phase1_setup"
./phase1_setup

echo
echo "[2/10] phase2_keygen Alice"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Alice

echo
echo "[3/10] phase2_keygen Bob"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Bob

echo
echo "[4/10] phase3_encrypt demo1"
./phase3_encrypt --scenario "$SCENARIO_PATH" --bundle demo1

initial_epoch="$(grep '^epoch=' "$BUNDLE_META" | cut -d= -f2-)"
assert_meta "$initial_epoch" 0

echo
echo "[5/10] phase5_revoke Alice"
./phase5_revoke --scenario "$SCENARIO_PATH" --revocation revoke_alice

echo "Checking that revocation alone did not eagerly upgrade the bundle..."
assert_meta "$initial_epoch" 0

echo
echo "[6/10] phase4_search Bob after revoke without refresh (expected to fail)"
set +e
stale_output="$(./phase4_search --scenario "$SCENARIO_PATH" --query bob_after_revoke 2>&1)"
stale_status=$?
set -e
printf '%s
' "$stale_output"
if [[ $stale_status -eq 0 ]]; then
  echo "Unexpected success: Bob should require key refresh before access." >&2
  exit 1
fi
if [[ "$stale_output" != *"User key update required for user Bob"* ]]; then
  echo "Unexpected failure mode for stale Bob access." >&2
  exit 1
fi

echo
echo "[7/10] phase2_keygen Bob refresh"
./phase2_keygen --scenario "$SCENARIO_PATH" --user Bob --refresh-existing

echo
echo "[8/10] phase4_search Bob after refresh (should trigger lazy re-encryption and succeed)"
refresh_output="$(./phase4_search --scenario "$SCENARIO_PATH" --query bob_after_revoke 2>&1)"
printf '%s
' "$refresh_output"
if [[ "$refresh_output" != *"Plaintext:"* || "$refresh_output" != *"hello_pq_world"* ]]; then
  echo "Bob refresh flow did not recover the expected plaintext." >&2
  exit 1
fi

echo "Checking that Bob's access upgraded the stale bundle just in time..."
next_epoch=$((initial_epoch + 1))
assert_meta "$next_epoch" 1

echo
echo "[9/10] phase4_search Alice after revocation (expected to fail)"
set +e
alice_output="$(./phase4_search --scenario "$SCENARIO_PATH" --query alice_after_revoke 2>&1)"
alice_status=$?
set -e
printf '%s
' "$alice_output"
if [[ $alice_status -eq 0 ]]; then
  echo "Unexpected success: Alice should be blocked after revocation." >&2
  exit 1
fi

echo
echo "[10/10] Final bundle metadata"
cat "$BUNDLE_META"

echo
echo "Lazy refresh regression passed: stale bundle stayed old after revoke, Bob refresh triggered on-access re-encryption, and Alice remained blocked."
