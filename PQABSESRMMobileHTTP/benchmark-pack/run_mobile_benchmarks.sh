#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-all}"
KEYWORD_COUNTS="${KEYWORD_COUNTS:-10,50,300,500}"
RUNS="${RUNS:-5}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-4096}"
WARMUP_RUNS="${WARMUP_RUNS:-30}"
INCLUDE_DECRYPTION="${INCLUDE_DECRYPTION:-true}"
OUTPUT_SUBDIR="${OUTPUT_SUBDIR:-benchmark-pack}"
FIXTURE_DIR="${FIXTURE_DIR:-}"
ADB="${ADB:-adb}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGE_NAME="com.example.pqabse_srmmobilehttp"
RUNNER="androidx.test.runner.AndroidJUnitRunner"
RESULT_DIR="$SCRIPT_DIR/results"
RESOLVED_FIXTURE_DIR="${FIXTURE_DIR:-$SCRIPT_DIR/fixtures}"

mkdir -p "$RESULT_DIR"

pull_device_file() {
  local device_path="$1"
  local local_path="$2"
  if "$ADB" shell "test -f '$device_path'"; then
    mkdir -p "$(dirname "$local_path")"
    "$ADB" exec-out cat "$device_path" > "$local_path"
  else
    echo "Device file not found: $device_path" >&2
  fi
}

cd "$PROJECT_DIR"
"$ADB" wait-for-device
bash ./gradlew :app:installDebug :app:installDebugAndroidTest

if [[ -d "$RESOLVED_FIXTURE_DIR" ]]; then
  DEVICE_FIXTURE_DIR="/sdcard/Android/data/$PACKAGE_NAME/files/$OUTPUT_SUBDIR/fixtures"
  "$ADB" shell "rm -rf '$DEVICE_FIXTURE_DIR'"
  "$ADB" shell "mkdir -p '$DEVICE_FIXTURE_DIR'"
  "$ADB" push "$RESOLVED_FIXTURE_DIR/." "$DEVICE_FIXTURE_DIR"
fi

"$ADB" shell am instrument -w \
  -e class "com.example.pqabse_srmmobilehttp.MobileBenchmarkPackInstrumentedTest#runBenchmarkPack" \
  -e benchmarkMode "$MODE" \
  -e keywordCounts "$KEYWORD_COUNTS" \
  -e runs "$RUNS" \
  -e payloadBytes "$PAYLOAD_BYTES" \
  -e warmupRuns "$WARMUP_RUNS" \
  -e includeDecryption "$INCLUDE_DECRYPTION" \
  -e outputSubdir "$OUTPUT_SUBDIR" \
  "$PACKAGE_NAME.test/$RUNNER"

DEVICE_ROOT="/sdcard/Android/data/$PACKAGE_NAME/files/$OUTPUT_SUBDIR"
pull_device_file "$DEVICE_ROOT/native_status.txt" "$RESULT_DIR/native_status.txt"

for suite in payload_mobile_primitives reference_mobile_primitives native_fixture_primitives; do
  pull_device_file "$DEVICE_ROOT/$suite/${suite}_raw.csv" "$RESULT_DIR/$suite/${suite}_raw.csv"
  pull_device_file "$DEVICE_ROOT/$suite/${suite}_averages.csv" "$RESULT_DIR/$suite/${suite}_averages.csv"
done

echo "Benchmark results: $RESULT_DIR"
