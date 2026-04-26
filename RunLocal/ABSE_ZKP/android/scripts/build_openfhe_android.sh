#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  cat <<'EOF' >&2
Usage:
  ./build_openfhe_android.sh <openfhe-source-dir> <android-ndk-dir> <abi> [api-level]

Example:
  ./build_openfhe_android.sh ~/src/openfhe-development ~/Android/Sdk/ndk/29.0.13113456 arm64-v8a 28
EOF
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENFHE_SRC="$(cd "$1" && pwd)"
ANDROID_NDK="$(cd "$2" && pwd)"
ABI="$3"
API_LEVEL="${4:-28}"

BUILD_DIR="$ANDROID_ROOT/build/openfhe/${ABI}"
INSTALL_DIR="$ANDROID_ROOT/prebuilt/${ABI}"
TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

echo "Configuring OpenFHE for Android ABI: $ABI"
echo "Source:  $OPENFHE_SRC"
echo "Build:   $BUILD_DIR"
echo "Install: $INSTALL_DIR"

cmake -S "$OPENFHE_SRC" -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-${API_LEVEL}" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DBUILD_SHARED=OFF \
  -DBUILD_STATIC=ON \
  -DBUILD_UNITTESTS=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_BENCHMARKS=OFF

cmake --build "$BUILD_DIR" -j"$(nproc)"
cmake --install "$BUILD_DIR"

cat <<EOF

OpenFHE Android build finished for ${ABI}.

Expected next checks:
  1. Confirm headers exist under:
     ${INSTALL_DIR}/include
  2. Confirm the required OpenFHE core libraries exist under:
     ${INSTALL_DIR}/lib
  3. Validate whether additional OpenFHE components beyond OPENFHEcore are needed by ABSE_ZKP.

EOF
