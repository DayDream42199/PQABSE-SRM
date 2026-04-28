#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  cat <<'EOF' >&2
Usage:
  ./build_liboqs_android.sh <liboqs-source-dir> <android-ndk-dir> <abi> [api-level]

Example:
  ./build_liboqs_android.sh ~/src/liboqs ~/Android/Sdk/ndk/29.0.13113456 arm64-v8a 28
EOF
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ANDROID_ROOT/.." && pwd)"

LIBOQS_SRC="$(cd "$1" && pwd)"
ANDROID_NDK="$(cd "$2" && pwd)"
ABI="$3"
API_LEVEL="${4:-28}"

BUILD_DIR="$ANDROID_ROOT/build/liboqs/${ABI}"
INSTALL_DIR="$ANDROID_ROOT/prebuilt/${ABI}"
TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

echo "Configuring liboqs for Android ABI: $ABI"
echo "Source:  $LIBOQS_SRC"
echo "Build:   $BUILD_DIR"
echo "Install: $INSTALL_DIR"

cmake -S "$LIBOQS_SRC" -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-${API_LEVEL}" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=ON

cmake --build "$BUILD_DIR" -j"$(nproc)"
cmake --install "$BUILD_DIR"

cat <<EOF

liboqs Android build finished for ${ABI}.

Expected next checks:
  1. Confirm headers exist under:
     ${INSTALL_DIR}/include
  2. Confirm static library exists under:
     ${INSTALL_DIR}/lib
  3. Verify the required algorithms are enabled for Android builds.

Repo root:
  ${REPO_ROOT}
EOF
