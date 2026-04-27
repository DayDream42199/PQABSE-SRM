#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"
REPO_ROOT="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

usage() {
  cat <<'EOF'
Usage:
  bash ./RunFullSys/bootstrap_amazon_linux_2023.sh <role> [repo-root]

Roles:
  ta
  edge
  cs
  mdu
  mdo
  all

Environment overrides:
  OPENFHE_REF=v1.2.2
  LIBOQS_REF=0.10.1
  INSTALL_PREFIX=/usr/local
  BUILD_JOBS=<nproc>
  SKIP_DEPENDENCY_BUILD=1
  RUN_ROLE_SETUP=1

Examples:
  bash ./RunFullSys/bootstrap_amazon_linux_2023.sh ta /srv/PQABSE-SRM
  bash ./RunFullSys/bootstrap_amazon_linux_2023.sh edge
  RUN_ROLE_SETUP=1 bash ./RunFullSys/bootstrap_amazon_linux_2023.sh cs
EOF
}

if [[ -z "$ROLE" ]]; then
  usage
  exit 1
fi

OPENFHE_REF="${OPENFHE_REF:-v1.2.2}"
LIBOQS_REF="${LIBOQS_REF:-0.10.1}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"
SKIP_DEPENDENCY_BUILD="${SKIP_DEPENDENCY_BUILD:-0}"
RUN_ROLE_SETUP="${RUN_ROLE_SETUP:-0}"
DEPS_ROOT="${REPO_ROOT}/.third_party"

role_dir_for() {
  case "$1" in
    ta) echo "${REPO_ROOT}/RunFullSys/TA+IA+Blockchain" ;;
    edge) echo "${REPO_ROOT}/RunFullSys/Edge node" ;;
    cs) echo "${REPO_ROOT}/RunFullSys/CS" ;;
    mdu) echo "${REPO_ROOT}/RunFullSys/MDU" ;;
    mdo) echo "${REPO_ROOT}/RunFullSys/MDO" ;;
    *) return 1 ;;
  esac
}

system_packages() {
  sudo dnf -y update
  sudo dnf -y install \
    cmake \
    git \
    gcc \
    gcc-c++ \
    make \
    ninja-build \
    python3 \
    python3-pip \
    nodejs \
    npm \
    openssl-devel \
    wget \
    curl \
    tar \
    gzip \
    unzip \
    jq \
    which \
    patch \
    perl
}

build_liboqs() {
  local src_dir="${DEPS_ROOT}/liboqs"
  local build_dir="${src_dir}/build"

  if [[ ! -d "$src_dir/.git" ]]; then
    git clone --branch "${LIBOQS_REF}" --depth 1 https://github.com/open-quantum-safe/liboqs.git "$src_dir"
  fi

  cmake -S "$src_dir" -B "$build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON

  cmake --build "$build_dir" -j "${BUILD_JOBS}"
  sudo cmake --install "$build_dir"
}

build_openfhe() {
  local src_dir="${DEPS_ROOT}/openfhe-development"
  local build_dir="${src_dir}/build"

  if [[ ! -d "$src_dir/.git" ]]; then
    git clone --branch "${OPENFHE_REF}" --depth 1 https://github.com/openfheorg/openfhe-development.git "$src_dir"
  fi

  cmake -S "$src_dir" -B "$build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DBUILD_SHARED=ON \
    -DBUILD_UNITTESTS=OFF \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_BENCHMARKS=OFF

  cmake --build "$build_dir" -j "${BUILD_JOBS}"
  sudo cmake --install "$build_dir"
}

refresh_linker_cache() {
  echo "${INSTALL_PREFIX}/lib" | sudo tee /etc/ld.so.conf.d/pqabse-local.conf >/dev/null
  sudo ldconfig
}

build_role() {
  local role="$1"
  local role_dir
  role_dir="$(role_dir_for "$role")"
  local app_dir="${role_dir}/app"

  if [[ ! -d "$app_dir" ]]; then
    echo "Skipping role '${role}' because ${app_dir} does not exist."
    return 0
  fi

  pushd "$app_dir" >/dev/null
  if [[ -f package-lock.json ]]; then
    npm ci
  elif [[ -f package.json ]]; then
    npm install
  fi
  cmake -S . -B build-wsl
  cmake --build build-wsl -j "${BUILD_JOBS}"
  popd >/dev/null

  if [[ "${RUN_ROLE_SETUP}" == "1" ]]; then
    case "$role" in
      ta) (cd "$role_dir" && bash ./ta_ia_blockchain.sh setup) ;;
      edge) (cd "$role_dir" && bash ./edge_node.sh setup) ;;
      cs) (cd "$role_dir" && bash ./cs.sh setup) ;;
      mdu) (cd "$role_dir" && bash ./mdu.sh setup || true) ;;
      mdo) (cd "$role_dir" && bash ./mdo.sh setup || true) ;;
    esac
  fi
}

main() {
  mkdir -p "$DEPS_ROOT"

  system_packages

  if [[ "${SKIP_DEPENDENCY_BUILD}" != "1" ]]; then
    build_liboqs
    build_openfhe
    refresh_linker_cache
  fi

  case "$ROLE" in
    ta|edge|cs|mdu|mdo)
      build_role "$ROLE"
      ;;
    all)
      build_role ta
      build_role edge
      build_role cs
      build_role mdu
      build_role mdo
      ;;
    *)
      usage
      exit 1
      ;;
  esac

  cat <<EOF

Bootstrap complete.

Role: ${ROLE}
Repo root: ${REPO_ROOT}
Install prefix: ${INSTALL_PREFIX}

If this node is a service node, the next step is usually:

TA:
  cd "${REPO_ROOT}/RunFullSys/TA+IA+Blockchain"
  bash ./ta_ia_blockchain.sh serve-http 0.0.0.0 8081

Edge:
  export PQ_ABSE_TA_URL=http://<TA_HOST>:8081
  export PQ_ABSE_CS_URL=http://<CS_HOST>:8083
  cd "${REPO_ROOT}/RunFullSys/Edge node"
  bash ./edge_node.sh serve-http 0.0.0.0 8082

CS:
  export PQ_ABSE_TA_URL=http://<TA_HOST>:8081
  cd "${REPO_ROOT}/RunFullSys/CS"
  bash ./cs.sh serve-http 0.0.0.0 8083
EOF
}

main "$@"
