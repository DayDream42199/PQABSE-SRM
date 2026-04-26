#!/usr/bin/env bash
set -e  # stop on error

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wslRepo="/home/chees/Work/ABSE"

cd "$wslRepo"

rm -rf build
mkdir build
cd build

cmake ..
cmake --build . -j2

./phase1_setup
./phase1_verify
./phase2_keygen
./phase3_encrypt
./phase4_search