#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc 2>/dev/null || echo 2)"

echo
printf '%s\n' 'Build completed successfully.'
printf '%s\n' 'Run: ./build/crypto_rgr'
