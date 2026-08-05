#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========== Running setup =========="
bash "$SCRIPT_DIR/setup.sh"

echo "========== Running build =========="
bash "$SCRIPT_DIR/build.sh"

echo "========== All done =========="
