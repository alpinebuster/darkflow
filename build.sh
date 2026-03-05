#!/usr/bin/env bash

set -e

echo "========== Building eBPF programs =========="

cargo xtask ebpf-ipv4
cargo xtask ebpf-ipv6

# Release builds
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release

echo "========== Building user space programs =========="

cargo build

# Release build
cargo build --release

echo "========== Done =========="
