#!/usr/bin/env bash

set -e

echo "========== Installing system dependencies =========="

# libpcap development headers
sudo apt update
sudo apt install -y libpcap-dev curl build-essential pkg-config


echo "========== Installing Rust (rustup) =========="

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
else
  echo "Rustup already installed, skipping."
fi


echo "========== Installing Rust toolchains =========="

rustup install stable
rustup toolchain install nightly --component rust-src
rustup default stable


echo "========== Installing bpf-linker =========="

ARCH="$(uname -m)"
OS="$(uname -s)"

if [[ "$OS" == "Linux" && "$ARCH" == "x86_64" ]]; then
  cargo install bpf-linker || echo "bpf-linker already installed"
else
  echo "Non-x86_64 or non-Linux detected."
  echo "Installing llvm and bpf-linker without default features."

  # macOS or other architectures
  if command -v brew >/dev/null 2>&1; then
    brew install llvm
  else
    echo "Homebrew not found. Please install llvm manually."
  fi

  cargo install --no-default-features bpf-linker || echo "bpf-linker already installed"
fi


echo "========== Ubuntu 20.04 specific linux-tools (optional) =========="

VMLINUX_DIR="/usr/lib/linux-tools/5.8.0-63-generic"

if [[ -d "$VMLINUX_DIR" ]]; then
  export PATH="$VMLINUX_DIR:$PATH"
  echo "Added $VMLINUX_DIR to PATH"
else
  echo "linux-tools-5.8.0-63-generic not found."
  echo "If you are on Ubuntu 20.04, you may need:"
  echo "  sudo apt install linux-tools-5.8.0-63-generic"
fi

echo "========== Setup completed =========="
