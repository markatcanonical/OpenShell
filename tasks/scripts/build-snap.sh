#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COMPRESSED="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-$ROOT/target/vm-runtime-compressed}"

# ── Stage 1: VM runtime ────────────────────────────────────────────────
# Download (or build) the libkrun / gvproxy runtime and build the base
# rootfs tarball so that openshell-driver-vm embeds real artifacts instead
# of empty stubs.

if ! find "$COMPRESSED" -maxdepth 1 -name 'libkrun*.zst' 2>/dev/null | grep -q .; then
    echo "==> Setting up VM runtime (download pre-built)..."
    tasks/scripts/vm/vm-setup.sh
fi

if [ ! -f "$COMPRESSED/rootfs.tar.zst" ]; then
    echo "==> Building base VM rootfs tarball..."
    tasks/scripts/vm/build-rootfs-tarball.sh --base
    # compress-vm-runtime picks up the tarball automatically
    tasks/scripts/vm/compress-vm-runtime.sh
fi

# Copy compressed artifacts for the snapcraft build environment
echo "==> Staging compressed VM runtime for snap build..."
mkdir -p snap/local-vm-runtime
cp "$COMPRESSED"/*.zst snap/local-vm-runtime/

# Pre-extract runtime libraries + gvproxy into the snap so they live
# under $SNAP/ where AppArmor grants mmap-exec permission (strict
# confinement blocks dlopen from $SNAP_DATA / $SNAP_COMMON).
echo "==> Pre-extracting VM runtime for snap inclusion..."
mkdir -p snap/local-vm-runtime-extracted
for f in libkrun.so libkrunfw.so.5 gvproxy; do
    src="$COMPRESSED/${f}.zst"
    if [ -f "$src" ]; then
        zstd -d -f "$src" -o "snap/local-vm-runtime-extracted/$f"
    fi
done
# macOS dylib variants (harmless no-op on Linux-only builds)
for f in libkrun.dylib libkrunfw.5.dylib; do
    src="$COMPRESSED/${f}.zst"
    if [ -f "$src" ]; then
        zstd -d -f "$src" -o "snap/local-vm-runtime-extracted/$f"
    fi
done
chmod 755 snap/local-vm-runtime-extracted/gvproxy 2>/dev/null || true

# Fail-fast: verify critical files are present and non-empty
echo "==> Validating VM runtime artifacts..."
fail=0
for f in snap/local-vm-runtime/rootfs.tar.zst; do
    if [ ! -s "$f" ]; then
        echo "FATAL: Missing or empty: $f" >&2
        fail=1
    fi
done
# Check for at least one platform's libkrun
if ! find snap/local-vm-runtime-extracted -maxdepth 1 \( -name 'libkrun.so' -o -name 'libkrun.dylib' \) -size +0c 2>/dev/null | grep -q .; then
    echo "FATAL: No libkrun shared library found in snap/local-vm-runtime-extracted/" >&2
    fail=1
fi
if [ ! -s "snap/local-vm-runtime-extracted/gvproxy" ]; then
    echo "FATAL: Missing or empty: snap/local-vm-runtime-extracted/gvproxy" >&2
    fail=1
fi
if [ "$fail" -eq 1 ]; then
    echo "" >&2
    echo "Snap build aborted: VM runtime artifacts are incomplete." >&2
    echo "Try: mise run vm:setup && mise run vm:rootfs -- --base" >&2
    exit 1
fi

# ── Stage 2: ROCK image (for k8s driver path) ─────────────────────────
echo "==> Building OpenShell Core ROCK (Gateway + Supervisor)..."
rm -f openshell-core_*_*.rock
rockcraft pack

echo "==> Exporting ROCK to snap/local-images..."
mkdir -p snap/local-images
cp openshell-core*.rock snap/local-images/openshell-core.rock

# ── Stage 3: Snap package ─────────────────────────────────────────────
echo "==> Building Snap package..."
rm -f openshell_*_*.snap
# If arguments are passed (like --build-for), forward them to snapcraft
if [ $# -eq 0 ]; then
    snapcraft pack
else
    snapcraft pack "$@"
fi
