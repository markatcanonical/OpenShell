#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build a Ubuntu rootfs for the openshell-vm microVM (Legacy macOS Builder).
# This script produces a lightweight rootfs (~200-300MB) without K3s.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

_CE_SEARCH="${PROJECT_ROOT}/tasks/scripts/container-engine.sh"
if [ -f "${_CE_SEARCH}" ]; then
    source "${_CE_SEARCH}"
fi

PINS_FILE="${SCRIPT_DIR}/../pins.env"
if [ -f "$PINS_FILE" ]; then
    source "$PINS_FILE"
fi

POSITIONAL_ARGS=()
GUEST_ARCH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            shift ;; # ignored, all builds are base now
        --arch)
            GUEST_ARCH="$2"; shift 2 ;;
        *)
            POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done

if [ -z "$GUEST_ARCH" ]; then
    case "$(uname -m)" in
        aarch64|arm64) GUEST_ARCH="aarch64" ;;
        x86_64)        GUEST_ARCH="x86_64" ;;
        *)
            echo "ERROR: Unsupported host architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
fi

case "$GUEST_ARCH" in
    aarch64) DOCKER_PLATFORM="linux/arm64"; RUST_TARGET="aarch64-unknown-linux-gnu" ;;
    x86_64)  DOCKER_PLATFORM="linux/amd64"; RUST_TARGET="x86_64-unknown-linux-gnu" ;;
    *) exit 1 ;;
esac

DEFAULT_ROOTFS="${PROJECT_ROOT}/target/rootfs-build"
ROOTFS_DIR="${POSITIONAL_ARGS[0]:-${DEFAULT_ROOTFS}}"
CONTAINER_NAME="krun-rootfs-builder"
BASE_IMAGE_TAG="krun-rootfs:openshell-vm"

echo "==> Building base openshell-vm rootfs"
echo "    Guest arch:  ${GUEST_ARCH}"
echo "    Output:      ${ROOTFS_DIR}"

ensure_build_nofile_limit() {
    [ "$(uname -s)" = "Darwin" ] || return 0
    local desired=8192
    ulimit -n "${desired}" 2>/dev/null || true
}
ensure_build_nofile_limit

VM_LOCK_FILE="$(dirname "${ROOTFS_DIR}")/$(basename "${ROOTFS_DIR}")-vm.lock"
if [ -f "${VM_LOCK_FILE}" ]; then
    echo "ERROR: An openshell-vm holds a lock on this rootfs."
    exit 1
fi

ce rm -f "${CONTAINER_NAME}" 2>/dev/null || true

echo "==> Building base image..."
ce build --platform "${DOCKER_PLATFORM}" -t "${BASE_IMAGE_TAG}" \
    --build-arg "BASE_IMAGE=${VM_BASE_IMAGE}" -f - . <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates e2fsprogs iptables iproute2 \
        python3 busybox-static sqlite3 util-linux zstd curl \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /usr/share/udhcpc && ln -sf /bin/busybox /sbin/udhcpc
DOCKERFILE

echo "==> Exporting filesystem..."
if [ -d "${ROOTFS_DIR}" ]; then
    chmod -R u+rwx "${ROOTFS_DIR}" 2>/dev/null || true
    rm -rf "${ROOTFS_DIR}"
fi
mkdir -p "${ROOTFS_DIR}"
ce create --platform "${DOCKER_PLATFORM}" --name "${CONTAINER_NAME}" "${BASE_IMAGE_TAG}" /bin/true
ce export "${CONTAINER_NAME}" | tar -C "${ROOTFS_DIR}" -xf -
ce rm "${CONTAINER_NAME}"

echo "==> Injecting scripts..."
mkdir -p "${ROOTFS_DIR}/srv"
cp "${SCRIPT_DIR}/openshell-vm-init.sh" "${ROOTFS_DIR}/srv/openshell-vm-init.sh"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-init.sh"
cp "${SCRIPT_DIR}/check-vm-capabilities.sh" "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"
chmod +x "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"

SUPERVISOR_TARGET="${RUST_TARGET}"
SUPERVISOR_BIN="${PROJECT_ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"

echo "==> Building openshell-sandbox supervisor binary (${SUPERVISOR_TARGET})..."
if command -v cargo-zigbuild >/dev/null 2>&1; then
    cargo zigbuild --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" --manifest-path "${PROJECT_ROOT}/Cargo.toml"
else
    cargo build --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" --manifest-path "${PROJECT_ROOT}/Cargo.toml"
fi

if [ ! -f "${SUPERVISOR_BIN}" ]; then
    echo "ERROR: supervisor binary not found at ${SUPERVISOR_BIN}"
    exit 1
fi

echo "    Injecting supervisor binary into rootfs..."
mkdir -p "${ROOTFS_DIR}/opt/openshell/bin"
cp "${SUPERVISOR_BIN}" "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"
chmod +x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"

echo "base" > "${ROOTFS_DIR}/opt/openshell/.rootfs-type"

echo "==> Base rootfs ready at: ${ROOTFS_DIR}"
exit 0
