#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Ensure the rock is staged before building the snap
if [ ! -f snap/local-images/openshell-core.rock ]; then
    echo "ERROR: openshell-core.rock not found in snap/local-images/"
    echo "Please run ./tasks/scripts/build-rock.sh first."
    exit 1
fi

echo "==> Building Snap package..."
rm -f openshell_*_*.snap
# If arguments are passed (like --build-for), forward them to snapcraft
if [ $# -eq 0 ]; then
    snapcraft pack
else
    snapcraft pack "$@"
fi
