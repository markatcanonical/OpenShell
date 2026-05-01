#! /bin/sh

# Build all crafted assets - VM root filesystem, OCI, and snap.

./tasks/scripts/vm/build-rockcraft-rootfs.sh
./tasks/scripts/build-rock.sh
./tasks/scripts/build-snap.sh

