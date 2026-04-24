# Walkthrough of OpenShell snap

This branch packages OpenShell as a snap with VM-based sandboxes (libkrun microVMs) as the default driver.

## Prerequisites

```shell
sudo snap install snapcraft --classic
sudo snap install rockcraft --classic
```

Docker (or a compatible container runtime) is required for `rockcraft pack` and the rootfs build.

## Build

The build script downloads the VM runtime, builds the rootfs, creates the ROCK container image, and packages the snap:

```shell
./tasks/scripts/build-snap.sh
```

This produces `openshell_<version>_<arch>.snap` in the repository root.

## Install

Since the snap is locally built (unsigned), install with `--dangerous`:

```shell
sudo snap install ./openshell_*.snap --dangerous
```

### Connect required interfaces

The `kvm` interface provides `/dev/kvm` access for microVMs. It does **not** auto-connect:

```shell
sudo snap connect openshell:kvm
```

If you also use the k8s driver or `openshell cluster` commands:

```shell
sudo snap connect openshell:kube-config
```

### Verify connections

```shell
snap connections openshell
```

Expected output:

```
Interface       Plug                      Slot             Notes
kvm             openshell:kvm             :kvm             manual
network         openshell:network         :network         -
network-bind    openshell:network-bind    :network-bind    -
personal-files  openshell:kube-config     :personal-files  manual
```

## Configure

The snap exposes settings via `snap set`:

```shell
# Driver: "vm" (default) or "k8s"
sudo snap set openshell driver=vm

# Gateway port (default 8080)
sudo snap set openshell port=8080

# UDS socket group and permissions
sudo snap set openshell socket-group=docker socket-mode=0660
```

## Use (VM mode)

```shell
# Check the gateway daemon is running
sudo snap services openshell.server

# View logs
sudo snap logs openshell.server -f

# Create a sandbox
openshell sandbox create
```

## Use (K8s mode)

```shell
sudo snap install k8s --classic --channel=1.35-classic
sudo k8s bootstrap
sudo k8s status --wait-ready
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $USER:$USER $HOME/.kube/config

sudo snap install registry
sudo snap set openshell driver=k8s registry=localhost:5000

openshell sandbox create
```

## Troubleshooting

### Daemon won't start

```shell
# Check service status and logs
sudo snap services openshell.server
sudo snap logs openshell.server -n 50

# Verify KVM access
sudo snap connect openshell:kvm
ls -la /dev/kvm
```

### "cannot open /dev/kvm" error

The `kvm` interface must be connected:

```shell
sudo snap connect openshell:kvm
sudo snap restart openshell.server
```

### Sandbox creation fails

Check that the gateway is healthy:

```shell
sudo snap logs openshell.server -f
```

Look for driver startup messages. The VM driver extracts a rootfs on first sandbox creation — this can take a few seconds.
