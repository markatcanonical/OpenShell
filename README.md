# Navigator

> Navigator is the runtime environment for autonomous agents—the "Matrix" where they live, work, and verify.
>
> While coding tools like Claude help agents write logic, Navigator provides the infrastructure to run it, offering a programmable factory where agents can spin up physics simulations to master tasks, generate synthetic data to fix edge cases, and safely iterate through thousands of failures in isolated sandboxes.
>
> It transforms the data center from a static deployment target into a continuous verification engine, allowing agents to autonomously build and operate complex systems—from physical robotics to self-healing infrastructure—without needing a human to manage the infrastructure.

## Quick Start

### Prerequisites

Install [mise](https://mise.jdx.dev/). This is used to setup the development environment.

```bash
# Install mise (macOS/Linux)
curl https://mise.run | sh
```

After installing `mise` be sure to activate the environment by running `mise activate` or [add it to your shell](https://mise.jdx.dev/getting-started.html).

Project uses Rust 1.85+ and Python 3.12+.

### Getting started

```bash
# Install dependencies and build
mise install

# Build the project
mise build

# Run all project tests
mise test

# Run the cluster agent
mise run server

# Run the CLI, this will build/run the cli from source
nav --help

# Run the sandbox
mise run sandbox

```

## Project Structure

```
crates/
├── navigator-core/      # Core library
├── navigator-server/    # Main gateway server, ingress for all operations
├── navigator-sandbox/   # Sandbox execution environment
└── navigator-cli/       # Command-line interface
python/                  # Python bindings
proto/                   # Protocol buffer definitions
```
