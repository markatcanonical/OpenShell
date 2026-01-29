# Contributing to Navigator

## Prerequisites

- **mise** - Task runner ([install guide](https://mise.jdx.dev/getting-started.html))

## Setup

See README.md for setup instructions.

## Development Workflow

### Building

```bash
mise run build           # Debug build
mise run build:release   # Release build
mise run check           # Quick compile check
```

### Testing

```bash
mise run test            # All tests (Rust + Python)
mise run test:rust       # Rust tests only
mise run test:python     # Python tests only
```

### Linting & Formatting

```bash
# Rust
mise run fmt             # Format code
mise run fmt:check       # Check formatting
mise run clippy          # Run Clippy lints

# Python
mise run python:fmt      # Format with ruff
mise run python:lint     # Lint with ruff
mise run python:typecheck # Type check with ty
```

### Running Components

```bash
mise run server          # Start the server
mise run cli -- --help   # Run CLI with arguments
mise run sandbox         # Run sandbox
```

## Code Style

- **Rust**: Formatted with `rustfmt`, linted with Clippy (pedantic + nursery)
- **Python**: Formatted and linted with `ruff`, type-checked with `mypy --strict`

Run `mise run all` before committing to check everything.

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes with tests
3. Run `mise run all` to verify
4. Open a PR with a clear description

Use the `create-gitlab-mr` skill to help with opening your pull request.
