# justfile — project command runner. `just` lists all commands,
# `just <name>` runs one (e.g. `just setup`).

set export
set shell := ["bash", "-uc"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
# Needed so shebang recipes see args as $1/$2/$@/$# instead of only
# via {{args}} text substitution, which mangles values containing $.
set positional-arguments

default:
    @just --list --unsorted


# =============================================================================
# Setup
# =============================================================================

# First-time setup — creates .venv and installs everything
[group('setup')]
setup:
    @echo "Creating virtual environment with uv..."
    uv venv --allow-existing
    @echo ""
    @echo "Installing dependencies (including dev tools)..."
    uv sync --all-extras
    @echo ""
    @echo "✓ Setup complete!"
    @echo ""
    @echo "Try it out:"
    @echo "  just run -- --help"
    @echo "  just test"

[group('setup')]
install:
    uv sync

[group('setup')]
install-dev:
    uv sync --all-extras


# =============================================================================
# Run the CLI
# =============================================================================

# Pass extra args after `--`: just run -- list / just run -- add github
# [no-exit-message] suppresses just's own failure line for pv's
# expected non-zero exits (wrong password, entry not found, etc) —
# those are real outcomes the CLI already explained. Exit code still
# propagates to the caller.
[group('run')]
[no-exit-message]
run *args:
    #!/usr/bin/env bash
    if [ $# -eq 0 ]; then
        cat <<'EOF'
    Usage: just run -- <command> [args]

    Examples:
      just run -- list
      just run -- add github
      just run -- get github
      just run -- remove github

    See all commands:
      just run -- --help
    EOF
        exit 0
    fi
    # "$@" (not {{args}}) so bash gets the raw argv — a password with
    # $ in it would otherwise get re-expanded by just's text substitution.
    uv run pv "$@"


# =============================================================================
# Utility / cleanup
# =============================================================================

[group('utility')]
clean:
    rm -rf .venv
    rm -rf __pycache__ src/**/__pycache__ tests/__pycache__
    rm -rf .mypy_cache .ruff_cache .pytest_cache
    rm -rf *.egg-info build dist
    rm -rf .coverage htmlcov
    @echo "✓ Cleaned"

[group('utility')]
lock:
    uv lock

[group('utility')]
update:
    uv lock --upgrade
    uv sync --all-extras


# =============================================================================
# CI
# =============================================================================

# Full pipeline for first-time runs
[group('ci')]
all: setup lint test
    @echo ""
    @echo "✓ Setup, lint, and tests all passed"

# What CI runs once deps are already installed
[group('ci')]
ci: lint test
    @echo "✓ CI checks passed"
