# rfc3161-client Development Guide

RFC 3161 Time-Stamp Protocol client library. Python package with Rust bindings for ASN.1 encoding.

## Project Structure

```
src/rfc3161_client/     # Python package
rust/                   # PyO3 bindings (Cargo.toml)
rust/tsp-asn1/          # ASN.1 types crate
test/                   # pytest suite with real TSA fixtures
```

## Quick Reference

| Task | Command |
|------|---------|
| Setup dev environment | `make dev` |
| Run all checks | `make lint` |
| Run tests | `make test` |
| Run specific test | `make test TESTS=test_verify` |
| Auto-fix formatting | `make reformat` |

## Quality Gates (All Enforced in CI)

- **100% test coverage** - pytest fails below this
- **100% docstring coverage** - interrogate enforces
- **100% type coverage** - ty --strict on src/ and test/
- **Rust formatting** - cargo fmt on both crates

## Development Workflow

1. `make dev` - Builds Rust extension with maturin
2. Make changes
3. `make lint` - Must pass before committing
4. `make test` - Run full test suite

## Build System

This is a **maturin** project:
- Python wheel built from Rust via PyO3
- ABI3 stable for Python ≥3.9
- Rust workspace with 2 crates: `rust/` (bindings) and `rust/tsp-asn1/` (ASN.1 types)

## Python Tooling

| Purpose | Tool |
|---------|------|
| Package management | `uv` |
| Lint & format | `ruff` (100-char lines, target py39) |
| Type checking | `ty --strict` |
| Docstring coverage | `interrogate` |
| Tests | `pytest` with `--fail-under 100` |

## Rust Tooling

| Purpose | Command |
|---------|---------|
| Format | `cargo fmt` (run on both crates) |
| Test | `cargo test` |
| Build for dev | `maturin develop --uv` |

Rust version: 1.81.0 (pinned in CI)

## Key Dependencies

**Python:**
- `cryptography>=43` - X.509/crypto primitives
- `maturin>=1.7` - Rust extension building

**Rust:**
- `pyo3` - Python bindings
- `asn1` - ASN.1 encoding
- `cryptography-x509` - X.509 types (git dependency from pyca/cryptography)

## Test Fixtures

Real TSA responses in `test/fixtures/`:
- `identrust/` - Commercial TSA
- `sigstage/` - Sigstore staging
- `sigstore.mock/` - Mock responses
- `test_tsa/` - Test server

## CI Matrix

- **Python:** 3.9, 3.10, 3.11, 3.12, 3.13, PyPy
- **Platforms:** Ubuntu, macOS (Intel + ARM), Windows
- **Wheels:** Linux (x86_64, x86, aarch64, armv7), musllinux, Windows, macOS

## Code Patterns

- Builder pattern: `TimestampRequestBuilder`, `VerifierBuilder`
- Rust types exposed via `rfc3161_client._rust` module
- Type stubs in `_rust.pyi` for IDE support
- `TYPE_CHECKING` blocks to avoid circular imports

## Adding Dependencies

Python deps go in `pyproject.toml` under appropriate group:
- Runtime: `dependencies`
- Tests: `dependency-groups.test`
- Lint: `dependency-groups.lint`
- Dev: `dependency-groups.dev`

Rust deps go in workspace `Cargo.toml` or crate-specific `Cargo.toml`.
