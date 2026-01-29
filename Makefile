SHELL := /bin/bash

PY_IMPORT = rfc3161_client

ALL_PY_SRCS := $(shell find src -name '*.py') \
		$(shell find test -name '*.py')

# Optionally overridden by the user in the `release` target.
BUMP_ARGS :=

# Optionally overridden by the user in the `test` target.
TESTS :=

# If the user selects a specific test pattern to run, set `pytest` to fail fast
# and only run tests that match the pattern.
# Otherwise, run all tests and enable coverage assertions, since we expect
# complete test coverage.
ifneq ($(TESTS),)
	TEST_ARGS := -x -k $(TESTS)
	COV_ARGS :=
else
	TEST_ARGS :=
	COV_ARGS := --fail-under 100
endif

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	uv sync --group dev
	uv run maturin develop --uv

.PHONY: lint
lint:
	uv sync --group lint
	uv run ruff format --check && \
		uv run ruff check && \
		cargo fmt --check --manifest-path rust/Cargo.toml && \
		cargo fmt --check --manifest-path rust/tsp-asn1/Cargo.toml && \
		uv run interrogate -c pyproject.toml . && \
		uv run ty check

.PHONY: reformat
reformat:
	uv sync --group lint
	uv run ruff format  && \
		uv run ruff check --fix  && \
		cargo fmt --manifest-path rust/Cargo.toml  && \
		cargo fmt --manifest-path rust/tsp-asn1/Cargo.toml

.PHONY: doc
doc:
	@echo "No documentation set up"


.PHONY: test tests
test tests:
	uv sync --group test
	uv run pytest --cov=$(PY_IMPORT) $(T) $(TEST_ARGS) && \
		uv run coverage report -m $(COV_ARGS)  && \
		cargo test --manifest-path rust/Cargo.toml  && \
		cargo test --manifest-path rust/tsp-asn1/Cargo.toml
