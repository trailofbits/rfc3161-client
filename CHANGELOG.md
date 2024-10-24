# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Magic methods (`__hash__` and `__repr__`) for TimestampResponse and 
  TimestampRequest ( [#32](https://github.com/trailofbits/rfc3161-client/pull/32) )

### Fixed

- The version is correctly sourced from `pyproject.toml` ( [#30](https://github.com/trailofbits/rfc3161-client/pull/30) )
- The nonce generation no longer fails ( [#33](https://github.com/trailofbits/rfc3161-client/pull/33) )

### Changed

- The CI no longer limit the MacOS jobs ( [#28](https://github.com/trailofbits/rfc3161-client/pull/28) )
- The public API is available directly from the main package module ( [#36](https://github.com/trailofbits/rfc3161-client/pull/36) )

## [0.0.1] - 2024-10-18

This is the first alpha release of `rfc3161-client`.