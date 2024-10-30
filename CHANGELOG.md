# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.0.2] - 2024-10-30

### Added

- Magic methods (`__hash__` and `__repr__`) have been added for TimestampResponse and 
  TimestampRequest ([#32](https://github.com/trailofbits/rfc3161-client/pull/32))
- `VerifierBuilder` is now the only way to create a `Verifier` ([#35](https://github.com/trailofbits/rfc3161-client/pull/35))

### Fixed

- The version is now correctly sourced from `pyproject.toml` ([#30](https://github.com/trailofbits/rfc3161-client/pull/30))
- The nonce generation no longer fails sporadically ([#33](https://github.com/trailofbits/rfc3161-client/pull/33))
- `Accuracy` now correctly accepts valid inputs and enforce range invariants ([#43](https://github.com/trailofbits/rfc3161-client/pull/43))
- Fixes a bug in how `TSTInfo` was parsed ([#45](https://github.com/trailofbits/rfc3161-client/pull/45))

### Changed

- The public API is now available directly from the main package module ([#36](https://github.com/trailofbits/rfc3161-client/pull/36))

## [0.0.1] - 2024-10-18

This is the first alpha release of `rfc3161-client`.

[Unreleased]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/trailofbits/rfc3161-client/releases/tag/v0.0.2
[0.0.1]: https://github.com/trailofbits/rfc3161-client/releases/tag/v0.0.1
