# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## Fixed

- Fixed spelling of `hash_algorithm` parameter in `TimestampRequestBuilder` class ([131](https://github.com/trailofbits/rfc3161-client/pull/131))

## [1.0.1] - 2025-03-24

### Fixed

- The Verifier now enforces that the EKU (Extended Key Usage) explicitly includes the `id-kp-timeStamping` OID ([#120](https://github.com/trailofbits/rfc3161-client/pull/120))

- The Verifier now searches for the leaf certificate in the Timestamp Response instead of using the first one provided ([#121](https://github.com/trailofbits/rfc3161-client/pull/121))

## [1.0.0] - 2024-12-31

## Added

- `TimestampRequest` now accepts setting the hash algorithm to `SHA256` (in addition to `SHA512`)
  ([93](https://github.com/trailofbits/rfc3161-client/pull/93))

## [0.1.2] - 2024-12-11

### Changed

- Moved `maturin` dependency from main project dependencies to development dependencies
  since it's only needed for development tasks ([88](https://github.com/trailofbits/rfc3161-client/pull/88))

- Relax cryptography version requirement ([91](https://github.com/trailofbits/rfc3161-client/pull/91))

### Fixed

- The project now correctly runs tests with PyPy
  ([89](https://github.com/trailofbits/rfc3161-client/pull/89))

## [0.1.1] - 2024-12-10

### Changed

- `rfc3161-client` release `0.1.0` was previously published and yanked on PyPI, preventing
  republication ([85](https://github.com/trailofbits/rfc3161-client/pull/85))

## [0.1.0] - 2024-12-10

### Changed

- `rfc3161-client` is now in beta ([82](https://github.com/trailofbits/rfc3161-client/pull/82)).

## [0.0.5] - 2024-12-02

### Changed

- The minimum version of `cryptography` required is now `44`
  ([#75](https://github.com/trailofbits/rfc3161-client/pull/75))

## [0.0.4] - 2024-11-20

### Added

- TimestampResponse now has a `as_bytes` method to retrieve the original
  request bytes ([#62](https://github.com/trailofbits/rfc3161-client/pull/62))

## [0.0.3] - 2024-11-06

### Added

- Magic method (`__eq__` and `__repr__`) has been added for TimestampResponse
  and TimestampRequest ([#48](https://github.com/trailofbits/rfc3161-client/pull/48))

### Fixed

- The CI now correctly builds wheels for Windows
  ([49](https://github.com/trailofbits/rfc3161-client/pull/49))

## [0.0.2] - 2024-10-30

### Added

- Magic methods (`__hash__` and `__repr__`) have been added for
  TimestampResponse and TimestampRequest ([#32](https://github.com/trailofbits/rfc3161-client/pull/32))
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

[Unreleased]: https://github.com/trailofbits/rfc3161-client/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/trailofbits/rfc3161-client/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/trailofbits/rfc3161-client/compare/v0.1.2...v1.0.0
[0.1.2]: https://github.com/trailofbits/rfc3161-client/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/trailofbits/rfc3161-client/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.5...v0.1.0
[0.0.4]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/trailofbits/rfc3161-client/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/trailofbits/rfc3161-client/releases/tag/v0.0.1
