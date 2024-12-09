# `rfc3161-client`

> [!WARNING]
> This project is currently in beta. While it is already being used in
> production by downstream projects, we reserve the right to make breaking
> changes to the API. We recommend pinning to specific versions until we reach
> a stable 1.0 release.


`rfc3161-client` is a Python library implementing the Time-Stamp Protocol (TSP)
described in [RFC 3161](https://www.ietf.org/rfc/rfc3161.txt).

It is composed of three subprojects:

- [:crab: tsp-asn1](./rust/tsp-asn1/Cargo.toml): A Rust crate using 
  [`rust-asn1`](https://docs.rs/asn1/latest/asn1/index.html) to create the 
  types used by the Time-Stamp protocol. This crate depends on `rust-asn1` 
  and `cryptography` to minimize the amount of duplicated code. While
  it is usable as a standalone crate, this is not officially supported. Drop
  us a message if you are interested in using it.
- [:crab: rfc3161-client](./rust/Cargo.toml): Another Rust crate that
  provides Python bindings to the `tsp-asn1` crate using PyO3.
- [:snake: rfc3161-client](./pyproject.toml) A Python library using the
  crate above to provide a usable API to create Timestamp Request and read
  Timestamp Response.

# Goals and anti-goals

- This library should be correct and provide an accurate implementation of
  protocol described in the RFC 3161.
- This library does not perform any network activity, it simply provides
  primitive to build and verify objects. Network activity must be handled
  separately.

# License

Apache 2.0

# Authors

Trail of Bits
