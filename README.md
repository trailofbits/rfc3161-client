# Sigstore-TSP

_Warning: Draft_

`sigstore-tsp` is a Python library implementing the Time-Stamp Protocol (TSP)
described in [RFC 3161](https://www.ietf.org/rfc/rfc3161.txt).

It is composed of two subprojects :

- A Rust crate using [`rust-asn1`](https://docs.rs/asn1/latest/asn1/index.html)
  to expose the various types used by the Time-Stamp protocol.
- A Python library re-using this types to expose them in Python and 
  providing various verifications methods.

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