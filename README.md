# `rfc3161-client`

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

# Usage

There are two parts to timestamping: retrieving + verifying the timestamp.

### 1. Retrieving a timestamp

The below code uses `requests` to get the timestamp from the Identrust TSA server:

```{python}

import requests
from rfc3161_client import (
    decode_timestamp_response,
    TimestampRequestBuilder,
    TimeStampResponse,
    VerifierBuilder,
    VerificationError,
)

# the data to sign. Could be a hash or any message. Should be bytes
message = b"Hello, World!"

# build the timestamp request
timestamp_request = (
    TimestampRequestBuilder().data(message).nonce(nonce=True).build()
    # Note: you could also add .hash_algorithm(XXX) to specify a specific hash algorithm
    # this means the algorithm check in the next section is not necessary
)

# TSA servers must be RFC 3161 compliant (see https://github.com/trailofbits/rfc3161-client/issues/46
# for a list of working clients)
tsa_server = "http://timestamp.identrust.com"

# make the request, remember to set content-type headers appropriately
response = requests.post(
    tsa_server,
    data=timestamp_request.as_bytes(),
    headers={"Content-Type": "application/timestamp-query"},
)
response.raise_for_status()

# if successful, should give a valid TimeStampResponse object
timestamp_response: TimeStampResponse = decode_timestamp_response(response.content)

```

### Verifying a timestamp

The second part is to verify the timestamp, this is done against a set of
root certificates. In this example, we'll Mozilla's list of root certs
provided in the  `certifi` package:

```{python}

import certifi
from cryptography import x509
import hashlib

# first get the timestamp certificate chain + intermediates
# NOTE: certs must be ordered correctly, so you may need to reorder
timestamp_certs = [
    x509.load_der_x509_certificate(c) for c in timestamp_response.signed_data.certificates
]
intermediate_certs = timestamp_certs[1:-1]

# get the message hash (hash method depends on what the TSA used)
message_hash = None
hash_algorithm = timestamp_response.tst_info.message_imprint.hash_algorithm
if hash_algorithm == x509.ObjectIdentifier(value="2.16.840.1.101.3.4.2.3"):
    message_hash = hashlib.sha512(message).digest()
elif hash_algorithm == x509.ObjectIdentifier(value="2.16.840.1.101.3.4.2.1"):
    message_hash = hashlib.sha256(message).digest()

# get trusted root certs from certifi
with open(certifi.where(), "rb") as f:
    cert_authorities = x509.load_pem_x509_certificates(f.read())

# for each of the root certs we have, try to verify the TSR with it
root_cert = None
for certificate in cert_authorities:
    builder = VerifierBuilder()
    builder.add_root_certificate(certificate)

    for cert in intermediate_certs:
        builder.add_intermediate_certificate(cert)

    verifier = builder.build()
    try:
        verifier.verify(timestamp_response, message_hash)
        root_cert = certificate
        break
    except VerificationError:
        continue

# if successful, the TSR was verified and we should have the root cert that signed this TSR :)
print("Here's the root cert that signed your TSR:")
print(root_cert)

```

# License

```
Copyright 2024 Trail of Bits

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

# Authors

Trail of Bits
