"""Base implementation."""

from __future__ import annotations

import enum

from rfc3161_client import _rust, tsp
from rfc3161_client._rust import verify as _rust_verify


class HashAlgorithm(enum.Enum):
    """Hash algorithms."""

    SHA512 = "SHA512"


_AllowedHashTypes = HashAlgorithm


class TimestampRequestBuilder:
    """Timestamp Request Builder class."""

    def __init__(
        self,
        data: bytes | None = None,
        hash_algorithm: _AllowedHashTypes | None = None,
        nonce: bool = True,
        cert_req: bool = True,
    ) -> None:
        """Init method."""
        self._data: bytes | None = data
        self._algorithm: _AllowedHashTypes | None = hash_algorithm
        self._nonce: bool = nonce
        self._cert_req: bool = cert_req

    def data(self, data: bytes) -> TimestampRequestBuilder:
        """Set the data to be timestamped."""
        if not data:
            msg = "The data to timestamp cannot be empty."
            raise ValueError(msg)
        if self._data is not None:
            msg = "The data may only be set once."
            raise ValueError(msg)
        return TimestampRequestBuilder(data, self._algorithm, self._nonce, self._cert_req)

    def hash_algorithm(self, hash_algorihtm: _AllowedHashTypes) -> TimestampRequestBuilder:
        """Set the Hash algorithm used."""
        if hash_algorihtm not in HashAlgorithm:
            msg = f"{hash_algorihtm} is not a supported hash."
            raise TypeError(msg)

        return TimestampRequestBuilder(self._data, hash_algorihtm, self._nonce, self._cert_req)

    def cert_request(self, *, cert_request: bool = False) -> TimestampRequestBuilder:
        """Set the cert request field."""
        if not isinstance(cert_request, bool):
            msg = "Cert request must be a boolean."
            raise TypeError(msg)

        return TimestampRequestBuilder(self._data, self._algorithm, self._nonce, cert_request)

    def nonce(self, *, nonce: bool = True) -> TimestampRequestBuilder:
        """Set the request policy field."""
        if not isinstance(nonce, bool):
            msg = "Request policy must be a boolean."
            raise TypeError(msg)

        return TimestampRequestBuilder(self._data, self._algorithm, nonce, self._cert_req)

    def build(self) -> tsp.TimeStampRequest:
        """Build a TimestampRequest."""
        if self._data is None:
            msg = "Data must be for a Timestamp Request."
            raise ValueError(msg)

        if self._algorithm is None:
            self._algorithm = HashAlgorithm.SHA512

        return _rust.create_timestamp_request(
            data=self._data,
            nonce=self._nonce,
            cert=self._cert_req,
        )


def decode_timestamp_response(data: bytes) -> tsp.TimeStampResponse:
    """Decode a Timestamp response."""
    return _rust.parse_timestamp_response(data)


def verify_signed_data(sig: bytes, certificates: set[bytes]) -> None:
    """Verify signed data.

    This function verify that the bytes used a signature are signed by a certificate
    trusted in the `certificates` list.
    The function does not return anything, but raises an exception if the verification fails.

    :param sig: Bytes of a PKCS7 object. This must be in DER format and will be unserialized.
    :param certificates: A list of trusted certificates to verify the response against.
    :raise: ValueError if the signature verification fails.
    """
    return _rust_verify.pkcs7_verify(sig, list(certificates))