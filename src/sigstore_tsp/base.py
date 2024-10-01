"""Base implementation."""

from __future__ import annotations

import enum

from sigstore_tsp import _rust, tsp


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
        req_policy: None | int = None,
        cert_req: bool = False,  # noqa: FBT001, FBT002
        extensions: None = None,
    ) -> None:
        """Init method."""
        self._data: bytes | None = data
        self._algorithm: _AllowedHashTypes | None = hash_algorithm
        self._req_policy = req_policy
        self._cert_req: bool = cert_req
        self._extensions = extensions

    def data(self, data: bytes) -> TimestampRequestBuilder:
        """Set the data to be timestamped."""
        if not data:
            msg = "The data to timestamp cannot be empty."
            raise ValueError(msg)
        if self._data is not None:
            msg = "The data may only be set once."
            raise ValueError(msg)
        return TimestampRequestBuilder(
            data, self._algorithm, self._req_policy, self._cert_req, self._extensions
        )

    def add_extension(self, _extension: None) -> TimestampRequestBuilder:
        """Add an extension."""
        msg = "Adding extensions is not yet supported."
        raise NotImplementedError(msg)

    def hash_algorithm(self, hash_algorihtm: _AllowedHashTypes) -> TimestampRequestBuilder:
        """Set the Hash algorithm used."""
        if hash_algorihtm not in HashAlgorithm:
            msg = f"{hash_algorihtm} is not a supported hash."
            raise TypeError(msg)

        return TimestampRequestBuilder(
            self._data, hash_algorihtm, self._req_policy, self._cert_req, self._extensions
        )

    def cert_request(self, *, cert_request: bool = False) -> TimestampRequestBuilder:
        """Set the cert request field."""
        if not isinstance(cert_request, bool):
            msg = "Cert request must be a boolean."
            raise TypeError(msg)

        return TimestampRequestBuilder(
            self._data, self._algorithm, self._req_policy, cert_request, self._extensions
        )

    def request_policy(self, request_policy: int) -> TimestampRequestBuilder:
        """Set the request policy field."""
        if not isinstance(request_policy, int):
            msg = "Request policy must be an integer."
            raise TypeError(msg)

        return TimestampRequestBuilder(
            self._data, self._algorithm, request_policy, self._cert_req, self._extensions
        )

    def build(self) -> tsp.TimeStampRequest:
        """Build a TimestampRequest."""
        if self._data is None:
            msg = "Data must be for a Timestamp Request."
            raise ValueError(msg)

        if self._algorithm is None:
            self._algorithm = HashAlgorithm.SHA512

        return _rust.create_timestamp_request(self._data)


def decode_timestamp_response(data: bytes) -> tsp.TimeStampResponse:
    """Decode a Timestamp response."""
    return _rust.parse_timestamp_response(data)
