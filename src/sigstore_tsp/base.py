from __future__ import annotations


class TimestampRequestBuilder:
    def __init__(self, data: bytes| None = None, hash_algorithm: None = None, req_policy: None = None, nonce: int | None = None, cert_req : bool = False, extensions: None = None):
        self._data = data
        self._algorithm = hash_algorithm
        self._req_policy = req_policy
        self._nonce = nonce
        self._cert_req = cert_req
        self._extensions = extensions

    def data(self, data: bytes) -> TimestampRequestBuilder:
        if not data:
            raise ValueError("The data to timestamp cannot be empty.")
        if self._data is not None:
            raise ValueError("The data may only be set once.")
        return TimestampRequestBuilder(
            data, self._algorithm, self._req_policy, self._nonce, self._cert_req, self._extensions
        )

    def add_extension(self, extension: None) -> TimestampRequestBuilder:
        raise NotImplemented("Adding extensions is not yet supported.")

    def build(self):
        raise NotImplemented("Building is not yet supported.")