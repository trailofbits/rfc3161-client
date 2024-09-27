class MessageImprint:
    """Represents a Message Imprint (per RFC 3161)."""
    @property
    def hash_algorithm(self) -> ObjectIdentifier:
        """Returns the Object Identifier of the Hash algorithm used."""
        ...

    @property
    def message(self) -> bytes:
        """Return the hashed message."""
        ...


class TimeStampRequest:
    """Represents a Timestamp Request (per RFC 3161)."""

    @property
    def version(self) -> int:
        """Returns the version of the Timestamp Request."""
        ...

    @property
    def nonce(self) -> int:
        """Returns the nonce generated for this request."""
        ...

    @property
    def policy(self) -> ObjectIdentifier:
        """Returns the request policy OID."""
        ...
    
    @property
    def cert_req(self) -> bool:
        """Is the certificate request present."""
        ...

    @property
    def message_imprint(self) -> MessageImprint:
        """Returns the Timestamp Request Message Imprint."""
        ...

    def as_bytes(self) -> bytes: 
        """Returns the Timestamp Request as bytes."""
        ...
        


def create_timestamp_request(
    data: bytes,
) -> TimeStampRequest: ...


class TimeStampResponse:
    @property
    def status(self) -> int: ...

    @property
    def tst_info_version(self) -> int: ...

    @property
    def tst_info_nonce(self) -> int: ...

    @property
    def tst_info_policy(self) -> ObjectIdentifier: ...

def parse_timestamp_response(
    data: bytes,
) -> TimeStampResponse: ...

class ObjectIdentifier:
    @property
    def dotted_string(self) -> str:...