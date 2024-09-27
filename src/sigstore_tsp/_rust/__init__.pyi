class TimeStampRequest:
    @property
    def nonce(self) -> int: ...

    @property
    def version(self) -> int: ...

    @property
    def policy(self) -> ObjectIdentifier: ...

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