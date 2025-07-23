from datetime import datetime

def pkcs7_verify(
    sig: bytes,
    verification_time: datetime,
    certs: list[bytes],
) -> None: ...