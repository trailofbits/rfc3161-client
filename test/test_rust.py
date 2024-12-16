from rfc3161_client._rust import create_timestamp_request
from rfc3161_client.base import HashAlgorithm

from .common import SHA256_OID, SHA512_OID


def test_create_timestamp_request():
    request = create_timestamp_request(
        data=b"hello", nonce=True, cert=False, hash_algorithm=HashAlgorithm.SHA512
    )

    assert request.message_imprint.hash_algorithm == SHA512_OID

    # Optional parameter
    request = create_timestamp_request(data=b"hello", nonce=True, cert=True)
    assert request.message_imprint.hash_algorithm == SHA512_OID

    request = create_timestamp_request(
        data=b"hello", nonce=True, cert=True, hash_algorithm=HashAlgorithm.SHA256
    )
    assert request.message_imprint.hash_algorithm == SHA256_OID
