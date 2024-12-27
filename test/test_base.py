import pytest
from cryptography.hazmat.primitives import hashes

from rfc3161_client.base import HashAlgorithm, TimestampRequestBuilder

from .common import SHA256_OID, SHA512_OID


class TestRequestBuilder:
    def test_succeeds(self) -> None:
        message = b"hello"
        request = TimestampRequestBuilder().data(message).build()
        print(request.nonce)

        assert request.version == 1
        assert request.cert_req is True
        assert request.nonce is not None
        assert request.policy is None

    def test_data(self) -> None:
        with pytest.raises(ValueError):
            TimestampRequestBuilder().build()

        with pytest.raises(ValueError, match="empty"):
            TimestampRequestBuilder().data(b"")

        with pytest.raises(ValueError, match="once"):
            TimestampRequestBuilder().data(b"hello").data(b"world")

    def test_algorithm_sha256(self) -> None:
        message = b"random-message"
        request = (
            TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA256).build()
        )
        assert request.message_imprint.hash_algorithm == SHA256_OID

        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        assert digest.finalize() == request.message_imprint.message

    def test_algorithm_sha512(self) -> None:
        message = b"random-message"
        request = (
            TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA512).build()
        )
        assert request.message_imprint.hash_algorithm == SHA512_OID

        digest = hashes.Hash(hashes.SHA512())
        digest.update(message)
        assert digest.finalize() == request.message_imprint.message

    def test_set_algorithm(self) -> None:
        with pytest.raises(TypeError):
            TimestampRequestBuilder().hash_algorithm("invalid hash algorihtm")

        # Default hash algorithm
        request = TimestampRequestBuilder().data(b"hello").build()
        assert request.message_imprint.hash_algorithm == SHA512_OID

    def test_cert_request(self) -> None:
        with pytest.raises(TypeError):
            TimestampRequestBuilder().cert_request(cert_request="not valid")

        request = TimestampRequestBuilder().cert_request(cert_request=False).data(b"hello").build()
        assert request.cert_req is False

        request = TimestampRequestBuilder().cert_request(cert_request=True).data(b"hello").build()
        assert request.cert_req is True

    def test_nonce(self) -> None:
        with pytest.raises(TypeError):
            TimestampRequestBuilder().nonce(nonce="not valid")

        request = TimestampRequestBuilder().nonce(nonce=False).data(b"hello").build()
        assert request.nonce is None

        request = TimestampRequestBuilder().nonce(nonce=True).data(b"hello").build()
        nonce = request.nonce
        assert nonce is not None and nonce > 0
