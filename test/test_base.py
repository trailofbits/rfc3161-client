import cryptography.x509
import pytest
from cryptography.hazmat.primitives import hashes

from rfc3161_client.base import HashAlgorithm, TimestampRequestBuilder

SHA512_OID = cryptography.x509.ObjectIdentifier("2.16.840.1.101.3.4.2.3")


class TestRequestBuilder:
    def test_succeeds(self):
        message = b"hello"
        request = TimestampRequestBuilder().data(message).build()
        print(request.nonce)

        assert request.version == 1
        assert request.cert_req is True
        assert request.nonce is not None
        assert request.policy is None

        message_imprint = request.message_imprint
        assert message_imprint.hash_algorithm == SHA512_OID

        digest = hashes.Hash(hashes.SHA512())
        digest.update(message)
        assert digest.finalize() == message_imprint.message

    def test_data(self):
        with pytest.raises(ValueError):
            TimestampRequestBuilder().build()

        with pytest.raises(ValueError, match="empty"):
            TimestampRequestBuilder().data(b"")

        with pytest.raises(ValueError, match="once"):
            TimestampRequestBuilder().data(b"hello").data(b"world")

    def test_set_algorithm(self):
        request = (
            TimestampRequestBuilder().hash_algorithm(HashAlgorithm.SHA512).data(b"hello").build()
        )
        assert request.message_imprint.hash_algorithm == SHA512_OID

        with pytest.raises(TypeError):
            TimestampRequestBuilder().hash_algorithm("invalid hash algorihtm")

        request = TimestampRequestBuilder().data(b"hello").build()
        assert request.message_imprint.hash_algorithm == SHA512_OID

    def test_cert_request(self):
        with pytest.raises(TypeError):
            TimestampRequestBuilder().cert_request(cert_request="not valid")

        request = TimestampRequestBuilder().cert_request(cert_request=False).data(b"hello").build()
        assert request.cert_req is False

        request = TimestampRequestBuilder().cert_request(cert_request=True).data(b"hello").build()
        assert request.cert_req is True

    def test_nonce(self):
        with pytest.raises(TypeError):
            TimestampRequestBuilder().nonce(nonce="not valid")

        request = TimestampRequestBuilder().nonce(nonce=False).data(b"hello").build()
        assert request.nonce is None

        request = TimestampRequestBuilder().nonce(nonce=True).data(b"hello").build()
        nonce = request.nonce
        assert nonce is not None and nonce > 0
