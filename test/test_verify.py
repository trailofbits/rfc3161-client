import pytest
from pathlib import Path
import cryptography.hazmat
import cryptography.x509

from sigstore_tsp.base import TimestampRequestBuilder, decode_timestamp_response
from sigstore_tsp.verify import verify_timestamp_response, create_verify_opts



_HERE = Path(__file__).parent.resolve()
_FIXTURE = _HERE / "fixtures"

def test_create_verify_opts():
    request = TimestampRequestBuilder().data(b"hello").build()

    certificates = cryptography.x509.load_pem_x509_certificates(
        (_FIXTURE / "ts_chain.pem").read_bytes()
    )

    verify_opts = create_verify_opts(
        request,
        tsa_certifiate=certificates[0],
        common_name=certificates[0].subject.rfc4514_string(),
        root_certificates=[certificates[-1]],
        intermediates=certificates[1:-1],
    )

    assert verify_opts.nonce == request.nonce
    assert verify_opts.policy_id == request.policy
    assert verify_opts.tsa_certificate == certificates[0]


def test_create_request():

    request = TimestampRequestBuilder().data(b"hello").build()

    assert request.version == 1
    assert request.cert_req is True


def test_verify():

    request = TimestampRequestBuilder().data(b"hello").build()
    response = (_FIXTURE / "response.tsr").read_bytes()
    certificates = cryptography.x509.load_pem_x509_certificates(
        (_FIXTURE / "ts_chain.pem").read_bytes()
    )

    verify_opts = create_verify_opts(
        request,
        tsa_certifiate=certificates[0],
        common_name=certificates[0].subject.rfc4514_string(),
        root_certificates=[certificates[-1]],
    )

    verify_timestamp_response(
        timestamp_response=decode_timestamp_response(response),
        hashed_message=request.message_imprint.message,
        verify_opts=verify_opts,
    )


@pytest.mark.skip(reason="certificate verification fails - to be tested")
def test_pkcs7():
    from cryptography.hazmat.bindings._rust import test_support
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7


    response = (_FIXTURE / "response.tsr").read_bytes()

    tsr = decode_timestamp_response(response)
    time_stamp_token = tsr.time_stamp_token()

    certificates = cryptography.x509.load_pem_x509_certificates(
        (_FIXTURE / "ts_chain.pem").read_bytes()
    )

    options = []

    test_support.pkcs7_verify(
        encoding=Encoding.DER,
        sig =time_stamp_token,
        msg=b"hello",
        certs=certificates,
        options=options,
    )
