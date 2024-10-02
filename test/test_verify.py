from pathlib import Path
import cryptography.x509

from sigstore_tsp.base import TimestampRequestBuilder, decode_timestamp_response
from sigstore_tsp.verify import verify_timestamp_response, VerifyOpts, create_verify_opts



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
