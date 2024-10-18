from pathlib import Path

import cryptography.hazmat
import cryptography.x509
import pretend
import pytest
from cryptography.hazmat.primitives import hashes

from rfc3161_client._rust import parse_timestamp_request
from rfc3161_client.base import TimestampRequestBuilder, decode_timestamp_response
from rfc3161_client.errors import VerificationError
from rfc3161_client.tsp import TimeStampRequest, TimeStampResponse
from rfc3161_client.verify import (
    VerifyOpts,
    _verify_tsr_with_chains,
    create_verify_opts,
    verify_timestamp_response,
)

_HERE = Path(__file__).parent.resolve()
_FIXTURE = _HERE / "fixtures"


@pytest.fixture
def certificates() -> list[cryptography.x509.Certificate]:
    return cryptography.x509.load_pem_x509_certificates((_FIXTURE / "ts_chain.pem").read_bytes())


@pytest.fixture
def ts_request() -> TimeStampRequest:
    return parse_timestamp_request((_FIXTURE / "request.der").read_bytes())


@pytest.fixture
def ts_response() -> TimeStampResponse:
    return decode_timestamp_response((_FIXTURE / "response.tsr").read_bytes())


@pytest.fixture
def verify_opts(
    certificates: list[cryptography.x509.Certificate], ts_request: TimeStampRequest
) -> VerifyOpts:
    return create_verify_opts(
        ts_request,
        tsa_certificate=certificates[0],
        common_name=certificates[0].subject.rfc4514_string(),
        root_certificates=[certificates[-1]],
        intermediates=certificates[1:-1],
    )


class TestVerifyOpts:
    @pytest.fixture
    def ts_request(self) -> TimeStampRequest:
        return TimestampRequestBuilder().data(b"hello").build()

    def test_create_verify_opts(
        self, ts_request: TimeStampRequest, certificates: list[cryptography.x509.Certificate]
    ):
        verify_opts = create_verify_opts(
            ts_request,
            tsa_certificate=certificates[0],
            common_name=certificates[0].subject.rfc4514_string(),
            root_certificates=[certificates[-1]],
            intermediates=certificates[1:-1],
        )

        assert verify_opts.nonce == ts_request.nonce
        assert verify_opts.policy_id == ts_request.policy
        assert verify_opts.tsa_certificate == certificates[0]

    def test_without_certificates(
        self, ts_request: TimeStampRequest, certificates: list[cryptography.x509.Certificate]
    ):
        verify_opts = create_verify_opts(
            ts_request,
            tsa_certificate=certificates[0],
            common_name=certificates[0].subject.rfc4514_string(),
            root_certificates=None,
            intermediates=None,
        )

        assert verify_opts.roots == []
        assert verify_opts.intermediates == []


def test_verify_tsr_with_chains(ts_response: TimeStampResponse, verify_opts: VerifyOpts):
    assert _verify_tsr_with_chains(ts_response, verify_opts) is True


def test_verify_tsr_with_chains_without_roots(
    ts_response: TimeStampResponse, verify_opts: VerifyOpts
):
    verify_opts.roots = []
    with pytest.raises(VerificationError, match="No roots"):
        _verify_tsr_with_chains(ts_response, verify_opts)


def test_verify_tsr_with_chains_without_certs(
    ts_response: TimeStampResponse, verify_opts: VerifyOpts
):
    with pytest.raises(VerificationError, match="Error while verifying"):
        _verify_tsr_with_chains(
            pretend.stub(
                signed_data=ts_response.signed_data,
                time_stamp_token=lambda: b"",
            ),
            verify_opts,
        )


def test_verify_tsr_with_chains_without_signer(verify_opts: VerifyOpts):
    with pytest.raises(VerificationError, match="0 signer infos"):
        _verify_tsr_with_chains(
            pretend.stub(signed_data=pretend.stub(signer_infos=[])), verify_opts
        )


def test_verify(ts_response: TimeStampResponse, verify_opts: VerifyOpts):
    digest = hashes.Hash(hashes.SHA512())
    digest.update(b"hello")  # This is used in scripts/update_fixtures.py
    message = digest.finalize()

    verify_timestamp_response(
        timestamp_response=ts_response,
        hashed_message=message,
        verify_opts=verify_opts,
    )
