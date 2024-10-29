from pathlib import Path

import cryptography.hazmat
import cryptography.x509
import pretend
import pytest
from cryptography.hazmat.primitives import hashes

from rfc3161_client._rust import parse_timestamp_request
from rfc3161_client.base import decode_timestamp_response
from rfc3161_client.errors import VerificationError
from rfc3161_client.tsp import TimeStampRequest, TimeStampResponse
from rfc3161_client.verify import Verifier, VerifyBuilder

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
def verifier(
    ts_request: TimeStampRequest, certificates: list[cryptography.x509.Certificate]
) -> Verifier:
    builder = VerifyBuilder.from_request(ts_request)
    builder = (
        builder.tsa_certificate(certificates[0])
        .common_name(certificates[0].subject.rfc4514_string())
        .add_root_certificate(certificates[-1])
    )
    for intermediate in certificates[1:-1]:
        builder = builder.add_intermediate_certificate(intermediate)
    return builder.build()


class TestVerifierBuilder:
    def test_succeeds(self):
        verifier = VerifyBuilder().build()
        assert verifier._policy_id is None
        assert verifier._tsa_certificate is None
        assert verifier._intermediates == []
        assert verifier._roots == []
        assert verifier._nonce is None
        assert verifier._common_name is None

    def test_policy_id(self):
        with pytest.raises(ValueError, match="type is not valid"):
            VerifyBuilder().policy_id("wrong-type")

        with pytest.raises(ValueError, match="only once"):
            VerifyBuilder().policy_id(cryptography.x509.ObjectIdentifier("1.2")).policy_id(
                cryptography.x509.ObjectIdentifier("1.3")
            )

        oid = cryptography.x509.ObjectIdentifier("1.2")
        verifier = VerifyBuilder().policy_id(oid).build()
        assert verifier._policy_id == oid

    def test_tsa_certificate(self, certificates):
        with pytest.raises(ValueError, match="type is not valid"):
            VerifyBuilder().tsa_certificate("wrong-type")

        with pytest.raises(ValueError, match="only once"):
            VerifyBuilder().tsa_certificate(certificates[0]).tsa_certificate(certificates[1])

        verifier = VerifyBuilder().tsa_certificate(certificates[0]).build()
        assert verifier._tsa_certificate == certificates[0]

    def test_add_intermediate_certificate(self, certificates):
        with pytest.raises(ValueError, match="type is not valid"):
            VerifyBuilder().add_intermediate_certificate("wrong-type")

        with pytest.raises(ValueError, match="already present"):
            VerifyBuilder().add_intermediate_certificate(
                certificates[0]
            ).add_intermediate_certificate(certificates[0])

        verifier = (
            VerifyBuilder()
            .add_intermediate_certificate(certificates[0])
            .add_intermediate_certificate(certificates[1])
            .build()
        )
        assert verifier._intermediates == [certificates[0], certificates[1]]

    def test_add_root_certificate(self, certificates):
        with pytest.raises(ValueError, match="type is not valid"):
            VerifyBuilder().add_root_certificate("wrong-type")

        with pytest.raises(ValueError, match="already present"):
            VerifyBuilder().add_root_certificate(certificates[0]).add_root_certificate(
                certificates[0]
            )

        verifier = (
            VerifyBuilder()
            .add_root_certificate(certificates[0])
            .add_root_certificate(certificates[1])
            .build()
        )
        assert verifier._roots == [certificates[0], certificates[1]]

    def test_nonce(self):
        with pytest.raises(ValueError, match="negative"):
            VerifyBuilder().nonce(-2)

        with pytest.raises(ValueError, match="only once"):
            VerifyBuilder().nonce(0xABCD).nonce(0xCAFE)

        verifier = VerifyBuilder().nonce(0xABCD).build()
        assert verifier._nonce == 0xABCD

    def test_common_name(self):
        with pytest.raises(ValueError, match="only once"):
            VerifyBuilder().common_name("foo").common_name("bar")

        verifier = VerifyBuilder().common_name("foo").build()
        assert verifier._common_name == "foo"


class TestVerifier:
    def test_verify_tsr_with_chains(self, ts_response: TimeStampResponse, verifier: Verifier):
        assert verifier._verify_tsr_with_chains(ts_response) is True

    def test_verify_tsr_with_chains_without_roots(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ):
        verifier._roots = []
        with pytest.raises(VerificationError, match="No roots"):
            verifier._verify_tsr_with_chains(ts_response)

    def test_verify_tsr_with_chains_without_certs(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ):
        with pytest.raises(VerificationError, match="Error while verifying"):
            verifier._verify_tsr_with_chains(
                pretend.stub(
                    signed_data=ts_response.signed_data,
                    time_stamp_token=lambda: b"",
                )
            )

    def test_verify_tsr_with_chains_without_signer(
        self,
        verifier: Verifier,
    ):
        with pytest.raises(VerificationError, match="0 signer infos"):
            verifier._verify_tsr_with_chains(
                pretend.stub(signed_data=pretend.stub(signer_infos=[]))
            )

    def test_verify_wrong_status(self, verifier: Verifier):
        with pytest.raises(VerificationError, match="GRANTED"):
            verifier.verify(pretend.stub(status=2), b"")

    def test_verify_wrong_nonce(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch
    ):
        verifier._nonce = 0xABCD
        with pytest.raises(VerificationError, match="Nonce mismatch"):
            verifier.verify(ts_response, b"")

    def test_verify_wrong_policy_oid(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch
    ):
        verifier._policy_id = cryptography.x509.ObjectIdentifier("1.1")
        with pytest.raises(VerificationError, match="Policy ID mismatch"):
            verifier.verify(ts_response, b"")

    def test_verify_wrong_message(self, ts_response: TimeStampResponse, verifier: Verifier):
        with pytest.raises(VerificationError, match="messages"):
            verifier.verify(ts_response, b"not-the-correct-message")

    def test_verify_succeeds(self, ts_response: TimeStampResponse, verifier: Verifier):
        digest = hashes.Hash(hashes.SHA512())
        digest.update(b"hello")  # This is used in scripts/update_fixtures.py
        message = digest.finalize()

        assert (
            verifier.verify(
                timestamp_response=ts_response,
                hashed_message=message,
            )
            is True
        )
