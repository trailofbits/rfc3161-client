from pathlib import Path

import cryptography.hazmat
import cryptography.x509
import pretend
import pytest
from cryptography.hazmat.primitives import hashes
from pytest import MonkeyPatch

import rfc3161_client
from rfc3161_client._rust import parse_timestamp_request
from rfc3161_client.base import decode_timestamp_response
from rfc3161_client.errors import VerificationError
from rfc3161_client.tsp import TimeStampRequest, TimeStampResponse
from rfc3161_client.verify import Verifier, VerifierBuilder

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
    builder = VerifierBuilder.from_request(ts_request)
    builder = (
        builder.tsa_certificate(certificates[0])
        .common_name(certificates[0].subject.rfc4514_string())
        .add_root_certificate(certificates[-1])
    )
    for intermediate in certificates[1:-1]:
        builder = builder.add_intermediate_certificate(intermediate)
    return builder.build()


class TestVerifierBuilder:
    @pytest.fixture
    def verifier_builder(
        self, certificates: list[cryptography.x509.Certificate]
    ) -> VerifierBuilder:
        return VerifierBuilder().add_root_certificate(certificates[-1])

    def test_succeeds(self, certificates: list[cryptography.x509.Certificate]) -> None:
        verifier = VerifierBuilder().add_root_certificate(certificates[-1]).build()
        assert verifier._policy_id is None
        assert verifier._tsa_certificate is None
        assert verifier._intermediates == []
        assert verifier._roots == [certificates[-1]]
        assert verifier._nonce is None
        assert verifier._common_name is None

    def test_policy_id(self, verifier_builder: VerifierBuilder) -> None:
        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().policy_id(cryptography.x509.ObjectIdentifier("1.2")).policy_id(
                cryptography.x509.ObjectIdentifier("1.3")
            )

        oid = cryptography.x509.ObjectIdentifier("1.2")
        verifier = verifier_builder.policy_id(oid).build()
        assert verifier._policy_id == oid

    def test_tsa_certificate(
        self, verifier_builder: VerifierBuilder, certificates: list[cryptography.x509.Certificate]
    ) -> None:
        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().tsa_certificate(certificates[0]).tsa_certificate(certificates[1])

        verifier = verifier_builder.tsa_certificate(certificates[0]).build()
        assert verifier._tsa_certificate == certificates[0]

    def test_add_intermediate_certificate(
        self, verifier_builder: VerifierBuilder, certificates: list[cryptography.x509.Certificate]
    ) -> None:
        with pytest.raises(ValueError, match="already present"):
            VerifierBuilder().add_intermediate_certificate(
                certificates[0]
            ).add_intermediate_certificate(certificates[0])

        verifier = (
            verifier_builder.add_intermediate_certificate(certificates[0])
            .add_intermediate_certificate(certificates[1])
            .build()
        )
        assert verifier._intermediates == [certificates[0], certificates[1]]

    def test_add_root_certificate(self, certificates: list[cryptography.x509.Certificate]) -> None:
        with pytest.raises(ValueError, match="already present"):
            VerifierBuilder().add_root_certificate(certificates[0]).add_root_certificate(
                certificates[0]
            )

        with pytest.raises(ValueError, match="at least"):
            VerifierBuilder().build()

        verifier = (
            VerifierBuilder()
            .add_root_certificate(certificates[0])
            .add_root_certificate(certificates[1])
            .build()
        )
        assert verifier._roots == [certificates[0], certificates[1]]

    def test_nonce(self, verifier_builder: VerifierBuilder) -> None:
        with pytest.raises(ValueError, match="negative"):
            VerifierBuilder().nonce(-2)

        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().nonce(0xABCD).nonce(0xCAFE)

        verifier = verifier_builder.nonce(0xABCD).build()
        assert verifier._nonce == 0xABCD

    def test_common_name(self, verifier_builder: VerifierBuilder) -> None:
        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().common_name("foo").common_name("bar")

        verifier = verifier_builder.common_name("foo").build()
        assert verifier._common_name == "foo"


class TestVerifier:
    def test_verify_tsr_with_chains(
        self, ts_response: TimeStampResponse, verifier: Verifier
    ) -> None:
        assert verifier._verify_tsr_with_chains(ts_response) is True

    def test_verify_tsr_with_chains_without_roots(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ) -> None:
        verifier._roots = []
        with pytest.raises(VerificationError, match="No roots"):
            verifier._verify_tsr_with_chains(ts_response)

    def test_verify_tsr_with_chains_without_certs(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ) -> None:
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
    ) -> None:
        with pytest.raises(VerificationError, match="0 signer infos"):
            verifier._verify_tsr_with_chains(
                pretend.stub(signed_data=pretend.stub(signer_infos=[]))
            )

    def test_verify_leaf_certs_no_certs(self, verifier: Verifier) -> None:
        verifier._tsa_certificate = None
        response = pretend.stub(signed_data=pretend.stub(certificates=[]))
        with pytest.raises(VerificationError, match="Certificates neither"):
            verifier._verify_leaf_certs(tsp_response=response)

    def test_verify_leaf_certs_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        verifier._tsa_certificate = "fake-certificate"
        with pytest.raises(VerificationError, match="Embedded certificate"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_update_cert(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rfc3161_client._rust.SignedData, "certificates", [])
        assert verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_no_eku(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cryptography.x509.Certificate, "extensions", [])
        with pytest.raises(
            VerificationError, match="The certificate does not contain the critical EKU extension"
        ):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_cert_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        verifier._tsa_certificate = pretend.stub(
            __ne__=lambda *args: False,
            issuer=None,
        )
        with pytest.raises(
            VerificationError, match="The certificate details does not match the one provided"
        ):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_name_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        verifier._common_name = "fake-name"
        with pytest.raises(VerificationError, match="The name provided in the opts does not match"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_wrong_status(self, verifier: Verifier) -> None:
        with pytest.raises(VerificationError, match="GRANTED"):
            verifier.verify(pretend.stub(status=2), b"")

    def test_verify_wrong_nonce(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch: MonkeyPatch
    ) -> None:
        verifier._nonce = 0xABCD
        with pytest.raises(VerificationError, match="Nonce mismatch"):
            verifier.verify(ts_response, b"")

    def test_verify_wrong_policy_oid(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch: MonkeyPatch
    ) -> None:
        verifier._policy_id = cryptography.x509.ObjectIdentifier("1.1")
        with pytest.raises(VerificationError, match="Policy ID mismatch"):
            verifier.verify(ts_response, b"")

    def test_verify_wrong_message(self, ts_response: TimeStampResponse, verifier: Verifier) -> None:
        with pytest.raises(VerificationError, match="messages"):
            verifier.verify(ts_response, b"not-the-correct-message")

    def test_verify_succeeds(self, ts_response: TimeStampResponse, verifier: Verifier) -> None:
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
