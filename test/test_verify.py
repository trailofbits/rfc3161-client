from datetime import datetime
from pathlib import Path
from typing import Any, cast

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
from rfc3161_client.verify import Verifier, VerifierBuilder, _Verifier

_HERE = Path(__file__).parent.resolve()
_FIXTURE = _HERE / "fixtures"

# List of TSA authorities to test against
TSA_AUTHORITIES = [
    "test_tsa",
    "sigstage",
]


@pytest.fixture(params=TSA_AUTHORITIES)
def tsa_path(request: pytest.FixtureRequest) -> Path:
    """
    Fixture that returns the path to the fixtures for a specific TSA provider.
    """
    return Path(_FIXTURE / request.param)


@pytest.fixture
def certificates(tsa_path: Path) -> list[cryptography.x509.Certificate]:
    """
    Load certificates for the current TSA provider.
    """
    cert_path = tsa_path / "ts_chain.pem"
    if not cert_path.exists():
        pytest.skip(f"Certificates not found for {tsa_path}")
    return cryptography.x509.load_pem_x509_certificates(cert_path.read_bytes())


@pytest.fixture
def ts_request(tsa_path: Path) -> TimeStampRequest:
    """
    Load timestamp request for the current TSA provider.
    """
    request_path = tsa_path / "request.der"
    if not request_path.exists():
        pytest.skip(f"Request file not found for {tsa_path}")
    return parse_timestamp_request(request_path.read_bytes())


@pytest.fixture
def ts_response(tsa_path: Path) -> TimeStampResponse:
    """
    Load timestamp response for the current TSA provider.
    """
    response_path = tsa_path / "response.tsr"
    if not response_path.exists():
        pytest.skip(f"Response file not found for {tsa_path}")
    return decode_timestamp_response(response_path.read_bytes())


@pytest.fixture
def ts_response_by_filename(request: pytest.FixtureRequest, tsa_path: Path) -> TimeStampResponse:
    """
    Load a specific timestamp response file from a TSA provider.
    """
    filename = request.param

    response_path = tsa_path / filename
    if not response_path.exists():
        pytest.skip(f"Response file not found: {response_path}")

    return decode_timestamp_response(response_path.read_bytes())


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
        verifier = cast(
            "_Verifier", VerifierBuilder().add_root_certificate(certificates[-1]).build()
        )
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
        verifier = cast("_Verifier", verifier_builder.policy_id(oid).build())
        assert verifier._policy_id == oid

    def test_tsa_certificate(
        self, verifier_builder: VerifierBuilder, certificates: list[cryptography.x509.Certificate]
    ) -> None:
        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().tsa_certificate(certificates[0]).tsa_certificate(certificates[1])

        verifier = cast("_Verifier", verifier_builder.tsa_certificate(certificates[0]).build())
        assert verifier._tsa_certificate == certificates[0]

    def test_add_intermediate_certificate(
        self, verifier_builder: VerifierBuilder, certificates: list[cryptography.x509.Certificate]
    ) -> None:
        with pytest.raises(ValueError, match="already present"):
            VerifierBuilder().add_intermediate_certificate(
                certificates[0]
            ).add_intermediate_certificate(certificates[0])

        verifier = cast(
            "_Verifier",
            (
                verifier_builder.add_intermediate_certificate(certificates[0])
                .add_intermediate_certificate(certificates[1])
                .build()
            ),
        )
        assert verifier._intermediates == [certificates[0], certificates[1]]

    def test_add_root_certificate(self, certificates: list[cryptography.x509.Certificate]) -> None:
        with pytest.raises(ValueError, match="already present"):
            VerifierBuilder().add_root_certificate(certificates[0]).add_root_certificate(
                certificates[0]
            )

        with pytest.raises(ValueError, match="at least"):
            VerifierBuilder().build()

        verifier = cast(
            "_Verifier",
            (
                VerifierBuilder()
                .add_root_certificate(certificates[0])
                .add_root_certificate(certificates[1])
                .build()
            ),
        )
        assert verifier._roots == [certificates[0], certificates[1]]

    def test_nonce(self, verifier_builder: VerifierBuilder) -> None:
        with pytest.raises(ValueError, match="negative"):
            VerifierBuilder().nonce(-2)

        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().nonce(0xABCD).nonce(0xCAFE)

        verifier = cast("_Verifier", verifier_builder.nonce(0xABCD).build())
        assert verifier._nonce == 0xABCD

    def test_common_name(self, verifier_builder: VerifierBuilder) -> None:
        with pytest.raises(ValueError, match="only once"):
            VerifierBuilder().common_name("foo").common_name("bar")

        verifier = cast("_Verifier", verifier_builder.common_name("foo").build())
        assert verifier._common_name == "foo"


class TestVerifierPrivate:
    def test_verify_tsr_with_chains(
        self, ts_response: TimeStampResponse, verifier: Verifier
    ) -> None:
        verifier = cast("_Verifier", verifier)
        assert verifier._verify_tsr_with_chains(ts_response) is True

    def test_verify_tsr_with_chains_without_roots(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._roots = []
        with pytest.raises(VerificationError, match="No roots"):
            verifier._verify_tsr_with_chains(ts_response)

    def test_verify_tsr_with_chains_without_certs(
        self,
        ts_response: TimeStampResponse,
        verifier: Verifier,
    ) -> None:
        verifier = cast("_Verifier", verifier)
        with pytest.raises(VerificationError, match="Error while verifying"):
            verifier._verify_tsr_with_chains(
                pretend.stub(
                    signed_data=ts_response.signed_data,
                    time_stamp_token=lambda: b"",
                    tst_info=ts_response.tst_info,
                )
            )

    def test_verify_tsr_with_chains_without_signer(
        self,
        verifier: Verifier,
    ) -> None:
        verifier = cast("_Verifier", verifier)
        with pytest.raises(VerificationError, match="0 signer infos"):
            verifier._verify_tsr_with_chains(
                pretend.stub(signed_data=pretend.stub(signer_infos=[]))
            )

    def test_verify_leaf_certs_no_certs(self, verifier: Verifier) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._tsa_certificate = None
        response = pretend.stub(signed_data=pretend.stub(certificates=[]))
        with pytest.raises(VerificationError, match="Certificates neither"):
            verifier._verify_leaf_certs(tsp_response=response)

    def test_verify_leaf_certs_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._tsa_certificate = "fake-certificate"  # type: ignore[assignment]
        with pytest.raises(VerificationError, match="Embedded certificate"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_update_cert(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        verifier = cast("_Verifier", verifier)
        monkeypatch.setattr(rfc3161_client._rust.SignedData, "certificates", [])
        assert verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_no_eku(
        self,
        verifier: Verifier,
        ts_response: TimeStampResponse,
        monkeypatch: MonkeyPatch,
        certificates: list[cryptography.x509.Certificate],
    ) -> None:
        verifier = cast("_Verifier", verifier)
        # We know that the root certificate in our test chain does not have the extensions
        # so we can use it to test the error message
        root = certificates[-1]

        monkeypatch.setattr(cryptography.x509.Certificate, "extensions", root.extensions)
        with pytest.raises(
            VerificationError, match="The certificate does not contain the critical EKU extension"
        ):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_non_critical_eku(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        verifier = cast("_Verifier", verifier)
        monkeypatch.setattr(cryptography.x509.Extension, "critical", False)
        with pytest.raises(VerificationError, match="The EKU extension is not critical"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_certs_eku_no_values(
        self, verifier: Verifier, ts_response: TimeStampResponse, monkeypatch: MonkeyPatch
    ) -> None:
        verifier = cast("_Verifier", verifier)

        def mock_get_extension_for_class(_self: Any, _extclass: Any) -> Any:
            return pretend.stub(
                oid=cryptography.x509.ObjectIdentifier("2.5.29.37"),
                value=[],
                critical=True,
            )

        monkeypatch.setattr(
            cryptography.x509.extensions.Extensions,
            "get_extension_for_class",
            mock_get_extension_for_class,
        )
        with pytest.raises(VerificationError, match="The EKU extension does not have KeyPurposeID"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_cert_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._tsa_certificate = pretend.stub(
            __ne__=lambda *args: False,
            issuer=None,
        )
        with pytest.raises(
            VerificationError, match="The certificate details does not match the one provided"
        ):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_leaf_cert_no_leaf_cert(
        self, verifier: Verifier, monkeypatch: MonkeyPatch
    ) -> None:
        verifier = cast("_Verifier", verifier)

        def mock_load_der_x509_certificate(_cert: bytes) -> cryptography.x509.Certificate:
            return cast(
                "cryptography.x509.Certificate",
                pretend.stub(issuer="fake-name", subject="fake-name"),
            )

        monkeypatch.setattr(
            cryptography.x509,
            "load_der_x509_certificate",
            mock_load_der_x509_certificate,
        )

        response = pretend.stub(
            signed_data=pretend.stub(certificates=[b"fake-cert", b"fake-cert-2"])
        )

        with pytest.raises(VerificationError, match="No leaf certificate found in the chain."):
            verifier._verify_leaf_certs(tsp_response=response)

    def test_verify_leaf_name_mismatch(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._common_name = "fake-name"
        with pytest.raises(VerificationError, match="The name provided in the opts does not match"):
            verifier._verify_leaf_certs(tsp_response=ts_response)

    def test_verify_wrong_status(self, verifier: Verifier) -> None:
        with pytest.raises(VerificationError, match="GRANTED"):
            verifier.verify(pretend.stub(status=2), b"")

    def test_verify_wrong_nonce(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch: MonkeyPatch
    ) -> None:
        verifier = cast("_Verifier", verifier)
        verifier._nonce = 0xABCD
        with pytest.raises(VerificationError, match="Nonce mismatch"):
            verifier.verify(ts_response, b"")

    def test_verify_wrong_policy_oid(
        self, ts_response: TimeStampResponse, verifier: Verifier
    ) -> None:
        verifier = cast("_Verifier", verifier)
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

    ts_response_files = ["response-sha256.tsr", "response-sha384.tsr", "response-sha512.tsr"]

    @pytest.mark.parametrize("ts_response_by_filename", ts_response_files, indirect=True)
    def test_verify_message_with_algo(
        self,
        ts_response_by_filename: TimeStampResponse,
        certificates: list[cryptography.x509.Certificate],
    ) -> None:
        verifier = (
            VerifierBuilder()
            .add_root_certificate(certificates[-1])
            .tsa_certificate(certificates[0])
            .build()
        )

        assert verifier.verify_message(ts_response_by_filename, b"hello") is True

    def test_verify_message_with_unsupported_algo(
        self, ts_response: TimeStampResponse, verifier: Verifier, monkeypatch: MonkeyPatch
    ) -> None:
        # tweak OID so the timestamp response hash algorithm won't match it
        monkeypatch.setattr(rfc3161_client.verify, "SHA512_OID", rfc3161_client.verify.SHA384_OID)

        with pytest.raises(VerificationError, match="Unsupported hash"):
            verifier.verify_message(
                timestamp_response=ts_response,
                message=b"hello",
            )


class TestVerifierPublic:
    def test_verify_message_succeeds(
        self, verifier: Verifier, ts_response: TimeStampResponse
    ) -> None:
        assert verifier.verify_message(ts_response, b"hello") is True

    def test_verify_succeeds(self, verifier: Verifier, ts_response: TimeStampResponse) -> None:
        digest = hashes.Hash(hashes.SHA512())
        digest.update(b"hello")
        message = digest.finalize()
        assert verifier.verify(ts_response, message) is True


def test_verify_succeeds_when_leaf_cert_is_not_first() -> None:
    """This is a regression test for a bug where the leaf certificate was not
    being verified if it was not the first certificate in the chain.

    https://github.com/trailofbits/rfc3161-client/issues/104#issuecomment-2711244010
    """
    root_path = _FIXTURE / "identrust" / "ts_chain.pem"
    tsr_path = _FIXTURE / "identrust" / "issue-104.tsr"

    root = cryptography.x509.load_der_x509_certificate(root_path.read_bytes())
    verifier = VerifierBuilder().add_root_certificate(root).build()

    ts_response = decode_timestamp_response(tsr_path.read_bytes())

    digest = hashes.Hash(hashes.SHA512())
    digest.update(b"hello")
    message = digest.finalize()

    assert verifier.verify(ts_response, message)


def test_verify_succeeds_without_embedded_cert() -> None:
    """Ensure that a timestamp is considered valid even if it does not
    contain any embedded certificates (as long as the full certificate
    chain is provided to the verifier).

    The test asset was produced with timestamp-cli from sigstore/timestamp-authority:

        $ echo -n "hello > artifact
        $ timestamp-cli --timestamp_server https://timestamp.sigstage.dev \
            timestamp --artifact artifact --certificate=false

    https://github.com/trailofbits/rfc3161-client/issues/162
    """
    cert_path = _FIXTURE / "sigstage" / "ts_chain.pem"
    tsr_path = _FIXTURE / "sigstage" / "response-no-embedded-cert.tsr"

    certificates = cryptography.x509.load_pem_x509_certificates(cert_path.read_bytes())
    verifier = (
        VerifierBuilder()
        .add_root_certificate(certificates[-1])
        .tsa_certificate(certificates[0])
        .build()
    )

    ts_response = decode_timestamp_response(tsr_path.read_bytes())

    assert verifier.verify_message(ts_response, b"hello")


def test_verify_fails_invalid_tsr_signature() -> None:
    """Ensure that a TSR is rejected if it has an invalid signature,
    even if the certificate chain is valid.

    This test asset was produced by taking `response-sha256.tsr`
    and twiddling the signature bytes to make it invalid.
    """
    cert_path = _FIXTURE / "sigstage" / "ts_chain.pem"
    tsr_path = _FIXTURE / "sigstage" / "response-invalid-signature.tsr"

    certificates = cryptography.x509.load_pem_x509_certificates(cert_path.read_bytes())
    verifier = (
        VerifierBuilder()
        .add_root_certificate(certificates[-1])
        .tsa_certificate(certificates[0])
        .build()
    )

    ts_response = decode_timestamp_response(tsr_path.read_bytes())

    with pytest.raises(VerificationError, match="signature failure"):
        verifier.verify_message(ts_response, b"hello")


def test_verify_succeeds_even_if_cert_is_currently_expired() -> None:
    """Ensure that a timestamp is considered valid even if it is expired
    at verification time (as long as the full certificate
    chain was valid at timestamp time).

    The test asset comes from sigstore-conformance test suite:

    https://github.com/trailofbits/rfc3161-client/issues/171
    """
    cert_path = _FIXTURE / "sigstore.mock" / "ts_chain.pem"
    tsr_path = _FIXTURE / "sigstore.mock" / "response-expired.tsr"
    payload_path = _FIXTURE / "sigstore.mock" / "payload"

    certificates = cryptography.x509.load_pem_x509_certificates(cert_path.read_bytes())
    verifier = (
        VerifierBuilder()
        .add_root_certificate(certificates[-1])
        .tsa_certificate(certificates[0])
        .build()
    )

    ts_response = decode_timestamp_response(tsr_path.read_bytes())

    # timestamp verifies because timestamp time is within certificate validity window
    # (even though currently the certificate chain is expired)
    assert verifier.verify_message(ts_response, payload_path.read_bytes())

    # same timestamp fails to verify if timestamp time is mocked to be outside validity window
    with pytest.raises(VerificationError, match="certificate has expired"):
        verifier.verify_message(
            pretend.stub(
                signed_data=ts_response.signed_data,
                time_stamp_token=ts_response.time_stamp_token,
                tst_info=pretend.stub(
                    message_imprint=ts_response.tst_info.message_imprint,
                    gen_time=datetime(2025, 7, 21),
                ),
                status=ts_response.status,
            ),
            payload_path.read_bytes(),
        )
