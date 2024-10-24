"""Verification module."""

from __future__ import annotations

import cryptography.x509
from cryptography.hazmat.primitives._serialization import Encoding

from rfc3161_client._rust import verify as _rust_verify
from rfc3161_client.errors import VerificationError
from rfc3161_client.tsp import PKIStatus, TimeStampRequest, TimeStampResponse


class VerifyBuilder:
    def __init__(
        self,
        policy_id: cryptography.x509.ObjectIdentifier | None = None,
        tsa_certificate: cryptography.x509.Certificate | None = None,
        intermediates: list[cryptography.x509.Certificate] | None = None,
        roots: list[cryptography.x509.Certificate] | None = None,
        nonce: int | None = None,
        common_name: str | None = None,
    ):
        """Init method."""
        self._policy_id: cryptography.x509.ObjectIdentifier | None = policy_id
        self._tsa_certificate: cryptography.x509.Certificate | None = tsa_certificate
        self._intermediates: list[cryptography.x509.Certificate] = intermediates or []
        self._roots: list[cryptography.x509.Certificate] = roots or []
        self._nonce: int | None = nonce
        self._common_name: str | None = common_name

    def policy_id(self, policy_oid: cryptography.x509.ObjectIdentifier) -> VerifyBuilder:
        """Set the nonce."""
        if not isinstance(policy_oid, cryptography.x509.ObjectIdentifier):
            msg = "The policy oid type is not valid"
            raise ValueError(msg)
        if self._policy_id is not None:
            msg = "The policy id can be set only once"
            raise ValueError(msg)
        return VerifyBuilder(
            policy_id=policy_oid,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )

    def tsa_certificate(self, certificate: cryptography.x509.Certificate) -> VerifyBuilder:
        """Set the TSA certificate."""
        if not isinstance(certificate, cryptography.x509.Certificate):
            msg = "The certificate type is not valid"
            raise ValueError(msg)
        if self._tsa_certificate is not None:
            msg = "The TSA certificate can be set only once"
            raise ValueError(msg)
        return VerifyBuilder(
            policy_id=self._policy_id,
            tsa_certificate=certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )

    def add_intermediate_certificate(
        self, certificate: cryptography.x509.Certificate
    ) -> VerifyBuilder:
        """Add an intermediate certificate."""
        if not isinstance(certificate, cryptography.x509.Certificate):
            msg = "The certificate type is not valid"
            raise ValueError(msg)

        intermediates = self._intermediates
        if certificate in intermediates:
            msg = "The certificate is already present"
            raise ValueError(msg)

        intermediates.append(certificate)

        return VerifyBuilder(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )

    def add_root_certificate(self, certificate: cryptography.x509.Certificate) -> VerifyBuilder:
        """Add a root certificate."""
        if not isinstance(certificate, cryptography.x509.Certificate):
            msg = "The certificate type is not valid"
            raise ValueError(msg)

        roots = self._roots
        if certificate in roots:
            msg = "The certificate is already present"
            raise ValueError(msg)

        roots.append(certificate)

        return VerifyBuilder(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )

    def nonce(self, nonce: int) -> VerifyBuilder:
        """Set the nonce."""
        if nonce < 0:
            msg = "The nonce must not be negative"
            raise ValueError(msg)
        if self._nonce is not None:
            msg = "The nonce can be set only once"
            raise ValueError(msg)
        return VerifyBuilder(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=nonce,
            common_name=self._common_name,
        )

    def common_name(self, name: str) -> VerifyBuilder:
        """Set the common name."""
        if self._common_name is not None:
            msg = "The name can be set only once"
            raise ValueError(msg)
        return VerifyBuilder(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=name,
        )

    def build(self) -> Verifier:
        """Build the VerifyOpts"""
        return Verifier(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )


class Verifier:
    def __init__(
        self,
        policy_id: cryptography.x509.ObjectIdentifier | None,
        tsa_certificate: cryptography.x509.Certificate | None,
        intermediates: list[cryptography.x509.Certificate],
        roots: list[cryptography.x509.Certificate],
        nonce: int | None,
        common_name: str | None = None,
    ):
        """Init."""
        self._policy_id: cryptography.x509.ObjectIdentifier | None = policy_id
        self._tsa_certificate: cryptography.x509.Certificate | None = tsa_certificate
        self._intermediates: list[cryptography.x509.Certificate] = intermediates
        self._roots: list[cryptography.x509.Certificate] = roots
        self._nonce: int | None = nonce
        self._common_name: str | None = common_name

    def verify(self, timestamp_response: TimeStampResponse, hashed_message: bytes) -> bool:
        """Verify a Timestamp Response.

        Inspired by:
            https://github.com/sigstore/timestamp-authority/blob/main/pkg/verification/verify.go#L209

        """
        # Note: digitorus/timestamp does not validate if the result is GRANTED_WITH_MOD
        # https://github.com/digitorus/timestamp/blob/master/timestamp.go#L268
        if PKIStatus(timestamp_response.status) != PKIStatus.GRANTED:
            msg = "PKIStatus is not GRANTED"
            raise VerificationError(msg)

        self._verify_tsr_with_chains(timestamp_response)

        # Verify Nonce
        if self._nonce is not None and timestamp_response.tst_info.nonce != self._nonce:
            msg = "Nonce mismatch"
            raise VerificationError(msg)

        # Verify Policy ID
        if self._policy_id is not None and timestamp_response.tst_info.policy != self._policy_id:
            msg = "Policy ID mismatch"
            raise VerificationError(msg)

        self._verify_leaf_certs(timestamp_response)

        # Verify message
        response_message = timestamp_response.tst_info.message_imprint.message
        if response_message != hashed_message:
            msg = "Mismatch between messages"
            raise VerificationError(msg)

        return True

    def _verify_leaf_certs(self, tsp_response: TimeStampResponse) -> bool:
        """
        Verify the timestamp response regarding the leaf certificate
        """
        if self._tsa_certificate is None and len(tsp_response.signed_data.certificates) == 0:
            msg = "Certificates neither found in the answer or in the Verification Options."
            raise VerificationError(msg)

        if len(tsp_response.signed_data.certificates) > 0:
            leaf_certificate_bytes = next(iter(tsp_response.signed_data.certificates))
            leaf_certificate = cryptography.x509.load_der_x509_certificate(leaf_certificate_bytes)

            if self._tsa_certificate is not None and leaf_certificate != self._tsa_certificate:
                msg = "Embedded certificate does not match the one in the Verification Options."
                raise VerificationError(msg)

        else:
            leaf_certificate = self._tsa_certificate

        critical_eku = False
        for extension in leaf_certificate.extensions:
            # EKUOID is the Extended Key Usage OID, per RFC 5280
            if extension.oid == cryptography.x509.ObjectIdentifier("2.5.29.37"):
                critical_eku = extension.critical

        if not critical_eku:
            msg = "The certificate does not contain the critical EKU extension."
            raise VerificationError(msg)

        #  verifyESSCertID
        if self._tsa_certificate:
            if (
                leaf_certificate.issuer != self._tsa_certificate.issuer
                or leaf_certificate.serial_number != self._tsa_certificate.serial_number
            ):
                msg = (
                    "The certificate details does not match the one provided in "
                    "Verification Options."
                )
                raise VerificationError(msg)

        # verifySubjectCommonName
        if self._common_name:
            if leaf_certificate.subject.rfc4514_string() != self._common_name:
                msg = (
                    "The name provided in the opts does not match the one in the leaf certificate."
                )
                raise VerificationError(msg)

        return True

    def _verify_tsr_with_chains(self, tsp_response: TimeStampResponse) -> bool:
        """Verify the Timestamp Response using the chains."""
        if len(self._roots) == 0:
            msg = "No roots provided in Verification Options."
            raise VerificationError(msg)

        signed_data = tsp_response.signed_data
        # https://github.com/digitorus/pkcs7/blob/3a137a8743524b3683ca4e11608d0dde37caee99/verify.go#L74
        if len(signed_data.signer_infos) == 0:
            msg = "The signed data has 0 signer infos."
            raise VerificationError(msg)

        verification_certificate: set[bytes] = set()
        if signed_data.certificates:
            verification_certificate.update(signed_data.certificates)

        if self._tsa_certificate:
            verification_certificate.add(self._tsa_certificate.public_bytes(Encoding.DER))

        if self._roots:
            verification_certificate.update(cert.public_bytes(Encoding.DER) for cert in self._roots)

        if self._intermediates:
            verification_certificate.update(
                cert.public_bytes(Encoding.DER) for cert in self._intermediates
            )

        p7 = tsp_response.time_stamp_token()
        try:
            self.verify_signed_data(p7, verification_certificate)
        except ValueError as e:
            msg = f"Error while verifying certificates: {e}"
            raise VerificationError(msg)

        return True

    def verify_signed_data(self, sig: bytes, certificates: set[bytes]) -> None:
        """Verify signed data.

        This function verifies that the bytes used in a signature are signed by a certificate
        trusted in the `certificates` list.
        The function does not return anything, but raises an exception if the verification fails.

        :param sig: Bytes of a PKCS7 object. This must be in DER format and will be unserialized.
        :param certificates: A list of trusted certificates to verify the response against.
        :raise: ValueError if the signature verification fails.
        """
        return _rust_verify.pkcs7_verify(sig, list(certificates))




def create_verifier_from_request(
    tsp_request: TimeStampRequest,
    tsa_certificate: cryptography.x509.Certificate | None,
    common_name: str | None,
    root_certificates: list[cryptography.x509.Certificate] | None = None,
    intermediates: list[cryptography.x509.Certificate] | None = None,
) -> Verifier:
    if intermediates is None:
        intermediates = []

    if root_certificates is None:
        root_certificates = []

    builder = VerifyBuilder()
    if tsp_request.policy:
        builder = builder.policy_id(tsp_request.policy)
    if tsp_request.nonce:
        builder = builder.nonce(tsp_request.nonce)
    if common_name:
        builder = builder.common_name(common_name)
    if tsa_certificate:
        builder = builder.tsa_certificate(tsa_certificate)

    for intermediate in intermediates:
        builder = builder.add_intermediate_certificate(intermediate)

    for root in root_certificates:
        builder = builder.add_root_certificate(root)

    return builder.build()
