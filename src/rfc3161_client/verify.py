"""Verification module."""

from __future__ import annotations

import abc
import hashlib
from copy import copy

import cryptography.x509
from cryptography.hazmat.primitives._serialization import Encoding

from rfc3161_client._rust import verify as _rust_verify
from rfc3161_client.errors import VerificationError
from rfc3161_client.tsp import PKIStatus, TimeStampRequest, TimeStampResponse

# See https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
SHA256_OID = "2.16.840.1.101.3.4.2.1"
SHA384_OID = "2.16.840.1.101.3.4.2.2"
SHA512_OID = "2.16.840.1.101.3.4.2.3"


class VerifierBuilder:
    """Builder for a Verifier."""

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

    def policy_id(self, policy_oid: cryptography.x509.ObjectIdentifier) -> VerifierBuilder:
        """Set the policy ID."""
        if self._policy_id is not None:
            msg = "policy id can be set only once"
            raise ValueError(msg)
        builder = copy(self)
        builder._policy_id = policy_oid
        return builder

    def tsa_certificate(self, certificate: cryptography.x509.Certificate) -> VerifierBuilder:
        """Set the TSA certificate."""
        if self._tsa_certificate is not None:
            msg = "TSA certificate can be set only once"
            raise ValueError(msg)
        builder = copy(self)
        builder._tsa_certificate = certificate
        return builder

    def add_intermediate_certificate(
        self, certificate: cryptography.x509.Certificate
    ) -> VerifierBuilder:
        """Add an intermediate certificate."""
        intermediates = self._intermediates
        if certificate in intermediates:
            msg = "intermediate certificate is already present"
            raise ValueError(msg)
        intermediates.append(certificate)

        builder = copy(self)
        builder._intermediates = intermediates
        return builder

    def add_root_certificate(self, certificate: cryptography.x509.Certificate) -> VerifierBuilder:
        """Add a root certificate."""
        roots = self._roots
        if certificate in roots:
            msg = "root certificate is already present"
            raise ValueError(msg)
        roots.append(certificate)

        builder = copy(self)
        builder._roots = roots
        return builder

    def nonce(self, nonce: int) -> VerifierBuilder:
        """Set the nonce."""
        if nonce < 0:
            msg = "nonce must not be negative"
            raise ValueError(msg)
        if self._nonce is not None:
            msg = "nonce can be set only once"
            raise ValueError(msg)
        builder = copy(self)
        builder._nonce = nonce
        return builder

    def common_name(self, name: str) -> VerifierBuilder:
        """Set the common name."""
        if self._common_name is not None:
            msg = "name can be set only once"
            raise ValueError(msg)
        builder = copy(self)
        builder._common_name = name
        return builder

    def build(self) -> Verifier:
        """Build the Verifier."""
        if not self._roots:
            msg = "Verifier must have at least one root certificate set"
            raise ValueError(msg)

        return _Verifier(
            policy_id=self._policy_id,
            tsa_certificate=self._tsa_certificate,
            intermediates=self._intermediates,
            roots=self._roots,
            nonce=self._nonce,
            common_name=self._common_name,
        )

    @classmethod
    def from_request(cls, tsp_request: TimeStampRequest) -> VerifierBuilder:
        """Create a verifier from a Timestamp Request."""
        return cls(
            policy_id=tsp_request.policy,
            nonce=tsp_request.nonce,
        )


class Verifier(metaclass=abc.ABCMeta):
    """Verifier.

    This class should not be instantiated directly but through a VerifierBuilder.
    """

    @abc.abstractmethod
    def verify_message(self, timestamp_response: TimeStampResponse, message: bytes) -> bool:
        """Verify a Timestamp Response over a given message

        Supports timestamp responses with SHA-256, SHA-384 or SHA-512 hash algorithms.
        """

    @abc.abstractmethod
    def verify(self, timestamp_response: TimeStampResponse, hashed_message: bytes) -> bool:
        """Verify a Timestamp Response over given message digest

        Note that caller is responsible for hashing the message appropriately for the
        given timestamp response.
        """


class _Verifier(Verifier):
    """Inner implementation of the Verifier.

    This pattern helps us ensure that the Verifier is never created directly.
    """

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

    def verify_message(self, timestamp_response: TimeStampResponse, message: bytes) -> bool:
        """Verify a Timestamp Response over a given message

        Supports timestamp responses with SHA-256, SHA-384 or SHA-512 hash algorithms.
        """

        algo = timestamp_response.tst_info.message_imprint.hash_algorithm
        if algo == cryptography.x509.ObjectIdentifier(value=SHA256_OID):
            hashed_message = hashlib.sha256(message).digest()
        elif algo == cryptography.x509.ObjectIdentifier(value=SHA384_OID):
            hashed_message = hashlib.sha384(message).digest()
        elif algo == cryptography.x509.ObjectIdentifier(value=SHA512_OID):
            hashed_message = hashlib.sha512(message).digest()
        else:
            raise VerificationError(f"Unsupported hash algorithm {algo}")

        return self.verify(timestamp_response, hashed_message)

    def verify(self, timestamp_response: TimeStampResponse, hashed_message: bytes) -> bool:
        """Verify a Timestamp Response over given message digest

        Note that caller is responsible for hashing the message appropriately for the
        given timestamp response.

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
            certs = [
                cryptography.x509.load_der_x509_certificate(cert)
                for cert in tsp_response.signed_data.certificates
            ]

            leaf_certificate = None
            for cert in certs:
                if not [c for c in certs if c.issuer == cert.subject]:
                    leaf_certificate = cert
                    break
            else:
                msg = "No leaf certificate found in the chain."
                raise VerificationError(msg)

            # Note: The order of comparison is important here since we mock
            # _tsa_certificate's __ne__ method in tests, rather than leaf_certificate's
            if self._tsa_certificate is not None and self._tsa_certificate != leaf_certificate:
                msg = "Embedded certificate does not match the one in the Verification Options."
                raise VerificationError(msg)

        else:
            leaf_certificate = self._tsa_certificate

        try:
            eku_extension = leaf_certificate.extensions.get_extension_for_class(
                cryptography.x509.ExtendedKeyUsage
            )
        except cryptography.x509.ExtensionNotFound:
            msg = "The certificate does not contain the critical EKU extension."
            raise VerificationError(msg)

        if not eku_extension.critical:
            msg = "The EKU extension is not critical."
            raise VerificationError(msg)

        # id-kp-timeStamping - RFC3161 2.3
        if cryptography.x509.ExtendedKeyUsageOID.TIME_STAMPING not in eku_extension.value:
            msg = "The EKU extension does not have KeyPurposeID id-kp-timeStamping."
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
            self._verify_signed_data(p7, verification_certificate)
        except ValueError as e:
            msg = f"Error while verifying certificates: {e}"
            raise VerificationError(msg)

        return True

    def _verify_signed_data(self, sig: bytes, certificates: set[bytes]) -> None:
        """Verify signed data.

        This function verifies that the bytes used in a signature are signed by a certificate
        trusted in the `certificates` list.
        The function does not return anything, but raises an exception if the verification fails.

        :param sig: Bytes of a PKCS7 object. This must be in DER format and will be unserialized.
        :param certificates: A list of trusted certificates to verify the response against.
        :raise: ValueError if the signature verification fails.
        """
        return _rust_verify.pkcs7_verify(sig, list(certificates))
