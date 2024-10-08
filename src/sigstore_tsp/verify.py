"""Verification module."""

from __future__ import annotations

from dataclasses import dataclass

import cryptography.x509
from cryptography.hazmat.primitives._serialization import Encoding

from sigstore_tsp.base import verify_signed_data
from sigstore_tsp.errors import VerificationError
from sigstore_tsp.tsp import PKIStatus, TimeStampRequest, TimeStampResponse


@dataclass
class VerifyOpts:
    policy_id: cryptography.x509.ObjectIdentifier | None
    tsa_certificate: cryptography.x509.Certificate | None
    intermediates: list[cryptography.x509.Certificate]
    roots: list[cryptography.x509.Certificate]
    nonce: int
    common_name: str


def create_verify_opts(
    tsp_request: TimeStampRequest,
    tsa_certificate: cryptography.x509.Certificate | None,
    common_name: str,
    root_certificates: list[cryptography.x509.Certificate] | None = None,
    intermediates: list[cryptography.x509.Certificate] | None = None,
) -> VerifyOpts:
    if intermediates is None:
        intermediates = []

    if root_certificates is None:
        root_certificates = []

    return VerifyOpts(
        policy_id=tsp_request.policy,
        tsa_certificate=tsa_certificate,
        intermediates=intermediates,
        roots=root_certificates,
        nonce=tsp_request.nonce,
        common_name=common_name,
    )


def _verify_leaf_certs(tsp_response: TimeStampResponse, opts: VerifyOpts) -> bool:
    if opts.tsa_certificate is None and len(tsp_response.signed_data.certificates) == 0:
        msg = "Certificates neither found in the answer or in the opts."
        raise VerificationError(msg)

    if len(tsp_response.signed_data.certificates) > 0:
        leaf_certificate_bytes = next(iter(tsp_response.signed_data.certificates))
        leaf_certificate = cryptography.x509.load_der_x509_certificate(leaf_certificate_bytes)

        if opts.tsa_certificate is not None and leaf_certificate != opts.tsa_certificate:
            msg = "Embedded certificate does not match the one in the opts."
            raise VerificationError(msg)

    else:
        leaf_certificate = opts.tsa_certificate

    critical_eku = False
    for extension in leaf_certificate.extensions:
        # EKUOID is the Extended Key Usage OID, per RFC 5280
        if extension.oid == cryptography.x509.ObjectIdentifier("2.5.29.37"):
            critical_eku = extension.critical

    if not critical_eku:
        msg = "The certificate does not contain the critical EKU extension."
        raise VerificationError(msg)

    #  verifyESSCertID
    if opts.tsa_certificate:
        if (
            leaf_certificate.issuer != opts.tsa_certificate.issuer
            or leaf_certificate.serial_number != opts.tsa_certificate.serial_number
        ):
            msg = "The certificate details does not match the one provided in opts."
            raise VerificationError(msg)

    # verifySubjectCommonName
    if opts.common_name:
        if leaf_certificate.subject.rfc4514_string() != opts.common_name:
            msg = "The name provided in the opts does not match the one in the leaf certificate."
            raise VerificationError(msg)

    return True


def _verify_tsr_with_chains(tsp_response: TimeStampResponse, opts: VerifyOpts) -> bool:
    """"""
    if len(opts.roots) == 0:
        msg = "No roots provided in opts."
        raise VerificationError(msg)

    signed_data = tsp_response.signed_data
    # https://github.com/digitorus/pkcs7/blob/3a137a8743524b3683ca4e11608d0dde37caee99/verify.go#L74
    if len(signed_data.signer_infos) == 0:
        msg = "The signed data has 0 signer infos."
        raise VerificationError(msg)

    verification_certificate: set[bytes] = set()
    if signed_data.certificates:
        verification_certificate.update(signed_data.certificates)

    if opts.tsa_certificate:
        verification_certificate.add(opts.tsa_certificate.public_bytes(Encoding.DER))

    if opts.roots:
        verification_certificate.update(cert.public_bytes(Encoding.DER) for cert in opts.roots)

    if opts.intermediates:
        verification_certificate.update(
            cert.public_bytes(Encoding.DER) for cert in opts.intermediates
        )

    p7 = tsp_response.time_stamp_token()
    try:
        verify_signed_data(p7, verification_certificate)
    except ValueError as e:
        msg = f"Error while verifying certificates: {e}"
        raise VerificationError(msg)

    return True


def verify_timestamp_response(
    timestamp_response: TimeStampResponse, hashed_message: bytes, verify_opts: VerifyOpts
) -> bool:
    """Verify a Timestamp Response.

    Inspired by:
        https://github.com/sigstore/timestamp-authority/blob/main/pkg/verification/verify.go#L209

    """
    # Note: digitorus/timestamp does not validate if the result is GRANTED_WITH_MOD
    # https://github.com/digitorus/timestamp/blob/master/timestamp.go#L268
    if PKIStatus(timestamp_response.status) != PKIStatus.GRANTED:
        msg = "PKIStatus is not GRANTED"
        raise VerificationError(msg)

    _verify_tsr_with_chains(timestamp_response, verify_opts)

    # Verify Nonce
    if verify_opts.nonce is not None and timestamp_response.tst_info.nonce != verify_opts.nonce:
        msg = "Nonce mismatch"
        raise VerificationError(msg)

    # Verify Policy ID
    if (
        verify_opts.policy_id is not None
        and timestamp_response.tst_info.policy != verify_opts.policy_id
    ):
        msg = "Policy ID mismatch"
        raise VerificationError(msg)

    _verify_leaf_certs(timestamp_response, verify_opts)

    # Verify message
    response_message = timestamp_response.tst_info.message_imprint.message
    if response_message != hashed_message:
        msg = "Mismatch between messages"
        raise VerificationError(msg)

    return True
