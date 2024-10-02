"""Verification module."""

from dataclasses import dataclass

import cryptography.x509

from sigstore_tsp.tsp import ObjectIdentifier, PKIStatus, TimeStampRequest, TimeStampResponse


@dataclass
class VerifyOpts:
    policy_id: ObjectIdentifier | None
    tsa_certificate: cryptography.x509.Certificate | None
    intermediates: list[cryptography.x509.Certificate]
    roots: list[cryptography.x509.Certificate]
    nonce: int
    common_name: str


def create_verify_opts(
    tsp_request: TimeStampRequest,
    tsa_certifiate: cryptography.x509.Certificate | None,
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
        tsa_certificate=tsa_certifiate,
        intermediates=intermediates,
        roots=root_certificates,
        nonce=tsp_request.nonce,
        common_name=common_name,
    )


def _verify_leaf_certs(tsp_response: TimeStampResponse, opts: VerifyOpts) -> bool:
    if opts.tsa_certificate is None and len(tsp_response.signed_data.certificates) == 0:
        return False

    if len(tsp_response.signed_data.certificates) > 0:
        leaf_certificate = next(iter(tsp_response.signed_data.certificates))

        # Embedded certificate does not match the one is the response
        if opts.tsa_certificate is not None and leaf_certificate != opts.tsa_certificate:
            return False

    else:
        leaf_certificate = opts.tsa_certificate

    critical_eku = False
    for extension in leaf_certificate.extensions:
        # EKUOID is the Extended Key Usage OID, per RFC 5280
        if extension.oid() == cryptography.x509.ObjectIdentifier(val="2.5.26.37"):
            critical_eku = extension.critical

    if not critical_eku:
        return False

    #  verifyESSCertID
    if opts.tsa_certificate:
        if (
            leaf_certificate.issuer != opts.tsa_certificate.issuer
            or leaf_certificate.serial_number != opts.tsa_certificate.serial_number
        ):
            return False

    # verifySubjectCommonName
    if opts.common_name:
        if leaf_certificate.subject.rfc4514_string() != opts.common_name:
            return False

    return True


def _verify_tsr_with_chains(tsp_response: TimeStampResponse, opts: VerifyOpts) -> bool:
    """"""
    if len(opts.roots) == 0:
        return False

    signed_data = tsp_response.signed_data
    if not signed_data.certificates and opts.tsa_certificate:
        # TODO(dm) I can't assign here because that's read only
        signed_data.certificates = opts.tsa_certificate

    # TODO(dm)
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
        return False

    if not _verify_tsr_with_chains(timestamp_response, verify_opts):
        return False

    # Verify Nonce
    if verify_opts.nonce is not None and timestamp_response.tst_info.nonce != verify_opts.nonce:
        return False

    # Verify Policy ID
    if (
        verify_opts.policy_id is not None
        and timestamp_response.tst_info.policy != verify_opts.policy_id
    ):
        return False

    if not _verify_leaf_certs(timestamp_response, verify_opts):
        return False

    # Verify message
    response_message = timestamp_response.tst_info.message_imprint.message
    if response_message != hashed_message:
        return False

    return True
