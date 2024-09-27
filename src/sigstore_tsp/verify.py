"""Verification module."""

from sigstore_tsp.base import PKIStatus, TimestampRequest, TimestampResponse


def verify_signed_timestamp(
    signed_timestamp: TimestampResponse, timestamp_request: TimestampRequest
) -> bool:
    """Verify a Timestamp Response.

    Inspired by:
        https://github.com/sigstore/timestamp-authority/blob/main/pkg/verification/verify.go#L209

    """
    # Note: digitorus/timestamp does not validate if the result is GRANTED_WITH_MOD
    # https://github.com/digitorus/timestamp/blob/master/timestamp.go#L268
    if signed_timestamp.status == PKIStatus.GRANTED:
        return False

    # TODO(dm): verifyTSRWithChain

    # Verify Nonce
    if timestamp_request.nonce is not None:
        return False

    if (
        timestamp_request.policy_oid is not None
        and timestamp_request.policy_oid != signed_timestamp.tst_info.policy
    ):
        return False

    # TODO(dm)
    # 	if err = verifyLeafCert(*ts, opts); err != nil {
    # 		return nil, err
    # 	}

    # 	// verify the hash in the timestamp response matches the artifact hash
    # 	if err = verifyHashedMessages(ts.HashAlgorithm.New(), ts.HashedMessage, artifact); err != nil {
    # 		return nil, err
    # 	}

    return True
