"""rfc3161-client"""
import os
import platform
import sys
from pathlib import Path

def add_missing_dlls():
    """Add required DLL search directories for Windows platform.

    This function ensures DLLs can be found by:
    1. Adding OpenSSL directory from OPENSSL_DIR environment variable (if set)
    2. Adding Python installation directory

    These directories are only added on Windows platforms. On other platforms,
    the function returns without making any changes.
    """
    if platform.system() != "Windows":
        return

    if openssl_dir := os.environ.get("OPENSSL_DIR"):
        os.add_dll_directory(openssl_dir)

    python_dir = Path(sys.executable).parent
    os.add_dll_directory(python_dir.as_posix())

add_missing_dlls()

from .base import TimestampRequestBuilder, decode_timestamp_response
from .errors import VerificationError
from .tsp import (
    Accuracy,
    MessageImprint,
    PKIStatus,
    SignedData,
    SignerInfo,
    TimeStampRequest,
    TimeStampResponse,
    TimeStampTokenInfo,
)
from .verify import Verifier, VerifierBuilder

__all__ = [
    "decode_timestamp_response",
    "TimestampRequestBuilder",
    "Verifier",
    "VerifierBuilder",
    "VerificationError",
    "TimeStampRequest",
    "TimeStampResponse",
    "TimeStampTokenInfo",
    "MessageImprint",
    "PKIStatus",
    "Accuracy",
    "SignedData",
    "SignerInfo",
]
