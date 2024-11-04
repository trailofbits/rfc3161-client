"""rfc3161-client"""
import os
import platform
import sys
from pathlib import Path

def add_missing_dlls():
    print(f'ADD MISSING DIR {platform.system()}')
    if platform.system() != "Windows":
        return

    print(f"Adding directories to DLL directory")
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
