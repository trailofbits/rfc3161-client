from __future__ import annotations

import abc
import enum
from typing import TYPE_CHECKING

from rfc3161_client import _rust

if TYPE_CHECKING:
    import datetime

    import cryptography.x509


class MessageImprint(metaclass=abc.ABCMeta):
    """Represents a Message Imprint (per RFC 3161)."""

    @property
    @abc.abstractmethod
    def hash_algorithm(self) -> cryptography.x509.ObjectIdentifier:
        """Returns the Object Identifier of the Hash algorithm used."""

    @property
    @abc.abstractmethod
    def message(self) -> bytes:
        """Return the hashed message."""


MessageImprint.register(_rust.PyMessageImprint)


class TimeStampRequest(metaclass=abc.ABCMeta):
    """Represents a Timestamp Request (per RFC 3161)."""

    @property
    @abc.abstractmethod
    def version(self) -> int:
        """Returns the version of the Timestamp Request."""

    @property
    @abc.abstractmethod
    def nonce(self) -> int | None:
        """Returns the nonce generated for this request."""

    @property
    @abc.abstractmethod
    def policy(self) -> cryptography.x509.ObjectIdentifier | None:
        """Returns the request policy OID."""

    @property
    @abc.abstractmethod
    def cert_req(self) -> bool:
        """Is the certificate request present."""

    @property
    @abc.abstractmethod
    def message_imprint(self) -> MessageImprint:
        """Returns the Timestamp Request Message Imprint."""

    @abc.abstractmethod
    def as_bytes(self) -> bytes:
        """Returns the Timestamp Request as bytes."""


TimeStampRequest.register(_rust.TimeStampReq)


class PKIStatus(enum.IntEnum):
    GRANTED = 0
    GRANTED_WITH_MODS = 1
    REJECTION = 2
    WAITING = 3
    REVOCATION_WARNING = 4
    REVOCATION_NOTIFICATION = 5


class TimeStampResponse(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def status(self) -> int:
        """Returns the status of the Timestamp Response."""

    @property
    @abc.abstractmethod
    def status_string(self) -> list[str]:
        """Returns the status string."""

    @property
    @abc.abstractmethod
    def tst_info(self) -> TimeStampTokenInfo:
        """Returns the Timestamp Token Info."""

    @property
    @abc.abstractmethod
    def signed_data(self) -> SignedData:
        """Returns the Signed Data."""

    @abc.abstractmethod
    def time_stamp_token(self) -> bytes:
        """Return the bytes of the TimestampToken field."""

    @abc.abstractmethod
    def as_bytes(self) -> bytes:
        """Returns the Timestamp Response as bytes."""


TimeStampResponse.register(_rust.TimeStampResp)


class Accuracy(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def seconds(self) -> int:
        """Returns the seconds."""

    @property
    @abc.abstractmethod
    def millis(self) -> int | None:
        """Returns the seconds."""

    @property
    @abc.abstractmethod
    def micros(self) -> int | None:
        """Returns the seconds."""


Accuracy.register(_rust.Accuracy)


class TimeStampTokenInfo(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def version(self) -> int:
        """Returns the version."""

    @property
    @abc.abstractmethod
    def policy(self) -> cryptography.x509.ObjectIdentifier:
        """Returns the policy OID."""

    @property
    @abc.abstractmethod
    def message_imprint(self) -> MessageImprint:
        """Returns the Message Imprint."""

    @property
    @abc.abstractmethod
    def serial_number(self) -> int:
        """Returns the Serial Number."""

    @property
    @abc.abstractmethod
    def gen_time(self) -> datetime.datetime:
        """Returns the policy OID."""

    @property
    @abc.abstractmethod
    def accuracy(self) -> Accuracy:
        """Returns the Accuracy."""

    @property
    @abc.abstractmethod
    def ordering(self) -> bool:
        """Returns the ordering."""

    @property
    @abc.abstractmethod
    def nonce(self) -> int:
        """Returns the nonce."""

    @property
    @abc.abstractmethod
    def name(self) -> cryptography.x509.GeneralName:
        """Returns the name."""


TimeStampTokenInfo.register(_rust.PyTSTInfo)


class SignedData(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def version(self) -> int:
        """Returns the version."""

    @property
    @abc.abstractmethod
    def digest_algorithms(self) -> set[cryptography.x509.ObjectIdentifier]:
        """Returns the set of digest algorithms."""

    @property
    @abc.abstractmethod
    def certificates(self) -> set[bytes]:
        """Returns the set of certificates.
        Warning: they are returned as a byte array and should be loaded.
        """

    @property
    @abc.abstractmethod
    def signer_infos(self) -> set[SignerInfo]:
        """Returns the signers infos."""


SignedData.register(_rust.SignedData)


class SignerInfo(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def version(self) -> int:
        """Returns the version."""


SignerInfo.register(_rust.SignerInfo)
