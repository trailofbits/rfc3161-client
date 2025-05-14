from datetime import datetime, timezone
from pathlib import Path

import pytest

from rfc3161_client import TimeStampRequest, decode_timestamp_response
from rfc3161_client._rust import parse_timestamp_request

_HERE = Path(__file__).parent.resolve()
_FIXTURE = _HERE / "fixtures"


@pytest.fixture
def response_path() -> Path:
    """Path to the response file for the test TSA."""
    return _FIXTURE / "test_tsa" / "response.tsr"


@pytest.fixture
def request_path() -> Path:
    """Path to the request file for the test TSA."""
    return _FIXTURE / "test_tsa" / "request.der"


class TestTimestampResponse:
    def test_parsing_good(self, response_path: Path) -> None:
        timestamp_response = decode_timestamp_response(response_path.read_bytes())
        assert timestamp_response.status == 0

        tst_info = timestamp_response.tst_info
        assert tst_info.name.value.rfc4514_string() == "CN=Test TSA Timestamping,O=local"
        assert tst_info.nonce == 3937359519792308179
        assert not tst_info.ordering
        assert tst_info.policy.dotted_string == "1.3.6.1.4.1.57264.2"
        assert tst_info.serial_number == 693290210947147715387173185458430793885588677084
        assert tst_info.version == 1
        assert datetime(2024, 10, 8, 15, 40, 32, tzinfo=timezone.utc) == tst_info.gen_time
        assert tst_info.message_imprint.message.hex().startswith("9b71d224bd62f3785d96d")

        assert tst_info.accuracy.seconds == 1
        assert tst_info.accuracy.millis is None
        assert tst_info.accuracy.micros is None

    def test_equality(self, response_path: Path) -> None:
        timestamp_response = decode_timestamp_response(response_path.read_bytes())
        other_response = decode_timestamp_response(
            (response_path.parent / "other_response.tsr").read_bytes()
        )

        assert timestamp_response != other_response
        assert decode_timestamp_response(response_path.read_bytes()) == decode_timestamp_response(
            response_path.read_bytes()
        )

    def test_round_trip(self, response_path: Path) -> None:
        timestamp_response = decode_timestamp_response(response_path.read_bytes())
        assert timestamp_response == decode_timestamp_response(timestamp_response.as_bytes())


class TestTimestampRequest:
    def test_parsing_good(self, request_path: Path) -> None:
        timestamp_request: TimeStampRequest = parse_timestamp_request(request_path.read_bytes())
        assert timestamp_request.version == 1
        assert timestamp_request.cert_req
        assert timestamp_request.nonce == 3937359519792308179
        assert timestamp_request.policy is None
        assert timestamp_request.message_imprint.message.hex().startswith("9b71d224bd62f3785d96d")

    def test_equality(self, request_path: Path) -> None:
        timestamp_request = parse_timestamp_request(request_path.read_bytes())
        other_request = parse_timestamp_request(
            (request_path.parent / "other_request.der").read_bytes()
        )

        assert timestamp_request != other_request

    def test_round_trip(self, request_path: Path) -> None:
        timestamp_request = parse_timestamp_request(request_path.read_bytes())
        assert timestamp_request == parse_timestamp_request(timestamp_request.as_bytes())
