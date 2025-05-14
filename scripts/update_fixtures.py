# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "requests",
#     "rfc3161-client",
# ]
# ///
import argparse
import sys
from http import HTTPStatus
from pathlib import Path

import requests

from rfc3161_client.base import TimestampRequestBuilder, decode_timestamp_response

_FIXTURE_DIRECTORY = Path(__file__).parent.parent / "test" / "fixtures" / "test_tsa"

TIMESTAMP_SERVER_URL = "http://localhost:3000"


def main() -> None:
    """Update fixtures file."""

    parser = argparse.ArgumentParser(description="Update fixture files")
    parser.add_argument("-u", "--timestamp_url", type=str, default=TIMESTAMP_SERVER_URL)

    args = parser.parse_args()

    request = TimestampRequestBuilder().data(b"hello").build()

    response = requests.post(
        f"{args.timestamp_url}/api/v1/timestamp/",
        headers={"Content-Type": "application/timestamp-query"},
        data=request.as_bytes(),
    )

    if response.status_code != HTTPStatus.CREATED:
        print(f"Error while signing the request: {response.status_code} {response.text}")
        sys.exit(1)

    timestamp_response = decode_timestamp_response(response.content)
    if not timestamp_response:
        print("Failed to decode response")
        sys.exit(1)

    certs_request = requests.get(f"{args.timestamp_url}/api/v1/timestamp/certchain")
    if certs_request.status_code != HTTPStatus.OK:
        print(f"Failed getting certificates from TSA {certs_request.text}")
        sys.exit(1)

    (_FIXTURE_DIRECTORY / "ts_chain.pem").write_bytes(certs_request.content)
    (_FIXTURE_DIRECTORY / "request.der").write_bytes(request.as_bytes())
    (_FIXTURE_DIRECTORY / "response.tsr").write_bytes(response.content)

    print("OK")


if __name__ == "__main__":
    main()
