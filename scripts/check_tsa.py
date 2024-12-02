# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptography",
#     "requests",
#     "rfc3161_client",
#     "rich",
# ]
# ///
import argparse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import requests
from cryptography.x509 import load_der_x509_certificate
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from rfc3161_client import (
    TimeStampRequest,
    TimestampRequestBuilder,
    TimeStampResponse,
    decode_timestamp_response,
)
from rfc3161_client._rust import parse_timestamp_request

# List is from https://gist.github.com/Manouchehri/fd754e402d98430243455713efada710
TSA_NAMES: dict[str, str] = {
    "digicert": "http://timestamp.digicert.com",
    "globalsign": "http://rfc3161timestamp.globalsign.com/advanced",  # Using the later entry
    "sectigo": "https://timestamp.sectigo.com",
    "sectigo_2": "https://timestamp.sectigo.com/qualified",
    "entrust": "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    "swisssign": "http://tsa.swisssign.net",
    "quovadisglobal": "http://ts.quovadisglobal.com/ch",
    "quovadisglobal_2": "http://ts.quovadisglobal.com/eu",
    "ssl_com": "http://ts.ssl.com",
    "identrust": "http://timestamp.identrust.com",
    "belgium": "http://tsa.belgium.be/connect",
    "cartaodecidadao": "http://ts.cartaodecidadao.pt/tsa/server",
    "accv_es": "http://tss.accv.es:8318/tsa",
    "baltstamp": "http://tsa.baltstamp.lt",
    "aped_gr": "https://timestamp.aped.gov.gr/qtss",
    "sep_bg": "http://tsa.sep.bg",
    "izenpe": "http://tsa.izenpe.com",
    "certum": "http://time.certum.pl",
    "globalsign_2": "http://timestamp.globalsign.com/tsa/r6advanced1",
    "apple": "http://timestamp.apple.com/ts01",
    "trustwave": "http://timestamp.ssl.trustwave.com",
    "freetsa": "https://freetsa.org/tsr",
    "zeitstempel": "http://zeitstempel.dfn.de",
    "catcert_cat": "http://psis.catcert.cat/psis/catcert/tsp",
    "codegic": "http://pki.codegic.com/codegic-service/timestamp",
    "wotrus": "https://tsa.wotrus.com",
    "lex_persona": "http://tsa.lex-persona.com/tsa",
    "cesnet": "https://tsa.cesnet.cz:5817/tsa",
    "cesnet_2": "https://tsa.cesnet.cz:3162/tsa",
    "signfiles": "http://ca.signfiles.com/TSAServer.aspx",
    "aloahacoin": "http://aloahacoin.chain-provider.com/tsa.aspx",
    "sinpe_cr": "http://tsa.sinpe.fi.cr/tsaHttp/",
    "mahidol_th": "https://tsa.mahidol.ac.th/tsa/get.aspx",
    "cra_ge": "http://tsa.cra.ge/signserver/tsa?workerName=qtsa",
    "gob_hn": "http://tss.cnbs.gob.hn/TSS/HttpTspServer",
    "mconnect": "https://time.mconnect.mc",
    "tugraz_at": "https://tsp.iaik.tugraz.at/tsp/TspRequest",
    "nowina_lu": "http://dss.nowina.lu/pki-factory/tsa/good-tsa",
}


class TSAStatus(Enum):
    """Enumeration of possible TSA response statuses"""

    OK = "OK"
    NOK = "NOK"
    REJECTED = "REJECTED"
    PARTIAL = "PARTIAL"


@dataclass
class TSAResult:
    """Data class to store TSA validation results"""

    status: TSAStatus
    reason: str | None = None
    warnings: list[str] = field(default_factory=lambda: [])


def create_result_directory(workdir: Path, data: bytes, with_certs: bool, with_nonce: bool):
    def with_(value: bool):
        return "with" if value else "without"

    data_clean = data.decode().replace(" ", "")[:8]
    name = f"{data_clean}-{with_(with_certs)}-certs-{with_(with_nonce)}-nonce"
    directory = workdir / name
    directory.mkdir(exist_ok=True)

    return directory


class TSAValidator:
    """Class to handle TSA validation operations"""

    def __init__(self, workdir: Path, console: Console):
        self.workdir: Path = workdir
        self.console: Console = console
        self.session: requests.Session = self._init_session()

    @staticmethod
    def _init_session() -> requests.Session:
        """Initialize and configure requests session"""
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "rfc3161_client - TSA validation tool",
                "Content-Type": "application/timestamp-query",
            }
        )
        return session

    def create_request(
        self, data: bytes, with_nonce: bool = True, with_certs: bool = True
    ) -> TimeStampRequest:
        """Create a timestamp request with specified parameters"""

        request_file = self.workdir / "request.tsq"
        if not request_file.is_file():
            request = (
                TimestampRequestBuilder()
                .data(data)
                .nonce(nonce=with_nonce)
                .cert_request(cert_request=with_certs)
                .build()
            )

            request_file.write_bytes(request.as_bytes())

        else:
            request = parse_timestamp_request(request_file.read_bytes())

        return request

    def validate_response(
        self, ts_request: TimeStampRequest, ts_response: TimeStampResponse
    ) -> tuple[list[str], list[str]]:
        """Validate timestamp response against request"""
        errors = []
        warnings = []

        # Version check
        if ts_response.tst_info.version != 1:
            errors.append("Wrong version number")

        # Nonce validation
        if ts_request.nonce and ts_request.nonce != ts_response.tst_info.nonce:
            errors.append("Wrong nonce value")

        # Policy validation
        if ts_request.policy:
            if ts_request.policy != ts_response.tst_info.policy:
                errors.append("Wrong policy value")
        elif not ts_response.tst_info.policy:
            errors.append("Missing Policy")

        # Message imprint validation
        if ts_request.message_imprint.message != ts_response.tst_info.message_imprint.message:
            errors.append("Wrong data hash")

        # TSA name validation
        if ts_response.tst_info.name:
            self._validate_tsa_name(ts_response, warnings)

        return errors, warnings

    @staticmethod
    def _validate_tsa_name(ts_response: TimeStampResponse, warnings: list[str]):
        """Validate TSA name against certificates"""
        name = ts_response.tst_info.name
        for cert in ts_response.signed_data.certificates:
            certificate = load_der_x509_certificate(cert)
            if certificate.issuer.rfc4514_string() == name:
                return
        warnings.append("Invalid name verification")

    def process_tsa(
        self,
        tsa_name: str,
        tsa_url: str,
        ts_request: TimeStampRequest,
        output_directory: Path,
        progress: Progress,
    ) -> TSAResult:
        """Process a single TSA endpoint"""
        task_id = progress.add_task(f"Processing {tsa_name}...", total=None)
        output_file = output_directory / tsa_name

        try:
            content = self._get_tsa_response(tsa_url, ts_request, output_file)
            result = self._process_tsa_response(content, ts_request, tsa_name)
        except Exception as e:
            self.console.print(f"Error processing {tsa_name}: {str(e)}")
            result = TSAResult(TSAStatus.NOK, reason=f"Error: {str(e)}")
        finally:
            progress.remove_task(task_id)

        return result

    def _get_tsa_response(self, url: str, request: TimeStampRequest, output_file: Path) -> bytes:
        """Get response from TSA server or load from cache"""
        if output_file.is_file():
            return output_file.read_bytes()

        try:
            response = self.session.post(
                url=url,
                data=request.as_bytes(),
                timeout=5,
            )
            response.raise_for_status()
            content = response.content
            output_file.write_bytes(content)
            return content
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {str(e)}")

    def _process_tsa_response(
        self, content: bytes, ts_request: TimeStampRequest, tsa_name: str
    ) -> TSAResult:
        """Process and validate TSA response"""
        try:
            tsr = decode_timestamp_response(content)

            if tsr.status > 1:
                return TSAResult(TSAStatus.REJECTED)

            errors, warnings = self.validate_response(ts_request, tsr)

            if errors:
                return TSAResult(TSAStatus.NOK, reason=f"Response Validation {''.join(errors)}")
            elif warnings:
                return TSAResult(TSAStatus.PARTIAL, warnings=warnings)

            return TSAResult(TSAStatus.OK)

        except ValueError as e:
            error_msg = "Invalid Set Ordering Error" if "InvalidSetOrdering" in str(e) else str(e)
            return TSAResult(TSAStatus.NOK, error_msg)

    def display_results(self, results: dict[str, TSAResult]):
        """Display validation results in a table format"""
        table = Table(title="TSA Validation Results")
        table.add_column("Status")
        table.add_column("TSA")
        table.add_column("Details")

        status_icons = {
            TSAStatus.OK: "[green]:green_circle:",
            TSAStatus.NOK: "[red]:cross_mark:",
            TSAStatus.REJECTED: ":yellow_circle:",
            TSAStatus.PARTIAL: ":orange_circle:",
        }

        for tsa_name, result in results.items():
            status = status_icons.get(result.status, "")
            if result.reason:
                details = result.reason
            else:
                details = ", ".join(result.warnings) if result.warnings else ""

            table.add_row(status, tsa_name, details)

        self.console.print(table)
        number_failed = len([r for r in results.values() if r.status == TSAStatus.NOK])
        self.console.print(f"\nFailed: {number_failed} / {len(results)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="RFC3161 Timestamp Authority Validator")
    parser.add_argument("workdir", type=Path, help="Directory to store responses")
    parser.add_argument("--data", type=str, default="hello world", help="Data to timestamp")
    parser.add_argument("--no-nonce", action="store_false", dest="with_nonce", help="Disable nonce")
    parser.add_argument(
        "--no-certs", action="store_false", dest="with_certs", help="Disable certificates"
    )
    args = parser.parse_args()

    console = Console(record=True)

    args.workdir.mkdir(exist_ok=True, parents=True)
    console.print(f"[cyan]Saving results in {args.workdir}")

    validator = TSAValidator(args.workdir, console)

    # Create timestamp request
    ts_request = validator.create_request(
        data=args.data.encode(), with_nonce=args.with_nonce, with_certs=args.with_certs
    )

    console.print(f"Parameters are: {args.data=} {args.with_nonce=}, {args.with_certs=}")

    results: dict[str, TSAResult] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console,
    ) as progress:
        # Loop through each TSA
        for tsa_name, tsa_url in TSA_NAMES.items():
            try:
                results[tsa_name] = validator.process_tsa(
                    tsa_name, tsa_url, ts_request, args.workdir, progress
                )
            except Exception as e:
                console.print(f"Failed to process {tsa_name}: {e}")
                results[tsa_name] = TSAResult(TSAStatus.NOK, str(e))

    validator.display_results(results)

    with (args.workdir / "output.md").open("w") as f:
        f.write(console.export_text())


if __name__ == "__main__":
    main()
