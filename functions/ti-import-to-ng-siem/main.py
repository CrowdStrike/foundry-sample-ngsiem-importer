"""
Threat Intelligence Import to Next-Gen SIEM Function

This module downloads threat intelligence data from various open-source providers,
processes the data into standardized CSV format, and uploads it to CrowdStrike's
Next-Gen SIEM platform as lookup files.
"""

import csv
import ipaddress
import logging
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
from crowdstrike.foundry.function import (  # type: ignore
    APIError,
    Function,
    Request,
    Response,
)
from falconpy import NGSIEM  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize function
FUNC = Function.instance()

# Define the threat intelligence sources to process
TI_SOURCES = [
    {
        "url": "https://www.botvrij.eu/data/ioclist.domain",
        "name": "domain-botvrij-eu",
        "headers": ["dns.domain.name", "dns.domain.details"],
        "separator": " # domain - ",
        "type": "domain",
    },
    {
        "url": "https://www.botvrij.eu/data/ioclist.sha1",
        "name": "sha1-botvrij-eu",
        "headers": ["file.hash.sha1", "file.hash.sha1.details"],
        "separator": " # sha1 - ",
        "type": "sha1",
    },
    {
        "url": "https://www.botvrij.eu/data/ioclist.ip-dst",
        "name": "ip-botvrij-eu",
        "headers": ["destination.ip", "destination.ip.details"],
        "separator": " # ip-dst - ",
        "type": "ip",
    },
    {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "name": "ip-emerging-threats",
        "headers": ["destination.ip"],
        "separator": None,
        "type": "ip",
    },
    {
        "url": "https://www.dan.me.uk/torlist/",
        "name": "ip-dan-me-uk-tor",
        "headers": ["destination.ip"],
        "separator": None,
        "type": "ip",
    },
    {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "name": "url-abuse-ch",
        "headers": ["url.original"],
        "separator": None,
        "type": "url",
    },
]


class ThreatIntelProcessor:
    """
    Class to handle downloading, processing, and uploading of threat intelligence data.
    """

    def __init__(self, repository: str = "search-all"):
        """
        Initialize the ThreatIntelProcessor.

        Args:
            repository: The NG-SIEM repository to upload data to
        """
        self.repository = repository
        self.ngsiem_client = NGSIEM()

    def process_all_sources(self) -> List[Dict[str, str]]:
        """
        Process all threat intelligence sources concurrently.

        Returns:
            List of dictionaries containing processing results for each source
        """
        results = []

        with tempfile.TemporaryDirectory() as temp_dir:
            # Process files concurrently
            with ThreadPoolExecutor(max_workers=min(len(TI_SOURCES), 5)) as executor:
                future_to_source = {
                    executor.submit(self.process_source, source, temp_dir): source
                    for source in TI_SOURCES
                }

                for future in as_completed(future_to_source):
                    source = future_to_source[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except (requests.RequestException, ValueError, IOError) as e:
                        logger.error("Error processing %s: %s", source["name"], str(e))
                        results.append(
                            {
                                "file": source["name"],
                                "status": "error",
                                "message": str(e),
                            }
                        )

        return results

    def process_source(self, source: Dict[str, Any], temp_dir: str) -> Dict[str, str]:
        """
        Process a single threat intelligence source.

        Args:
            source: Dictionary containing source information
            temp_dir: Temporary directory to store processed files

        Returns:
            Dictionary containing the result of processing
        """
        try:
            logger.info("Processing %s from %s", source["name"], source["url"])

            # Download file
            content = self._download_file(source["url"])

            # Process content
            output_path = self._process_content(source, content, temp_dir)

            # Upload to NG-SIEM
            self._upload_to_ngsiem(output_path)

            return {
                "file": source["name"],
                "status": "success",
                "message": "File processed and uploaded successfully",
            }

        except (requests.RequestException, ValueError, IOError) as e:
            logger.error("Error processing %s: %s", source["name"], str(e))
            return {"file": source["name"], "status": "error", "message": str(e)}

    def _download_file(self, url: str) -> str:
        """
        Download content from a URL.

        Args:
            url: The URL to download from

        Returns:
            The text content of the response

        Raises:
            requests.HTTPError: If the request fails
        """
        # Note: Maintaining original request behavior without adding custom headers
        # and with SSL verification disabled as per requirements
        response = requests.get(url, verify=False, timeout=30)
        response.raise_for_status()  # Raise exception for 4XX/5XX responses

        return response.text.strip()

    def _process_content(
        self, source: Dict[str, Any], content: str, temp_dir: str
    ) -> str:
        """
        Process downloaded content and save to CSV.

        Args:
            source: Dictionary containing source information
            content: The text content to process
            temp_dir: Directory to save processed file

        Returns:
            Path to the processed CSV file
        """
        lines = content.splitlines()
        output_rows = []

        # Process based on source type
        if source["separator"]:
            # Process files with separators (e.g. "value # comment")
            for line in lines:
                if not line or line.startswith("#"):
                    continue

                try:
                    parts = line.split(source["separator"])
                    value = parts[0].strip()

                    # Validate value based on type
                    if source["type"] == "ip" and not self._is_valid_ipv4(value):
                        continue

                    if len(parts) == 2:
                        output_rows.append([value, parts[1].strip()])
                    else:
                        output_rows.append([value, ""])
                except (ValueError, IndexError) as e:
                    logger.warning(
                        "Error parsing line in %s: %s, %s",
                        source["name"],
                        line,
                        str(e),
                    )
        else:
            # Process single-column files
            for line in lines:
                if not line or line.startswith("#"):
                    continue

                value = line.strip()

                # Validate value based on type
                if source["type"] == "ip" and not self._is_valid_ipv4(value):
                    continue

                output_rows.append([value])

        # Create DataFrame and save to CSV
        df = pd.DataFrame(output_rows, columns=source["headers"])

        # Save to CSV
        output_filename = f"ti_{source['name']}.csv"
        output_path = os.path.join(temp_dir, output_filename)
        df.to_csv(output_path, index=False, quoting=csv.QUOTE_MINIMAL)

        logger.info("Processed %d entries from %s", len(df), source["name"])
        return output_path

    def _upload_to_ngsiem(self, file_path: str) -> None:
        """
        Upload a file to NG-SIEM.

        Args:
            file_path: Path to the file to upload

        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If the upload fails
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File does not exist: {file_path}")

        try:
            self.ngsiem_client.upload_file(
                lookup_file=file_path, repository=self.repository
            )
            logger.info(
                "Successfully uploaded %s to repository %s",
                file_path,
                self.repository,
            )
        except Exception as e:
            logger.error("Error uploading file to NG-SIEM: %s", str(e))
            raise IOError(f"Failed to upload to NG-SIEM: {str(e)}") from e

    @staticmethod
    def _is_valid_ipv4(ip_string: str) -> bool:
        """
        Check if a string is a valid IPv4 address.

        Args:
            ip_string: String to check

        Returns:
            True if the string is a valid IPv4 address, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_string)
            return True
        except (ValueError, TypeError):
            return False


@FUNC.handler(method="POST", path="/ti-import-bulk")
def next_gen_siem_csv_import(
    request: Request, config: Optional[Dict[str, object]]  # pylint: disable=unused-argument
) -> Response:
    """
    Handler function for the ti-import-bulk endpoint.

    Downloads, processes, and uploads threat intelligence data to NG-SIEM.

    Args:
        request: The request object containing parameters
        config: Optional configuration values (unused, required by API interface)

    Returns:
        Response object with results or error
    """
    try:
        # Get and validate parameters
        repository = request.body.get("repository", "search-all")
        if not isinstance(repository, str):
            raise ValueError("Repository must be a string")
        repository = repository.strip()

        logger.info("Starting threat intel import to repository: %s", repository)

        # Process all sources
        processor = ThreatIntelProcessor(repository=repository)
        results = processor.process_all_sources()

        # Log results
        success_count = sum(1 for r in results if r["status"] == "success")
        logger.info(
            "Import completed. %d/%d sources processed successfully",
            success_count,
            len(results),
        )

        return Response(body={"results": results}, code=200)

    except (ValueError, IOError) as e:
        logger.error("Error in threat intel import: %s", str(e))
        return Response(errors=[APIError(code=500, message=str(e))], code=500)


if __name__ == "__main__":
    FUNC.run()
