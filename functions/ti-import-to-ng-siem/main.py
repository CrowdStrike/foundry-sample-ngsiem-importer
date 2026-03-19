"""Threat intelligence feed importer for CrowdStrike Falcon Next-Gen SIEM."""

import csv
import ipaddress
import os
import tempfile
from typing import Dict

from crowdstrike.foundry.function import APIError, Function, Request, Response
from falconpy import NGSIEM
import requests

FUNC = Function.instance()

# Define the files to process
FILES_TO_PROCESS = [
    {
        "url": "https://www.botvrij.eu/data/ioclist.domain",
        "name": "domain-botvrij-eu",
        "headers": ["dns.domain.name", "dns.domain.details"],
        "separator": " # domain - "
    },
    {
        "url": "https://www.botvrij.eu/data/ioclist.sha1",
        "name": "sha1-botvrij-eu",
        "headers": ["file.hash.sha1", "file.hash.sha1.details"],
        "separator": " # sha1 - "
    },
    {
        "url": "https://www.botvrij.eu/data/ioclist.ip-dst",
        "name": "ip-botvrij-eu",
        "headers": ["destination.ip", "destination.ip.details"],
        "separator": " # ip-dst - "
    },
    {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "name": "ip-emerging-threats",
        "headers": ["destination.ip"],
        "separator": None
    },
    {
        "url": "https://www.dan.me.uk/torlist/",
        "name": "ip-dan-me-uk-tor",
        "headers": ["destination.ip"],
        "separator": None
    },
    {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "name": "url-abuse-ch",
        "headers": ["url.original"],
        "separator": None
    }
]


def is_valid_ipv4(ip_string):
    """Check whether the given string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except ValueError:
        return False


def _process_lines_with_separator(lines, file_info):
    """Parse lines that use a separator to split value and description."""
    rows = []
    separator = file_info["separator"]
    is_ip = file_info["name"].startswith("ip-")
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if is_ip and not is_valid_ipv4(line.split(separator)[0].strip()):
            continue
        parts = line.split(separator)
        if len(parts) == 2:
            rows.append([parts[0].strip(), parts[1].strip()])
        else:
            rows.append([parts[0].strip(), ""])
    return rows


def _process_lines_single_column(lines, file_info):
    """Parse lines that contain a single value per row."""
    rows = []
    is_ip = file_info["name"].startswith("ip-")
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if is_ip:
            if is_valid_ipv4(line.strip()):
                rows.append([line.strip()])
        else:
            rows.append([line.strip()])
    return rows


def process_file(file_info, temp_dir):
    """Download a TI feed, parse it into CSV rows, and write to a temp file."""
    try:
        response = requests.get(file_info["url"], timeout=60)
        response.raise_for_status()

        content = response.text.strip()
        lines = content.splitlines()

        if file_info["separator"]:
            output_rows = _process_lines_with_separator(lines, file_info)
        else:
            output_rows = _process_lines_single_column(lines, file_info)

        if not output_rows:
            return None

        output_filename = f"ti_{file_info['name']}.csv"
        output_path = os.path.join(temp_dir, output_filename)
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(file_info["headers"])
            writer.writerows(output_rows)

        return output_path
    except (requests.RequestException, OSError, ValueError) as e:
        raise RuntimeError(
            f"Error processing {file_info['name']}: {e}"
        ) from e


@FUNC.handler(method='POST', path='/ti-import-bulk')
def next_gen_siem_csv_import(request: Request, _config: Dict[str, object] | None, logger) -> Response:
    """Handle bulk TI feed import and upload to Falcon Next-Gen SIEM."""
    try:
        repository = request.body.get('repository', 'search-all').strip()
        ngsiem = NGSIEM()

        with tempfile.TemporaryDirectory() as temp_dir:
            results = []

            for file_info in FILES_TO_PROCESS:
                try:
                    output_path = process_file(file_info, temp_dir)
                    if output_path is None:
                        logger.info("No data rows for %s, skipping upload", file_info['name'])
                        results.append({
                            "file": file_info["name"],
                            "status": "skipped",
                            "message": "Feed returned no data rows"
                        })
                        continue
                    if not os.path.exists(output_path):
                        raise FileNotFoundError("File does not exist")

                    response = ngsiem.upload_file(lookup_file=output_path, repository=repository)
                    logger.info("API response: %s", response)

                    if response["status_code"] >= 400:
                        error_messages = response.get("body", {}).get("errors", [])
                        results.append({
                            "file": output_path,
                            "status": response["status_code"],
                            "message": f"NGSIEM upload error: {error_messages}"
                        })
                        continue

                    results.append({
                        "file": output_path,
                        "status": "success",
                        "message": "File processed and uploaded successfully"
                    })
                except (RuntimeError, OSError, requests.RequestException, KeyError) as e:
                    results.append({
                        "file": file_info["name"],
                        "status": "error",
                        "message": str(e)
                    })

        return Response(
            body={"results": results},
            code=200
        )

    except (AttributeError, TypeError, ValueError) as e:
        return Response(
            errors=[APIError(code=500, message=str(e))],
            code=500
        )


if __name__ == '__main__':
    FUNC.run()
