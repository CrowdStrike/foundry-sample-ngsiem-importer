from crowdstrike.foundry.function import APIError, Function, Request, Response
from falconpy import NGSIEM
import requests
import pandas as pd
import tempfile
import os
import ipaddress
import csv
from typing import Union, Dict

func = Function.instance()

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
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except:
        return False

def process_file(file_info, temp_dir):
    try:
        # Download file
        response = requests.get(file_info["url"])
        response.raise_for_status()

        # Read content
        content = response.text.strip()
        lines = content.splitlines()

        # Process based on file type
        output_rows = []

        if file_info["separator"]:
            # For files with separators
            for line in lines:
                if line and not line.startswith('#'):
                    if file_info["name"].startswith("ip-") and not is_valid_ipv4(line.split(file_info["separator"])[0].strip()):
                        continue
                    parts = line.split(file_info["separator"])
                    if len(parts) == 2:
                        output_rows.append([parts[0].strip(), parts[1].strip()])
                    else:
                        output_rows.append([parts[0].strip(), ""])
        else:
            # For single column files
            for line in lines:
                if line and not line.startswith('#'):
                    if file_info["name"].startswith("ip-"):
                        if is_valid_ipv4(line.strip()):
                            output_rows.append([line.strip()])
                    else:
                        output_rows.append([line.strip()])

        # Create DataFrame
        df = pd.DataFrame(output_rows, columns=file_info["headers"])

        # Save to CSV
        output_filename = f"ti_{file_info['name']}.csv"
        output_path = os.path.join(temp_dir, output_filename)
        df.to_csv(output_path, index=False, quoting=csv.QUOTE_MINIMAL)

        return output_path
    except Exception as e:
        raise Exception(f"Error processing {file_info['name']}: {str(e)}")

@func.handler(method='POST', path='/ti-import-bulk')
def next_gen_siem_csv_import(request: Request, config: Dict[str, object] | None, logger) -> Response:
    try:
        # Get parameters
        repository = request.body.get('repository', 'search-all').strip()

        # Initialize NGSIEM client
        ngsiem = NGSIEM()

        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            results = []

            # Process each file
            for file_info in FILES_TO_PROCESS:
                try:
                    output_path = process_file(file_info, temp_dir)
                    if not os.path.exists(output_path):
                        raise FileNotFoundError("File does not exist")

                    response = ngsiem.upload_file(lookup_file=output_path, repository=repository)

                    # Log the raw response for troubleshooting
                    logger.info(f"API response: {response}")

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
                        "message": f"File processed and uploaded successfully"
                    })
                except Exception as e:
                    results.append({
                        "file": file_info["name"],
                        "status": "error",
                        "message": str(e)
                    })

        return Response(
            body={"results": results},
            code=200
        )

    except Exception as e:
        return Response(
            errors=[APIError(code=500, message=str(e))],
            code=500
        )

if __name__ == '__main__':
    func.run()
