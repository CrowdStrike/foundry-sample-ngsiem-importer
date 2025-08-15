from crowdstrike.foundry.function import APIError, Function, Request, Response
import requests
import pandas as pd
import os
import ipaddress
import csv
from typing import Dict, Optional
from falconpy import NGSIEM

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

def validate_csv_file(file_path):
    """Validate that the file is a proper CSV file"""
    try:
        df = pd.read_csv(file_path)
        # Empty CSV files are still valid, just with 0 rows
        return True, f"CSV file is valid with {len(df)} rows"
    except Exception as e:
        return False, f"CSV validation failed: {str(e)}"

def download_and_create_csv(file_info):
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

        # Save to CSV in the functions directory
        output_filename = f"ti_{file_info['name']}.csv"
        output_path = os.path.join(os.path.dirname(__file__), output_filename)
        df.to_csv(output_path, index=False, quoting=csv.QUOTE_MINIMAL)

        # Validate the created CSV file
        is_valid, validation_message = validate_csv_file(output_path)
        if not is_valid:
            raise Exception(f"CSV validation failed for {file_info['name']}: {validation_message}")

        return output_path, validation_message
    except Exception as e:
        raise Exception(f"Error processing {file_info['name']}: {str(e)}")

def upload_file_to_ngsiem(file_path, repository):
    """Upload file to NGSIEM using FalconPy client"""
    falcon = NGSIEM(debug=True)

    try:
        response = falcon.upload_file(
            lookup_file=file_path,
            repository=repository
        )
        return response
    except Exception as e:
        return {
            "status_code": 500,
            "error": {"message": str(e)}
        }

@func.handler(method='POST', path='/ti-import-bulk')
def next_gen_siem_csv_import(request: Request, config: Optional[Dict[str, object]], logger) -> Response:
    try:
        # Get repository from request body, default to "search-all"
        repository = request.body.get("repository", "search-all") if request.body else "search-all"

        results = []

        # Process each file
        for file_info in FILES_TO_PROCESS:
            try:
                # Check if CSV file already exists in functions directory
                output_filename = f"ti_{file_info['name']}.csv"
                output_path = os.path.join(os.path.dirname(__file__), output_filename)

                if os.path.exists(output_path):
                    # File exists, validate it and use it
                    is_valid, validation_message = validate_csv_file(output_path)
                    if not is_valid:
                        # Re-download if validation fails
                        logger.info(f"Existing file {output_filename} is invalid, re-downloading: {validation_message}")
                        output_path, validation_message = download_and_create_csv(file_info)
                    else:
                        logger.info(f"Using existing file {output_filename}: {validation_message}")
                else:
                    # File doesn't exist, download and create it
                    logger.info(f"File {output_filename} not found, downloading and creating...")
                    output_path, validation_message = download_and_create_csv(file_info)

                logger.info(f"File validation for {file_info['name']}: {validation_message}")

                # Upload the file to NGSIEM
                response = upload_file_to_ngsiem(output_path, repository)

                # Log the raw response for troubleshooting
                logger.info(f"API response for {file_info['name']}: {response}")

                if response.get("status_code", 200) >= 400:
                    error_message = response.get("error", {}).get("message", "Unknown error")

                    return Response(
                        code=response.get("status_code", 500),
                        errors=[APIError(
                            code=response.get("status_code", 500),
                            message=f"NGSIEM upload error for {file_info['name']}: {error_message}"
                        )]
                    )

                results.append({
                    "file": file_info["name"],
                    "status": "success",
                    "message": f"File processed and uploaded successfully. {validation_message}",
                    "path": output_path
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
