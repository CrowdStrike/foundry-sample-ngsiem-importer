"""Unit tests for the TI feed importer function."""

import csv
import importlib
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from crowdstrike.foundry.function import Request

# Import the functions to test
from main import (
    is_valid_ipv4,
    process_file,
    FILES_TO_PROCESS
)


def mock_handler(*_args, **_kwargs):
    """Mock decorator that replaces @FUNC.handler for testing."""
    def identity(func):
        return func
    return identity


# Test data
MOCK_IP_FILE_CONTENT = """
# This is a comment
192.168.1.1
invalid.ip
10.0.0.1 # Some comment
"""

MOCK_DOMAIN_FILE_CONTENT = """
example.com # domain - Example Domain
malicious.com # domain - Malicious Domain
# Comment line
"""

MOCK_SHA1_FILE_CONTENT = """
deadbeefdeadbeefdeadbeefdeadbeefdeadbeef # sha1 - Test Malware
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # sha1 - Another Malware
"""

MOCK_URL_FILE_CONTENT = """
https://example.com/malware.exe
https://malicious.com/backdoor.php
"""

@pytest.fixture(name="temp_dir")
def fixture_temp_dir():
    """Fixture to create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp

@pytest.fixture(name="requests_get")
def fixture_requests_get():
    """Fixture to mock requests.get."""
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        yield mock_get, mock_response

@pytest.fixture(name="ngsiem")
def fixture_ngsiem():
    """Fixture to mock NGSIEM client."""
    with patch('falconpy.NGSIEM') as mock_ngsiem_class:
        mock_instance = MagicMock()
        mock_instance.upload_file.return_value = {
            "status_code": 200,
            "body": {"message": "File uploaded successfully"}
        }
        mock_ngsiem_class.return_value = mock_instance
        yield mock_instance

def test_is_valid_ipv4():
    """Test IP validation function."""
    # Valid IPs
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("10.0.0.1") is True
    assert is_valid_ipv4("0.0.0.0") is True
    assert is_valid_ipv4("255.255.255.255") is True

    # Invalid IPs
    assert is_valid_ipv4("256.0.0.1") is False
    assert is_valid_ipv4("192.168.1") is False
    assert is_valid_ipv4("example.com") is False
    assert is_valid_ipv4("") is False
    assert is_valid_ipv4("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is False  # IPv6

def test_process_file_ip_with_separator(requests_get, temp_dir):
    """Test processing IP file with separator."""
    _, mock_response = requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip", "destination.ip.details"],
        "separator": " # "
    }

    output_path = process_file(file_info, temp_dir)

    assert os.path.exists(output_path)

    with open(output_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)
    assert rows[0] == ["destination.ip", "destination.ip.details"]
    assert len(rows) == 3  # header + 2 data rows
    assert rows[1][0] == "192.168.1.1"
    assert rows[1][1] == ""  # no comment for first IP
    assert rows[2][0] == "10.0.0.1"
    assert rows[2][1] == "Some comment"

def test_process_file_ip_without_separator(requests_get, temp_dir):
    """Test processing IP file without separator."""
    _, mock_response = requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, temp_dir)

    with open(output_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)
    assert rows[0] == ["destination.ip"]
    assert len(rows) == 2  # header + 1 data row
    assert rows[1][0] == "192.168.1.1"

def test_process_file_domain(requests_get, temp_dir):
    """Test processing domain file."""
    _, mock_response = requests_get
    mock_response.text = MOCK_DOMAIN_FILE_CONTENT

    file_info = {
        "url": "https://example.com/domainlist.txt",
        "name": "domain-test",
        "headers": ["dns.domain.name", "dns.domain.details"],
        "separator": " # domain - "
    }

    output_path = process_file(file_info, temp_dir)

    with open(output_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        rows = list(reader)
    assert rows[0] == ["dns.domain.name", "dns.domain.details"]
    assert len(rows) == 3  # header + 2 data rows
    assert rows[1][0] == "example.com"
    assert rows[1][1] == "Example Domain"
    assert rows[2][0] == "malicious.com"
    assert rows[2][1] == "Malicious Domain"

def test_process_file_request_error(requests_get, temp_dir):
    """Test handling of request errors."""
    _, mock_response = requests_get
    mock_response.raise_for_status.side_effect = Exception("Failed to download")

    file_info = {
        "url": "https://example.com/error.txt",
        "name": "error-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    with pytest.raises(Exception) as excinfo:
        process_file(file_info, temp_dir)

    assert "Failed to download" in str(excinfo.value)


def _reload_main_with_mock_handler():
    """Reload main module with mocked handler decorator."""
    import main  # pylint: disable=import-outside-toplevel
    importlib.reload(main)
    return main


def test_handler_success(ngsiem):
    """Test successful handler execution."""
    request = Request(body={"repository": "custom-repo"})
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)
            assert mock_process_file.call_count == len(FILES_TO_PROCESS)
            assert ngsiem.upload_file.call_count == len(FILES_TO_PROCESS)


def test_handler_with_skipped_files(ngsiem):
    """Test handler with some feeds returning no data (skipped)."""
    request = Request(body={"repository": "custom-repo"})
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.side_effect = [
                None, None,
                *["/tmp/test_file.csv"] * (len(FILES_TO_PROCESS) - 2)
            ]

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)
            assert response.body["results"][0]["status"] == "skipped"
            assert response.body["results"][1]["status"] == "skipped"
            assert ngsiem.upload_file.call_count == len(FILES_TO_PROCESS) - 2

def test_handler_with_processing_error(ngsiem):
    """Test handler with processing error for one file."""
    request = Request(body={"repository": "custom-repo"})
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.side_effect = [
                RuntimeError("Failed to process"),
                *["/tmp/test_file.csv"] * (len(FILES_TO_PROCESS) - 1)
            ]

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)
            assert response.body["results"][0]["status"] == "error"
            assert "Failed to process" in response.body["results"][0]["message"]
            assert ngsiem.upload_file.call_count == len(FILES_TO_PROCESS) - 1

def test_handler_with_missing_files(ngsiem):
    """Test handler with processing error for all files."""
    request = Request(body={"repository": "custom-repo"})
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = False
            mock_process_file.return_value = "/tmp/test_file.csv"

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)
            assert response.body["results"][0]["status"] == "error"
            assert response.body["results"][0]["message"] == "File does not exist"
            assert ngsiem.upload_file.call_count == 0

def test_handler_global_exception(ngsiem):  # pylint: disable=unused-argument
    """Test handler with a global exception."""
    request = Request(body=None)
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        response = main.next_gen_siem_csv_import(request, {}, mock_logger)
        assert response.code == 500
        assert len(response.errors) == 1
        assert response.errors[0].code == 500


def test_process_file_empty_content(requests_get, temp_dir):
    """Test processing empty file content."""
    _, mock_response = requests_get
    mock_response.text = ""

    file_info = {
        "url": "https://example.com/empty.txt",
        "name": "empty-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, temp_dir)
    assert output_path is None


def test_process_file_only_comments(requests_get, temp_dir):
    """Test processing file with only comments."""
    _, mock_response = requests_get
    mock_response.text = "# Comment 1\n# Comment 2\n"

    file_info = {
        "url": "https://example.com/comments.txt",
        "name": "comments-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, temp_dir)
    assert output_path is None

def test_handler_default_repository(ngsiem):
    """Test handler with default repository."""
    request = Request(body={})
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            ngsiem.upload_file.assert_called_with(
                lookup_file="/tmp/test_file.csv",
                repository="search-all"
            )

def test_handler_ngsiem_api_error(ngsiem):
    """Test handler with NGSIEM API error."""
    request = Request(body={"repository": "custom-repo"})
    mock_logger = MagicMock()

    ngsiem.upload_file.return_value = {
        "status_code": 400,
        "error": {
            "message": "Invalid file format"
        }
    }

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        main = _reload_main_with_mock_handler()

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            for result in response.body["results"]:
                assert result["status"] == 400
                assert "NGSIEM upload error:" in result["message"]
