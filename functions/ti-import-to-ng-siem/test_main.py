import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
import tempfile
import os
from io import StringIO

# Import the functions to test
from main import (
    is_valid_ipv4,
    process_file,
    FILES_TO_PROCESS
)

def mock_handler(*args, **kwargs):
    def identity(func):
        return func
    return identity


from crowdstrike.foundry.function import Request, Response, APIError

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

@pytest.fixture
def mock_temp_dir():
    """Fixture to create a temporary directory for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir

@pytest.fixture
def mock_requests_get():
    """Fixture to mock requests.get"""
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        yield mock_get, mock_response

@pytest.fixture
def mock_ngsiem():
    """Fixture to mock NGSIEM client"""
    with patch('falconpy.NGSIEM') as mock_ngsiem_class:
        mock_instance = MagicMock()
        # Mock successful upload response
        mock_instance.upload_file.return_value = {
            "status_code": 200,
            "body": {"message": "File uploaded successfully"}
        }
        mock_ngsiem_class.return_value = mock_instance
        yield mock_instance

def test_is_valid_ipv4():
    """Test IP validation function"""
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

def test_process_file_ip_with_separator(mock_requests_get, mock_temp_dir):
    """Test processing IP file with separator"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip", "destination.ip.details"],
        "separator": " # "
    }

    output_path = process_file(file_info, mock_temp_dir)

    # Verify the file was created
    assert os.path.exists(output_path)

    # Verify content
    df = pd.read_csv(output_path)
    assert len(df) == 2  # Two valid IPs
    assert df.loc[0]["destination.ip"] == "192.168.1.1"
    # verify details is na for the first ip with no comment
    assert pd.isna(df.loc[0]["destination.ip.details"])
    assert df.loc[1]["destination.ip"] == "10.0.0.1"
    assert df.loc[1]["destination.ip.details"] == "Some comment"

def test_process_file_ip_without_separator(mock_requests_get, mock_temp_dir):
    """Test processing IP file without separator"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, mock_temp_dir)

    # Verify content
    df = pd.read_csv(output_path)
    assert len(df) == 1  # Only 1 valid IP
    assert df.loc[0]["destination.ip"] == "192.168.1.1"

def test_process_file_domain(mock_requests_get, mock_temp_dir):
    """Test processing domain file"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_DOMAIN_FILE_CONTENT

    file_info = {
        "url": "https://example.com/domainlist.txt",
        "name": "domain-test",
        "headers": ["dns.domain.name", "dns.domain.details"],
        "separator": " # domain - "
    }

    output_path = process_file(file_info, mock_temp_dir)

    # Verify content
    df = pd.read_csv(output_path)
    assert len(df) == 2
    assert "example.com" in df["dns.domain.name"].values  # lgtm[py/incomplete-url-substring-sanitization]
    assert "malicious.com" in df["dns.domain.name"].values  # lgtm[py/incomplete-url-substring-sanitization]
    assert "Example Domain" in df["dns.domain.details"].values
    assert "Malicious Domain" in df["dns.domain.details"].values

def test_process_file_request_error(mock_requests_get, mock_temp_dir):
    """Test handling of request errors"""
    mock_get, mock_response = mock_requests_get
    mock_response.raise_for_status.side_effect = Exception("Failed to download")

    file_info = {
        "url": "https://example.com/error.txt",
        "name": "error-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    with pytest.raises(Exception) as excinfo:
        process_file(file_info, mock_temp_dir)

    assert "Failed to download" in str(excinfo.value)

def test_handler_success(mock_ngsiem):
    """Test successful handler execution"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )

    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            # execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify all files were processed
            assert mock_process_file.call_count == len(FILES_TO_PROCESS)

            # Verify NGSIEM upload was called
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS)

            # Verify logger was called
            assert mock_logger.info.call_count == len(FILES_TO_PROCESS)

def test_handler_with_processing_error(mock_ngsiem):
    """Test handler with processing error for one file"""

    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )

    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        # Setup mocks - first file fails, others succeed
        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.side_effect = [
                Exception("Failed to process"),  # First file fails
                *["/tmp/test_file.csv"] * (len(FILES_TO_PROCESS) - 1)  # Rest succeed
            ]

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify first file has error
            assert response.body["results"][0]["status"] == "error"
            assert "Failed to process" in response.body["results"][0]["message"]

            # Verify NGSIEM upload was called for successful files only
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS) - 1

def test_handler_with_missing_files(mock_ngsiem):
    """Test handler with processing error for all files"""

    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )

    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        # Setup mocks - first file fails, others succeed
        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = False
            mock_process_file.return_value = "/tmp/test_file.csv"

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify all files have error
            assert response.body["results"][0]["status"] == "error"
            assert response.body["results"][0]["message"] == "File does not exist"

            # Verify NGSIEM upload was not called
            assert mock_ngsiem.upload_file.call_count == 0

def test_handler_global_exception(mock_ngsiem):
    """Test handler with a global exception"""

    # Create request that will cause an exception
    request = Request(
        body=None,  # This will cause an exception when trying to access .get()
    )

    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        response = main.next_gen_siem_csv_import(request, {}, mock_logger)
        # Verify error response
        assert response.code == 500
        assert len(response.errors) == 1
        assert response.errors[0].code == 500


def test_process_file_empty_content(mock_requests_get, mock_temp_dir):
    """Test processing empty file content"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = ""

    file_info = {
        "url": "https://example.com/empty.txt",
        "name": "empty-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, mock_temp_dir)

    # Verify content
    df = pd.read_csv(output_path)
    assert len(df) == 0


def test_process_file_only_comments(mock_requests_get, mock_temp_dir):
    """Test processing file with only comments"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = "# Comment 1\n# Comment 2\n"

    file_info = {
        "url": "https://example.com/comments.txt",
        "name": "comments-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path = process_file(file_info, mock_temp_dir)

    # Verify content
    df = pd.read_csv(output_path)
    assert len(df) == 0

def test_handler_default_repository(mock_ngsiem):
    """Test handler with default repository"""

    # Create request with no repository specified
    request = Request(
        body={},  # No repository specified
    )

    # Create mock logger
    mock_logger = MagicMock()

    # Setup mocks
    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200

            # Verify NGSIEM upload was called with default repository
            mock_ngsiem.upload_file.assert_called_with(
                lookup_file="/tmp/test_file.csv",
                repository="search-all"  # Default value
            )

def test_handler_ngsiem_api_error(mock_ngsiem):
    """Test handler with NGSIEM API error"""

    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )

    # Create mock logger
    mock_logger = MagicMock()

    # Mock NGSIEM to return an error response
    mock_ngsiem.upload_file.return_value = {
        "status_code": 400,
        "error": {
            "message": "Invalid file format"
        }
    }

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.process_file') as mock_process_file:
            mock_exists.return_value = True
            mock_process_file.return_value = "/tmp/test_file.csv"

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify response is still successful (bulk processing continues despite individual errors)
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify all files have error status due to NGSIEM API error
            for result in response.body["results"]:
                assert result["status"] == 400
                assert "NGSIEM upload error:" in result["message"]
