import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
import tempfile
import os
from io import StringIO

# Import the functions to test
from main import (
    is_valid_ipv4,
    download_and_create_csv,
    validate_csv_file,
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

def test_handler_with_invalid_file_redownload(mock_ngsiem):
    """Test handler when existing file is invalid and needs redownload"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )
    request.access_token = "test-token"  # Add access token
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.validate_csv_file') as mock_validate, \
                patch('main.download_and_create_csv') as mock_download:
            # File exists but is invalid, then gets redownloaded
            mock_exists.return_value = True
            mock_validate.return_value = (False, "CSV validation failed: corrupted file")
            mock_download.return_value = ("/tmp/new_file.csv", "CSV file is valid with 100 rows")

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify validation was called for each file
            assert mock_validate.call_count == len(FILES_TO_PROCESS)
            
            # Verify download was called for each file (since all were invalid)
            assert mock_download.call_count == len(FILES_TO_PROCESS)

            # Verify NGSIEM upload was called for each file
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS)

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

def test_download_and_create_csv_ip_with_separator(mock_requests_get):
    """Test downloading and creating CSV for IP file with separator"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip", "destination.ip.details"],
        "separator": " # "
    }

    output_path, validation_message = download_and_create_csv(file_info)

    try:
        # Verify the file was created
        assert os.path.exists(output_path)
        assert "CSV file is valid with 2 rows" in validation_message

        # Verify content
        df = pd.read_csv(output_path)
        assert len(df) == 2  # Two valid IPs
        assert df.loc[0]["destination.ip"] == "192.168.1.1"
        # verify details is na for the first ip with no comment
        assert pd.isna(df.loc[0]["destination.ip.details"])
        assert df.loc[1]["destination.ip"] == "10.0.0.1"
        assert df.loc[1]["destination.ip.details"] == "Some comment"
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)

def test_download_and_create_csv_ip_without_separator(mock_requests_get):
    """Test downloading and creating CSV for IP file without separator"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_IP_FILE_CONTENT

    file_info = {
        "url": "https://example.com/iplist.txt",
        "name": "ip-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path, validation_message = download_and_create_csv(file_info)

    try:
        # Verify content
        df = pd.read_csv(output_path)
        assert len(df) == 1  # Only 1 valid IP
        assert df.loc[0]["destination.ip"] == "192.168.1.1"
        assert "CSV file is valid with 1 rows" in validation_message
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)

def test_download_and_create_csv_domain(mock_requests_get):
    """Test downloading and creating CSV for domain file"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = MOCK_DOMAIN_FILE_CONTENT

    file_info = {
        "url": "https://example.com/domainlist.txt",
        "name": "domain-test",
        "headers": ["dns.domain.name", "dns.domain.details"],
        "separator": " # domain - "
    }

    output_path, validation_message = download_and_create_csv(file_info)

    try:
        # Verify content
        df = pd.read_csv(output_path)
        assert len(df) == 2
        assert "example.com" in df["dns.domain.name"].values
        assert "malicious.com" in df["dns.domain.name"].values
        assert "Example Domain" in df["dns.domain.details"].values
        assert "Malicious Domain" in df["dns.domain.details"].values
        assert "CSV file is valid with 2 rows" in validation_message
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)

def test_download_and_create_csv_request_error(mock_requests_get):
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
        download_and_create_csv(file_info)

    assert "Failed to download" in str(excinfo.value)

def test_handler_success_with_existing_files(mock_ngsiem):
    """Test successful handler execution with existing CSV files"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.validate_csv_file') as mock_validate:
            # Mock that files exist and are valid
            mock_exists.return_value = True
            mock_validate.return_value = (True, "CSV file is valid with 100 rows")

            # execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify validation was called for each file
            assert mock_validate.call_count == len(FILES_TO_PROCESS)

            # Verify NGSIEM upload was called for each file
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS)
            
            # Verify logger was called
            assert mock_logger.info.call_count >= len(FILES_TO_PROCESS)

def test_handler_with_download_error(mock_ngsiem):
    """Test handler with download error for one file"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        # Setup mocks - first file fails to download, others succeed
        with patch('os.path.exists') as mock_exists, \
                patch('main.download_and_create_csv') as mock_download:
            mock_exists.return_value = False
            mock_download.side_effect = [
                Exception("Failed to download"),  # First file fails
                *[("/tmp/test_file.csv", "CSV file is valid with 50 rows")] * (len(FILES_TO_PROCESS) - 1)  # Rest succeed
            ]

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify first file has error
            assert response.body["results"][0]["status"] == "error"
            assert "Failed to download" in response.body["results"][0]["message"]

            # Verify NGSIEM upload was called for successful files only
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS) - 1

def test_handler_with_missing_files_download(mock_ngsiem):
    """Test handler when files need to be downloaded"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.download_and_create_csv') as mock_download:
            # Files don't exist, need to download
            mock_exists.return_value = False
            mock_download.return_value = ("/tmp/test_file.csv", "CSV file is valid with 50 rows")

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)

            # Verify download was called for each file
            assert mock_download.call_count == len(FILES_TO_PROCESS)

            # Verify NGSIEM upload was called for each file
            assert mock_ngsiem.upload_file.call_count == len(FILES_TO_PROCESS)

def test_handler_global_exception(mock_ngsiem):
    """Test handler with exceptions during file processing"""
    # Create request that will cause an exception
    request = Request(
        body=None,  # This will cause an exception when trying to access .get()
    )
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        # Mock an actual exception during processing by making os.path.exists fail
        with patch('os.path.exists', side_effect=Exception('Simulated filesystem error')):
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)
            # The function handles errors gracefully and returns 200 with individual file errors
            assert response.code == 200
            assert "results" in response.body
            assert len(response.body["results"]) == len(FILES_TO_PROCESS)
            # All files should have error status
            for result in response.body["results"]:
                assert result["status"] == "error"
                assert "Simulated filesystem error" in result["message"]


def test_download_and_create_csv_empty_content(mock_requests_get):
    """Test processing empty file content"""
    mock_get, mock_response = mock_requests_get
    mock_response.text = ""

    file_info = {
        "url": "https://example.com/empty.txt",
        "name": "empty-test",
        "headers": ["destination.ip"],
        "separator": None
    }

    output_path, validation_message = download_and_create_csv(file_info)

    try:
        # Verify content - empty CSV should still be valid, just with 0 rows
        df = pd.read_csv(output_path)
        assert len(df) == 0
        assert "CSV file is valid with 0 rows" in validation_message
    finally:
        # Cleanup
        if os.path.exists(output_path):
            os.remove(output_path)


def test_validate_csv_file_valid():
    """Test CSV validation with valid file"""
    # Create a temporary CSV file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ip,description\n192.168.1.1,test ip\n10.0.0.1,another ip\n")
        temp_file = f.name
    
    try:
        is_valid, message = validate_csv_file(temp_file)
        assert is_valid is True
        assert "CSV file is valid with 2 rows" in message
    finally:
        os.unlink(temp_file)

def test_validate_csv_file_empty():
    """Test CSV validation with empty file"""
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ip,description\n")
        temp_file = f.name
    
    try:
        is_valid, message = validate_csv_file(temp_file)
        assert is_valid is True  # Empty CSV files are now considered valid
        assert "CSV file is valid with 0 rows" in message
    finally:
        os.unlink(temp_file)

def test_validate_csv_file_nonexistent():
    """Test CSV validation with non-existent file"""
    is_valid, message = validate_csv_file("/path/that/does/not/exist.csv")
    assert is_valid is False
    assert "CSV validation failed" in message

def test_handler_default_repository(mock_ngsiem):
    """Test handler with default repository"""
    # Create request with no repository specified
    request = Request(
        body={},  # No repository specified
    )
    request.access_token = "test-token"  # Add access token
    
    # Create mock logger
    mock_logger = MagicMock()

    # Setup mocks
    with patch('crowdstrike.foundry.function.Function.handler', new=mock_handler):
        import importlib
        import main
        importlib.reload(main)

        with patch('os.path.exists') as mock_exists, \
                patch('main.validate_csv_file') as mock_validate:
            mock_exists.return_value = True
            mock_validate.return_value = (True, "CSV file is valid with 100 rows")

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify results
            assert response.code == 200

            # Verify NGSIEM upload was called with default repository
            calls = mock_ngsiem.upload_file.call_args_list
            for call in calls:
                args, kwargs = call
                assert kwargs["repository"] == "search-all"  # Default value

def test_handler_ngsiem_api_error(mock_ngsiem):
    """Test handler with NGSIEM API error"""
    # Create request
    request = Request(
        body={"repository": "custom-repo"},
    )
    request.access_token = "test-token"  # Add access token
    
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
                patch('main.validate_csv_file') as mock_validate:
            mock_exists.return_value = True
            mock_validate.return_value = (True, "CSV file is valid with 100 rows")

            # Execute handler
            response = main.next_gen_siem_csv_import(request, {}, mock_logger)

            # Verify error response
            assert response.code == 400
            assert len(response.errors) == 1
            assert response.errors[0].code == 400
            assert "NGSIEM upload error" in response.errors[0].message
            assert "Invalid file format" in response.errors[0].message
