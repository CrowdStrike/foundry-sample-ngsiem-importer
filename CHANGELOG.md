# Changelog

All notable changes to the Threat Intel Import to NG-SIEM project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-06-12

### Added
- Object-oriented design with the new `ThreatIntelProcessor` class
- Concurrent processing of threat intelligence sources for better performance
- Request timeouts to prevent hanging on slow connections
- Comprehensive logging throughout the application
- Type annotations for better IDE support and code readability
- More detailed docstrings for all functions and methods
- Features & Improvements section in README.md
- Enhanced descriptions in JSON schemas with examples
- Additional dependency on urllib3 for better HTTP handling

### Changed
- Improved error handling with specific exception types
- Renamed `func` constant to `FUNC` to follow Python naming conventions
- Replaced f-strings in logging with lazy string formatting for better performance
- Enhanced JSON schemas with consistent formatting and better documentation
- Updated CSV file naming to use f-strings for consistency
- More specific error propagation with `raise from` pattern
- Refactored code for better modularity and readability

### Fixed
- Fixed inconsistent indentation in JSON schema files
- Added proper exception handling in IP address validation
- Fixed potential issues with error reporting in file processing
- Fixed logging format to follow best practices
- All linting issues resolved, achieving 10/10 pylint score

## [1.0.0] - 2025-06-11

### Added
- Initial release of the Threat Intel Import to NG-SIEM application
- Support for downloading threat intelligence from multiple sources:
  - botvrij.eu (domains, SHA1 hashes, IP addresses)
  - Emerging Threats (compromised IPs)
  - dan.me.uk (Tor exit node IPs)
  - urlhaus.abuse.ch (malicious URLs)
- Conversion of data to CSV files
- Upload to NG-SIEM as lookup files
- Daily scheduled workflow
