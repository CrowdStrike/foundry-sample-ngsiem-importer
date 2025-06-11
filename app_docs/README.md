# Threat Intel Import to NG-SIEM sample Foundry app

This app has a Python function that downloads threat intelligence from multiple public sources:

- _botvrij.eu_: Collects malicious domains, SHA1 file hashes, and IP addresses
- _Emerging Threats_: Gathers compromised IP addresses
- _dan.me.uk_: Downloads Tor exit node IP addresses
- _urlhaus.abuse.ch_: Retrieves malicious URLs

The function then converts this data to CSV files by:

- Parsing various file formats and structures
- Validating entries (especially IP addresses)
- Organizing the data into appropriate fields for SIEM ingestion:
    - IP addresses: destination.ip
    - Domains: dns.domain.name
    - File hashes: file.hash.sha1
    - URLs: url.original

Finally, it uploads lookup files to NG-SIEM using FalconPy:

- Uploads CSVs to the specified NG-SIEM repository (default: "search-all")
- Returns status information for each processed file

After installing this app, you can find its workflow in **Fusion SOAR** > **Workflows**. This workflow:

- Runs automatically at 3:00 AM Eastern Time (America/New_York) every day
- Can also be triggered manually through the CrowdStrike platform

The source code for this app can be found on GitHub: <https://github.com/CrowdStrike/foundry-sample-ngsiem-importer>. 
