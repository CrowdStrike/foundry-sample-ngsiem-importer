![CrowdStrike Falcon](/images/cs-logo.png?raw=true)

# NG-SIEM Importer sample Foundry app

The NG-SIEM Importer sample Foundry app is a community-driven, open source project which serves as an example of an app which can be built using CrowdStrike's Foundry ecosystem. `foundry-sample-ngsiem-importer` is an open source project, not a CrowdStrike product. As such, it carries no formal support, expressed or implied.

This app is one of several App Templates included in Foundry that you can use to jumpstart your development. It comes complete with a set of preconfigured capabilities aligned to its business purpose. Deploy this app from the Templates page with a single click in the Foundry UI, or create an app from this template using the CLI.

> [!IMPORTANT]  
> To view documentation and deploy this sample app, you need access to the Falcon console.

## Description

The NG-SIEM Importer sample Foundry app automates the collection, processing, and ingestion of threat intelligence data into CrowdStrike's Next-Generation Security Information and Event Management (NG-SIEM) platform.

## Prerequisites

* The Foundry CLI (instructions below).
* Python 3.9+ (needed if modifying the app's functions). See [Python For Beginners](https://www.python.org/about/gettingstarted/) for installation instructions.

### Install the Foundry CLI

You can install the Foundry CLI with Scoop on Windows or Homebrew on Linux/macOS.

**Windows**:

Install [Scoop](https://scoop.sh/). Then, add the Foundry CLI bucket and install the Foundry CLI.

```shell
scoop bucket add foundry https://github.com/crowdstrike/scoop-foundry-cli.git
scoop install foundry
```

Or, you can download the [latest Windows zip file](https://assets.foundry.crowdstrike.com/cli/latest/foundry_Windows_x86_64.zip), expand it, and add the install directory to your PATH environment variable.

**Linux and macOS**:

Install [Homebrew](https://docs.brew.sh/Installation). Then, add the Foundry CLI repository to the list of formulae that Homebrew uses and install the CLI:

```shell
brew tap crowdstrike/foundry-cli
brew install crowdstrike/foundry-cli/foundry
```

Run `foundry version` to verify it's installed correctly.

## Getting Started

Clone this sample to your local system, or [download as a zip file](https://github.com/CrowdStrike/foundry-sample-ngsiem-importer/archive/refs/heads/main.zip) and import it into Foundry. 

```shell
git clone https://github.com/CrowdStrike/foundry-sample-ngsiem-importer
cd foundry-sample-ngsiem-importer
```

Log in to Foundry:

```shell
foundry login
```

Select the following permissions:

- [ ] Create and run RTR scripts
- [x] Create, execute and test workflow templates
- [ ] Create, run and view API integrations
- [ ] Create, edit, delete, and list queries

Deploy the app:

```shell
foundry apps deploy
```

> [!TIP]
> If you get an error that the name already exists, change the name to something unique to your CID in `manifest.yml`.

Once the deployment has finished, you can release the app:

```shell
foundry apps release
```

Next, go to **Foundry** > **App catalog**, find your app, and install it. Go to **Fusion SOAR** > **Workflows** to see the scheduled workflow from this app.

## About this sample app

### 1. Data Collection

The extension downloads threat intelligence from multiple public sources:

- _botvrij.eu_: Collects malicious domains, SHA1 file hashes, and IP addresses
- _Emerging Threats_: Gathers compromised IP addresses
- _dan.me.uk_: Downloads Tor exit node IP addresses
- _urlhaus.abuse.ch_: Retrieves malicious URLs

### 2. Data Processing

- Parses various file formats and structures
- Validates entries (especially IP addresses)
- Standardizes the data into a consistent format
- Organizes data into appropriate fields for SIEM ingestion:
  - IP addresses: destination.ip
  - Domains: dns.domain.name
  - File hashes: file.hash.sha1
  - URLs: url.original

### 3. Data Ingestion

- Converts processed data into CSV format
- Uploads CSVs to the specified NG-SIEM repository (default: "search-all")
- Returns status information for each processed file

### 4. Scheduling

- Runs automatically at 3:00 AM Eastern Time (America/New_York) every day
- Can also be triggered manually through the CrowdStrike platform

## Technical Implementation

- Built on CrowdStrike's Foundry Function framework
- Written in Python with dependencies including:
  - [crowdstrike-foundry-function](https://github.com/CrowdStrike/foundry-fn-python) and [FalconPy](https://falconpy.io/) for CrowdStrike API integration
  - pandas for data processing
  - requests for HTTP communication
  - ipaddress for IP validation

## Security Value

This extension enhances an organization's security posture by:

- Automating the collection of threat intelligence from multiple sources
- Standardizing heterogeneous data formats
- Regularly updating the SIEM with fresh threat data
- Enabling detection of malicious domains, IPs, file hashes, and URLs in security logs

## Foundry resources

- Foundry documentation: [US-1](https://falcon.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [US-2](https://falcon.us-2.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry) | [EU](https://falcon.eu-1.crowdstrike.com/documentation/category/c3d64B8e/falcon-foundry)
- Foundry learning resources: [US-1](https://falcon.crowdstrike.com/foundry/learn) | [US-2](https://falcon.us-2.crowdstrike.com/foundry/learn) | [EU](https://falcon.eu-1.crowdstrike.com/foundry/learn)

---

<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><br/><img width="300px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-goblin-panda.png"></p>
<h3><p align="center">WE STOP BREACHES</p></h3>
