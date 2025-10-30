# E2E Tests

End-to-end tests for the NG-SIEM Importer Foundry app using Playwright.

## Tests Included

- **Workflow Execution**: TI Import Scheduler workflow
- **NG-SIEM Verification**: Validates that lookup files are created in NG-SIEM
- **Pre-test Cleanup**: Removes existing TI lookup files before testing

## Setup

```bash
npm ci
npx playwright install chromium
cp .env.sample .env
# Edit .env with your credentials
```

## Run Tests

```bash
npm test              # All tests
npm run test:debug    # Debug mode
npm run test:ui       # Interactive UI
```

## Environment Variables

```env
APP_NAME=foundry-sample-ngsiem-importer
FALCON_BASE_URL=https://falcon.us-2.crowdstrike.com
FALCON_USERNAME=your-username
FALCON_PASSWORD=your-password
FALCON_AUTH_SECRET=your-mfa-secret
```

**Important:** The `APP_NAME` must exactly match the app name as deployed in Falcon.

## Test Flow

1. **Setup**: Authenticates and installs the app
2. **Cleanup**: Deletes any existing TI lookup files (6 files total)
3. **Execute Workflow**: Runs the "TI Import Scheduler" workflow manually
4. **Verify Results**: Confirms all 6 expected lookup files were created in NG-SIEM
5. **Teardown**: Uninstalls the app

## Expected Lookup Files

The TI Import workflow downloads threat intelligence from open-source feeds and creates these lookup files:

- `ti_domain-botvrij-eu.csv` - Malicious domains (botvrij.eu)
- `ti_sha1-botvrij-eu.csv` - Malicious file hashes SHA1 (botvrij.eu)
- `ti_ip-botvrij-eu.csv` - Malicious IP addresses (botvrij.eu)
- `ti_ip-emerging-threats.csv` - Compromised IPs (Emerging Threats)
- `ti_ip-dan-me-uk-tor.csv` - Tor exit node IPs (dan.me.uk)
- `ti_url-abuse-ch.csv` - Malicious URLs (urlhaus.abuse.ch)

## CI/CD

Tests run automatically in GitHub Actions on push/PR to main. The workflow deploys the app, runs tests, and cleans up.
