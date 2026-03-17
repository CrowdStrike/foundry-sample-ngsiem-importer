import { test } from '../src/fixtures';

test.describe.configure({ mode: 'serial' });

test.describe('NG-SIEM Importer - E2E Tests', () => {
  // Lookup files that should always be created (feeds with reliable data)
  const requiredLookupFiles = [
    'ti_ip-botvrij-eu.csv',
    'ti_ip-emerging-threats.csv',
    'ti_ip-dan-me-uk-tor.csv',
    'ti_url-abuse-ch.csv',
  ];

  // Lookup files from feeds that may be empty upstream (skipped when no data rows)
  const optionalLookupFiles = [
    'ti_domain-botvrij-eu.csv',
    'ti_sha1-botvrij-eu.csv',
  ];

  const allLookupFiles = [...requiredLookupFiles, ...optionalLookupFiles];

  test('should cleanup existing TI lookup files before workflow execution', async ({ ngsiemPage }) => {
    // Navigate to NG-SIEM lookup files
    await ngsiemPage.navigateToNGSIEM();
    await ngsiemPage.navigateToLookupFiles();

    // Delete any existing TI lookup files to ensure clean test
    const result = await ngsiemPage.deleteLookupFiles(allLookupFiles);

    console.log(`Cleanup: Deleted ${result.deleted.length} files, ${result.notFound.length} not found`);
  });

  test('should execute TI Import Scheduler workflow', async ({ workflowsPage }) => {
    // Increase timeout for this test since the workflow execution takes time
    test.setTimeout(180000);

    // Navigate to workflows
    await workflowsPage.navigateToWorkflows();

    // Execute the TI Import Scheduler workflow
    await workflowsPage.executeAndVerifyWorkflow('TI Import Scheduler');

    // Verify the workflow execution actually completed successfully
    // This waits for the execution to reach a terminal state and checks for errors
    await workflowsPage.verifyWorkflowExecutionCompleted();
  });

  test('should verify TI lookup files were created in NG-SIEM', async ({ ngsiemPage }) => {
    // Verify required lookup files were created (feeds with reliable data)
    await ngsiemPage.verifyTILookupFilesCreated(requiredLookupFiles);
  });
});
