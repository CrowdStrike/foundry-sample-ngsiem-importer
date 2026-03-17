import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page object for NG-SIEM Lookup File verification
 *
 * Handles navigation to NG-SIEM and verification of lookup files created by the TI Import workflow
 */
export class NGSIEMPage extends BasePage {
  constructor(page: Page) {
    super(page, 'NG-SIEM');
  }

  protected getPagePath(): string {
    return '/next-gen-siem/investigate';
  }

  protected async verifyPageLoaded(): Promise<void> {
    // Wait for NG-SIEM to load - could be "Investigate" or similar heading
    const heading = this.page.getByRole('heading', { name: /investigate|ng-siem/i }).first();
    await expect(heading).toBeVisible({ timeout: 15000 });
    this.logger.success('NG-SIEM page loaded');
  }

  /**
   * Navigate to NG-SIEM via hamburger menu
   */
  async navigateToNGSIEM(): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info('Navigating to NG-SIEM');

        // Navigate to home first
        await this.navigateToPath('/foundry/home', 'Foundry Home');

        // Open hamburger menu
        const menuButton = this.page.getByTestId('nav-trigger');
        await menuButton.click();
        await this.page.waitForLoadState('networkidle');

        // Click Next-Gen SIEM in the left sidebar
        const ngsiemButton = this.page.getByRole('button', { name: 'Next-Gen SIEM' }).last();
        await ngsiemButton.click();

        this.logger.success('Navigated to NG-SIEM menu');
      },
      'Navigate to NG-SIEM'
    );
  }

  /**
   * Navigate to Lookup Files section
   */
  async navigateToLookupFiles(): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info('Navigating to Lookup Files');

        // Click Lookup files link from the expanded NG-SIEM menu
        const lookupFilesLink = this.page.getByRole('link', { name: /lookup files/i });
        await lookupFilesLink.click();
        await this.page.waitForLoadState('networkidle');

        // Verify we're on the lookup files page
        await expect(this.page.getByRole('heading', { name: /lookup files/i })).toBeVisible({ timeout: 10000 });
        this.logger.success('Navigated to Lookup Files');
      },
      'Navigate to Lookup Files'
    );
  }

  /**
   * Search for a specific lookup file by name
   */
  async searchLookupFile(fileName: string): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info(`Searching for lookup file: ${fileName}`);

        // Look for search box
        const searchBox = this.page.getByRole('searchbox')
          .or(this.page.locator('input[type="search"]'))
          .or(this.page.locator('input[placeholder*="Search"]'))
          .or(this.page.locator('input[aria-label*="Search"]'));

        await searchBox.fill(fileName);
        await this.page.keyboard.press('Enter');
        await this.page.waitForLoadState('networkidle');

        // Wait for loading overlay to disappear before interacting with results
        const loader = this.page.getByTestId('falcon-loader');
        await loader.waitFor({ state: 'hidden', timeout: 10000 }).catch(() => {});

        this.logger.success(`Searched for lookup file: ${fileName}`);
      },
      `Search for lookup file: ${fileName}`
    );
  }

  /**
   * Verify a lookup file exists in the list
   */
  async verifyLookupFileExists(fileName: string): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info(`Verifying lookup file exists: ${fileName}`);

        // Search for the file first
        await this.searchLookupFile(fileName);

        // Look for the file in the table/list
        const fileLink = this.page.getByRole('link', { name: new RegExp(fileName, 'i') })
          .or(this.page.getByText(new RegExp(fileName, 'i')));

        try {
          await expect(fileLink.first()).toBeVisible({ timeout: 5000 });
          this.logger.success(`Lookup file found: ${fileName}`);
        } catch (error) {
          this.logger.error(`Lookup file not found: ${fileName}`);
          throw new Error(`Lookup file "${fileName}" not found in NG-SIEM`);
        }
      },
      `Verify lookup file exists: ${fileName}`
    );
  }

  /**
   * Delete a lookup file by name.
   * The UI uses a kebab "Open menu" button per row that reveals a "Delete file" menuitem.
   */
  async deleteLookupFile(fileName: string): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info(`Deleting lookup file: ${fileName}`);

        // Search for the file
        await this.searchLookupFile(fileName);

        // Find the row containing the file using ARIA role (table uses div role="row", not <tr>)
        const fileRow = this.page.getByRole('row').filter({ hasText: new RegExp(fileName, 'i') }).first();
        await fileRow.waitFor({ state: 'visible', timeout: 5000 });

        // Click the "Open menu" kebab button in the row
        const menuButton = fileRow.getByRole('button', { name: /open menu/i });
        await menuButton.click();

        // Click "Delete file" from the dropdown menu
        const deleteMenuItem = this.page.getByRole('menuitem', { name: /delete file/i });
        await deleteMenuItem.click();

        // Confirm deletion in the modal dialog
        const confirmButton = this.page.getByRole('dialog').getByRole('button', { name: /delete file/i });
        await confirmButton.click();

        await this.page.waitForLoadState('networkidle');
        this.logger.success(`Deleted lookup file: ${fileName}`);
      },
      `Delete lookup file: ${fileName}`
    );
  }

  /**
   * Delete multiple lookup files (cleanup before tests).
   * Files that don't exist are reported as notFound.
   * Files that exist but fail to delete will throw an error.
   */
  async deleteLookupFiles(fileNames: string[]): Promise<{ deleted: string[], notFound: string[] }> {
    return this.withTiming(
      async () => {
        this.logger.info(`Attempting to delete ${fileNames.length} lookup files`);

        const deleted: string[] = [];
        const notFound: string[] = [];

        for (const fileName of fileNames) {
          // Search and wait for results to stabilize
          await this.searchLookupFile(fileName);

          // Check if any results were returned by looking for the file link in the grid
          const fileLink = this.page.getByRole('row').filter({ hasText: new RegExp(fileName, 'i') }).first();
          const fileExists = await fileLink.isVisible({ timeout: 3000 }).catch(() => false);

          if (fileExists) {
            await this.deleteLookupFile(fileName);
            deleted.push(fileName);
          } else {
            this.logger.info(`Lookup file not found (already deleted): ${fileName}`);
            notFound.push(fileName);
          }
        }

        this.logger.success(`Deleted ${deleted.length} files, ${notFound.length} not found`);
        return { deleted, notFound };
      },
      'Delete lookup files'
    );
  }

  /**
   * Verify all expected TI lookup files were created
   */
  async verifyTILookupFilesCreated(expectedFiles: string[]): Promise<void> {
    return this.withTiming(
      async () => {
        this.logger.info(`Verifying ${expectedFiles.length} TI lookup files were created`);

        await this.navigateToNGSIEM();
        await this.navigateToLookupFiles();

        const results: { file: string, exists: boolean }[] = [];

        for (const fileName of expectedFiles) {
          try {
            await this.verifyLookupFileExists(fileName);
            results.push({ file: fileName, exists: true });
          } catch (error) {
            results.push({ file: fileName, exists: false });
          }
        }

        const allFound = results.every(r => r.exists);

        if (allFound) {
          this.logger.success(`All ${expectedFiles.length} TI lookup files verified`);
        } else {
          const missing = results.filter(r => !r.exists).map(r => r.file);
          this.logger.error(`Missing ${missing.length} lookup files: ${missing.join(', ')}`);
          throw new Error(`Missing lookup files: ${missing.join(', ')}`);
        }
      },
      'Verify TI lookup files created'
    );
  }
}
