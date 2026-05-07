import { test as baseTest } from '@playwright/test';
import { WorkflowsPage } from '@crowdstrike/foundry-playwright';
import { NGSIEMPage } from './pages/NGSIEMPage';

type FoundryFixtures = {
  workflowsPage: WorkflowsPage;
  ngsiemPage: NGSIEMPage;
};

export const test = baseTest.extend<FoundryFixtures>({
  workflowsPage: async ({ page }, use) => {
    await use(new WorkflowsPage(page));
  },

  ngsiemPage: async ({ page }, use) => {
    await use(new NGSIEMPage(page));
  },
});

export { expect } from '@playwright/test';
