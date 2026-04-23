import { test as baseTest } from '@playwright/test';
import {
  FoundryHomePage, AppManagerPage, AppCatalogPage, WorkflowsPage, config,
} from '@crowdstrike/foundry-playwright';
import { NGSIEMPage } from './pages/NGSIEMPage';

type FoundryFixtures = {
  foundryHomePage: FoundryHomePage;
  appManagerPage: AppManagerPage;
  appCatalogPage: AppCatalogPage;
  workflowsPage: WorkflowsPage;
  ngsiemPage: NGSIEMPage;
  appName: string;
};

export const test = baseTest.extend<FoundryFixtures>({
  foundryHomePage: async ({ page }, use) => { await use(new FoundryHomePage(page)); },
  appManagerPage: async ({ page }, use) => { await use(new AppManagerPage(page)); },
  appCatalogPage: async ({ page }, use) => { await use(new AppCatalogPage(page)); },
  workflowsPage: async ({ page }, use) => { await use(new WorkflowsPage(page)); },
  ngsiemPage: async ({ page }, use) => { await use(new NGSIEMPage(page)); },
  appName: async ({}, use) => { await use(config.appName); },
});

export { expect } from '@playwright/test';
