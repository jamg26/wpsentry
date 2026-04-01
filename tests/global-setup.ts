/**
 * Playwright global setup — creates the stable E2E test account once,
 * then saves the browser storage state so all authenticated tests reuse it.
 */

import { chromium } from '@playwright/test';

const FRONTEND  = process.env.PLAYWRIGHT_FRONTEND_URL ?? 'http://localhost:5173';
export const E2E_EMAIL = process.env.E2E_EMAIL ?? 'e2e@example.com';
export const E2E_PASS  = process.env.E2E_PASS  ?? 'ChangeMe1234!';

async function globalSetup() {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page    = await context.newPage();

  // Attempt signup; fall back to login if the account already exists.
  await page.goto(`${FRONTEND}/signup`);
  await page.locator('#email').fill(E2E_EMAIL);
  await page.locator('#password').fill(E2E_PASS);
  await page.locator('#confirm-password').fill(E2E_PASS);
  await page.getByRole('button', { name: 'Create account' }).click();

  try {
    await page.waitForURL(/dashboard/, { timeout: 15000 });
  } catch {
    // Account already exists — log in instead.
    await page.goto(`${FRONTEND}/login`);
    await page.locator('#email').fill(E2E_EMAIL);
    await page.locator('#password').fill(E2E_PASS);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL(/dashboard/, { timeout: 15000 });
  }

  // Persist cookies (including the workers.dev session cookie) for all tests.
  await context.storageState({ path: 'storageState.json' });
  await browser.close();
}

export default globalSetup;
