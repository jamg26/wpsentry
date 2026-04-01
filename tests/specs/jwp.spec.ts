/**
 * JWP Scanner — Full Playwright Test Suite
 *
 * Auth strategy:
 *   • global-setup.ts creates "e2e@example.com" once and saves storageState.json
 *   • UI/display tests use  test.use({ storageState: 'storageState.json' })
 *   • Tests that CREATE scans use fresh per-run accounts (via { request } or
 *     inline sign-up) to avoid hitting the 5-scans/day free-tier limit.
 */

import { test, expect } from '@playwright/test';

const FRONTEND  = process.env.PLAYWRIGHT_FRONTEND_URL ?? 'http://localhost:5173';
const API       = process.env.PLAYWRIGHT_API_URL      ?? 'http://localhost:8787';

const E2E_EMAIL = process.env.E2E_EMAIL ?? 'e2e@example.com';
const E2E_PASS  = process.env.E2E_PASS  ?? 'ChangeMe1234!';

const RUN_ID    = Date.now();
const NEW_EMAIL = `new+${RUN_ID}@example.com`; // unique per run — signup happy path
const TARGET    = 'https://example.com';

// ── Helpers ───────────────────────────────────────────────────────────────────

async function loginViaUI(page: import('@playwright/test').Page, email: string, pass: string) {
  await page.goto(`${FRONTEND}/login`);
  await page.locator('#email').fill(email);
  await page.locator('#password').fill(pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });
}

/** Sign up + login a brand-new account; returns { email, password }. */
async function freshAccount(request: import('@playwright/test').APIRequestContext) {
  const email = `fresh+${Date.now()}@example.com`;
  const pass  = 'Fresh1234!';
  await request.post(`${API}/auth/signup`, { data: { email, password: pass } });
  await request.post(`${API}/auth/login`,  { data: { email, password: pass } });
  return { email, pass };
}

// ─── 1. API health ────────────────────────────────────────────────────────────

test('API health endpoint returns ok', async ({ request }) => {
  const res  = await request.get(`${API}/health`);
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.status).toBe('ok');
  expect(body.version).toBeTruthy();
});

// ─── 2. Unauthenticated redirects ────────────────────────────────────────────

test('frontend: unauthenticated / redirects to /login', async ({ page }) => {
  await page.goto(FRONTEND);
  await expect(page).toHaveURL(/login/, { timeout: 15000 });
  await expect(page.locator('#email')).toBeVisible();
});

test('frontend: unauthenticated /dashboard redirects to /login', async ({ page }) => {
  await page.goto(`${FRONTEND}/dashboard`);
  await expect(page).toHaveURL(/login/, { timeout: 10000 });
});

test('frontend: unauthenticated /history redirects to /login', async ({ page }) => {
  await page.goto(`${FRONTEND}/history`);
  await expect(page).toHaveURL(/login/, { timeout: 10000 });
});

test('frontend: unauthenticated /scans/new redirects to /login', async ({ page }) => {
  await page.goto(`${FRONTEND}/scans/new`);
  await expect(page).toHaveURL(/login/, { timeout: 10000 });
});

// ─── 3. Signup ───────────────────────────────────────────────────────────────

test.describe('Auth — Signup', () => {
  test('shows signup form with all required fields', async ({ page }) => {
    await page.goto(`${FRONTEND}/signup`);
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#confirm-password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible();
  });

  test('shows error for short password', async ({ page }) => {
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(`short+${RUN_ID}@example.com`);
    await page.locator('#password').fill('abc');
    await page.locator('#confirm-password').fill('abc');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 8000 });
    await expect(page).toHaveURL(/signup/);
  });

  test('shows error when passwords do not match', async ({ page }) => {
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(`mismatch+${RUN_ID}@example.com`);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Different999!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/match/i, { timeout: 8000 });
    await expect(page).toHaveURL(/signup/);
  });

  test('successfully creates new account and lands on dashboard', async ({ page }) => {
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(NEW_EMAIL);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });
    await expect(page.locator('[data-testid="user-email"]')).toContainText(NEW_EMAIL, { timeout: 10000 });
  });

  test('prevents duplicate email signup', async ({ page }) => {
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(E2E_EMAIL);
    await page.locator('#password').fill(E2E_PASS);
    await page.locator('#confirm-password').fill(E2E_PASS);
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 8000 });
    await expect(page).toHaveURL(/signup/);
  });

  test('login page has link to signup', async ({ page }) => {
    await page.goto(`${FRONTEND}/login`);
    await expect(page.getByRole('link', { name: /create one|sign up|register/i })).toBeVisible();
  });
});

// ─── 4. Login ────────────────────────────────────────────────────────────────

test.describe('Auth — Login', () => {
  test('shows login form', async ({ page }) => {
    await page.goto(`${FRONTEND}/login`);
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  });

  test('rejects wrong password', async ({ page }) => {
    await page.goto(`${FRONTEND}/login`);
    await page.locator('#email').fill(E2E_EMAIL);
    await page.locator('#password').fill('WrongPass999!');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 8000 });
    await expect(page).toHaveURL(/login/);
  });

  test('rejects non-existent email', async ({ page }) => {
    await page.goto(`${FRONTEND}/login`);
    await page.locator('#email').fill(`ghost+${RUN_ID}@example.com`);
    await page.locator('#password').fill(E2E_PASS);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible({ timeout: 8000 });
    await expect(page).toHaveURL(/login/);
  });

  test('validates empty form (HTML required)', async ({ page }) => {
    await page.goto(`${FRONTEND}/login`);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/login/);
  });

  test('successfully logs in and shows dashboard', async ({ page }) => {
    await loginViaUI(page, E2E_EMAIL, E2E_PASS);
    await expect(page.locator('[data-testid="user-email"]')).toContainText(E2E_EMAIL);
  });

  test('authenticated user visiting /login is redirected away', async ({ page }) => {
    await loginViaUI(page, E2E_EMAIL, E2E_PASS);
    await page.goto(`${FRONTEND}/login`);
    await expect(page).not.toHaveURL(/\/login/, { timeout: 8000 });
  });
});

// ─── 5. Dashboard ────────────────────────────────────────────────────────────

test.describe('Dashboard', () => {
  test.use({ storageState: 'storageState.json' });

  test('shows free tier usage limits', async ({ page }) => {
    await page.goto(`${FRONTEND}/dashboard`);
    await expect(page.getByText(/5 scans per day/i)).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(/50 scans per month/i)).toBeVisible();
  });

  test('mentions all 67 security modules', async ({ page }) => {
    await page.goto(`${FRONTEND}/dashboard`);
    await expect(page.getByText(/all 67 security modules/i)).toBeVisible({ timeout: 10000 });
  });

  test('new-scan button navigates to /scans/new', async ({ page }) => {
    await page.goto(`${FRONTEND}/dashboard`);
    await page.locator('[data-testid="new-scan-btn"]').click();
    await expect(page).toHaveURL(/scans\/new/, { timeout: 8000 });
  });

  test('shows logged-in email in header', async ({ page }) => {
    await page.goto(`${FRONTEND}/dashboard`);
    await expect(page.locator('[data-testid="user-email"]')).toContainText(E2E_EMAIL, { timeout: 10000 });
  });
});

// ─── 6. New Scan form ────────────────────────────────────────────────────────
// Display-only tests use storageState; the scan-creation test uses a fresh user.

test.describe('New Scan', () => {
  test.describe('form display', () => {
    test.use({ storageState: 'storageState.json' });

    test('shows target input and Start Scan button', async ({ page }) => {
      await page.goto(`${FRONTEND}/scans/new`);
      await expect(page.locator('#target')).toBeVisible({ timeout: 10000 });
      await expect(page.getByRole('button', { name: /start scan/i })).toBeVisible();
    });

    test('shows "All 67 modules" option', async ({ page }) => {
      await page.goto(`${FRONTEND}/scans/new`);
      await expect(page.getByText('All 67 modules')).toBeVisible({ timeout: 8000 });
    });

    test('module checklist appears after "Select modules"', async ({ page }) => {
      await page.goto(`${FRONTEND}/scans/new`);
      await page.getByRole('button', { name: 'Select modules' }).click();
      await expect(page.getByText('Version Detection')).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('SQL Injection')).toBeVisible();
    });

    test('"Select all" updates Start Scan button with module count', async ({ page }) => {
      await page.goto(`${FRONTEND}/scans/new`);
      await page.getByRole('button', { name: 'Select modules' }).click();
      await page.getByText('Select all').click();
      await expect(page.getByRole('button', { name: 'Start Scan (67 modules)' })).toBeVisible({ timeout: 5000 });
    });

    test('HTML required prevents empty target submission', async ({ page }) => {
      await page.goto(`${FRONTEND}/scans/new`);
      await page.getByRole('button', { name: /start scan/i }).click();
      await expect(page).toHaveURL(/scans\/new/);
    });
  });

  // Fresh account so this test never hits the daily rate limit regardless of
  // how many times the suite has run today.
  test('creates scan and navigates to scan detail page', async ({ page }) => {
    const email = `scan+${RUN_ID}@example.com`;
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });

    await page.goto(`${FRONTEND}/scans/new`);
    await page.locator('#target').fill(TARGET);
    await page.getByRole('button', { name: /start scan/i }).click();
    await expect(page).toHaveURL(/\/scans\/[a-zA-Z0-9_-]+$/, { timeout: 20000 });
    await expect(page.getByText(TARGET, { exact: false })).toBeVisible({ timeout: 10000 });
  });
});

// ─── 7. Scan Detail ───────────────────────────────────────────────────────────
// Each test creates its own scan on a fresh account.

test.describe('Scan Detail', () => {
  test('shows status badge and target URL', async ({ request, page }) => {
    await freshAccount(request);
    const res = await request.post(`${API}/scans`, { data: { target: TARGET } });
    expect(res.status()).toBe(202);
    const { id } = await res.json() as { id: string };

    // Load the page using the same auth cookie (page.request shares context cookies)
    // but we need to navigate the browser — sign in via UI first.
    // Simpler: check via API directly and then verify the detail page renders.
    const detail = await request.get(`${API}/scans/${id}`);
    expect(detail.status()).toBe(200);
    const scan = await detail.json() as { id: string; status: string; target: string };
    expect(scan.status).toMatch(/queued|running|completed|failed/);
    expect(scan.target).toBe(TARGET);
    expect(scan.id).toBe(id);
  });

  test('detail page shows status badge and target URL', async ({ page }) => {
    const email = `detail+${RUN_ID}@example.com`;
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });

    const res = await page.request.post(`${API}/scans`, { data: { target: TARGET } });
    const { id } = await res.json() as { id: string };

    await page.goto(`${FRONTEND}/scans/${id}`);
    await expect(page.getByText(/queued|running|completed|failed/i).first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByText(TARGET, { exact: false }).first()).toBeVisible({ timeout: 10000 });
  });

  test('back link navigates to /history', async ({ page }) => {
    const email = `detail2+${RUN_ID}@example.com`;
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });

    const res = await page.request.post(`${API}/scans`, { data: { target: TARGET } });
    const { id } = await res.json() as { id: string };

    await page.goto(`${FRONTEND}/scans/${id}`);
    await expect(page.getByText(/← History/i)).toBeVisible({ timeout: 10000 });
    await page.getByText(/← History/i).click();
    await expect(page).toHaveURL(/history/, { timeout: 8000 });
  });

  test('shows error message for non-existent scan ID', async ({ page }) => {
    await loginViaUI(page, E2E_EMAIL, E2E_PASS);
    await page.goto(`${FRONTEND}/scans/totally-invalid-000`);
    await expect(page.getByText(/not found|failed to load/i)).toBeVisible({ timeout: 10000 });
  });

  test('unauthenticated access to scan detail redirects to /login', async ({ page }) => {
    await page.goto(`${FRONTEND}/scans/some-scan-id`);
    await expect(page).toHaveURL(/login/, { timeout: 10000 });
  });
});

// ─── 8. Scan History ─────────────────────────────────────────────────────────

test.describe('Scan History', () => {
  // fresh account per describe — creates its own scan so history is guaranteed non-empty
  test('lists scans with target URLs', async ({ request, page }) => {
    const email = `hist+${RUN_ID}@example.com`;
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });

    await page.request.post(`${API}/scans`, { data: { target: TARGET } });
    await page.goto(`${FRONTEND}/history`);
    await expect(page.getByText(TARGET, { exact: false }).first()).toBeVisible({ timeout: 15000 });
  });

  test('scan row links to the scan detail page', async ({ page }) => {
    const email = `hist2+${RUN_ID}@example.com`;
    await page.goto(`${FRONTEND}/signup`);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('Test1234!');
    await page.locator('#confirm-password').fill('Test1234!');
    await page.getByRole('button', { name: 'Create account' }).click();
    await expect(page).toHaveURL(/dashboard/, { timeout: 20000 });

    await page.request.post(`${API}/scans`, { data: { target: TARGET } });
    await page.goto(`${FRONTEND}/history`);
    await page.getByText(TARGET, { exact: false }).first().click();
    await expect(page).toHaveURL(/\/scans\/[a-zA-Z0-9_-]+$/, { timeout: 10000 });
  });

  test('queued scan returns 409 on delete attempt', async ({ request }) => {
    await freshAccount(request);
    const res = await request.post(`${API}/scans`, { data: { target: TARGET } });
    expect(res.status()).toBe(202);
    const { id } = await res.json() as { id: string };
    // Cannot delete a queued/running scan
    const del = await request.delete(`${API}/scans/${id}`);
    expect(del.status()).toBe(409);
    // Scan still exists
    const check = await request.get(`${API}/scans/${id}`);
    expect(check.status()).toBe(200);
  });

  test('non-existent scan returns 404 on delete', async ({ request }) => {
    await freshAccount(request);
    const check = await request.delete(`${API}/scans/totally-made-up-id-99999`);
    expect(check.status()).toBe(404);
  });

  test('unauthenticated /history redirects to /login', async ({ page }) => {
    await page.goto(`${FRONTEND}/history`);
    await expect(page).toHaveURL(/login/, { timeout: 10000 });
  });
});

// ─── 9. Rate Limiting ─────────────────────────────────────────────────────────

test.describe('Rate Limiting', () => {
  test('usage API returns correct free tier limits for new user', async ({ request }) => {
    await freshAccount(request);
    const usage = await (await request.get(`${API}/user/usage`)).json() as Record<string, unknown>;
    expect(usage.daily_limit).toBe(5);
    expect(usage.monthly_limit).toBe(50);
    expect(usage.daily_remaining).toBe(5);
    expect(usage.monthly_remaining).toBe(50);
    expect(usage).toHaveProperty('reset_daily_at');
    expect(usage).toHaveProperty('reset_monthly_at');
  });

  test('creating a scan decrements daily_remaining', async ({ request }) => {
    await freshAccount(request);
    const before = await (await request.get(`${API}/user/usage`)).json() as Record<string, number>;
    await request.post(`${API}/scans`, { data: { target: TARGET } });
    const after  = await (await request.get(`${API}/user/usage`)).json() as Record<string, number>;
    expect(after.daily_used).toBe(before.daily_used + 1);
    expect(after.daily_remaining).toBe(before.daily_remaining - 1);
  });
});

// ─── 10. Logout ───────────────────────────────────────────────────────────────

test.describe('Logout', () => {
  test('logout button clears session and redirects to /login', async ({ page }) => {
    await loginViaUI(page, E2E_EMAIL, E2E_PASS);
    await page.locator('[data-testid="logout-btn"]').click();
    await expect(page).toHaveURL(/login/, { timeout: 10000 });
  });

  test('all protected routes inaccessible after logout', async ({ page }) => {
    await loginViaUI(page, E2E_EMAIL, E2E_PASS);
    await page.locator('[data-testid="logout-btn"]').click();
    await expect(page).toHaveURL(/login/, { timeout: 10000 });

    for (const route of ['/dashboard', '/history', '/scans/new']) {
      await page.goto(`${FRONTEND}${route}`);
      await expect(page).toHaveURL(/login/, { timeout: 8000 });
    }
  });
});

// ─── 11. Edge Cases ───────────────────────────────────────────────────────────

test.describe('Edge Cases', () => {
  test('unknown route shows 404 page', async ({ page }) => {
    await page.goto(`${FRONTEND}/this/does/not/exist`);
    await expect(page.getByText('404')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/page not found/i)).toBeVisible();
  });

  test('API: 401 without auth token', async ({ request }) => {
    expect((await request.get(`${API}/user/me`)).status()).toBe(401);
  });

  test('API: 401 with invalid token', async ({ request }) => {
    expect(
      (await request.get(`${API}/user/me`, { headers: { Authorization: 'Bearer bad.token' } })).status()
    ).toBe(401);
  });

  test('API: 400 for scan with invalid URL (no TLD)', async ({ request }) => {
    await freshAccount(request);
    // Validation runs before rate-limit, so this returns 400 even if daily limit is hit
    expect((await request.post(`${API}/scans`, { data: { target: 'not-a-url' } })).status()).toBe(400);
  });

  test('API: 400 for scan with empty target', async ({ request }) => {
    await freshAccount(request);
    expect((await request.post(`${API}/scans`, { data: { target: '' } })).status()).toBe(400);
  });

  test('API: 400 for scan with localhost (no dot)', async ({ request }) => {
    await freshAccount(request);
    expect((await request.post(`${API}/scans`, { data: { target: 'http://localhost' } })).status()).toBe(400);
  });

  test('API: 202 for valid scan target', async ({ request }) => {
    await freshAccount(request);
    const res  = await request.post(`${API}/scans`, { data: { target: TARGET } });
    expect(res.status()).toBe(202);
    const body = await res.json() as { id: string; status: string };
    expect(body.id).toBeTruthy();
    expect(body.status).toBe('queued');
  });

  test('API: 400 for signup with oversized email', async ({ request }) => {
    const res = await request.post(`${API}/auth/signup`, {
      data: { email: 'a'.repeat(250) + '@x.com', password: 'Test1234!' },
    });
    expect(res.status()).toBe(400);
  });

  test('API: required security headers are present', async ({ request }) => {
    const h = (await request.get(`${API}/health`)).headers();
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['x-frame-options']).toBe('DENY');
    expect(h['referrer-policy']).toBeTruthy();
    expect(h['strict-transport-security']).toMatch(/max-age/i);
  });

  test('API: CORS allows pages.dev origin', async ({ request }) => {
    const origin = process.env.PLAYWRIGHT_FRONTEND_URL ?? 'http://localhost:5173';
    const h = (await request.get(`${API}/health`, {
      headers: { Origin: origin },
    })).headers();
    expect(h['access-control-allow-origin']).toBe(origin);
    expect(h['access-control-allow-credentials']).toBe('true');
  });

  test('API: CORS preflight returns 204', async ({ request }) => {
    const origin = process.env.PLAYWRIGHT_FRONTEND_URL ?? 'http://localhost:5173';
    const res = await request.fetch(`${API}/scans`, {
      method: 'OPTIONS',
      headers: {
        Origin: origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type',
      },
    });
    expect(res.status()).toBe(204);
  });
});
