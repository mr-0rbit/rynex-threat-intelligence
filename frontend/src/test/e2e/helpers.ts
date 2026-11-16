import type { Page } from "@playwright/test";

/** True when the E2E run has been provisioned with a bootstrap admin account. */
export const e2eCredentialsConfigured = Boolean(
  process.env.E2E_EMAIL && process.env.E2E_PASSWORD,
);

/**
 * Sign in with the per-run bootstrap credentials supplied by the runner.
 * No credentials are committed to the repository; CI generates them for each
 * run and passes them to both the backend and the test process.
 */
export async function loginAsAdmin(page: Page) {
  const email = process.env.E2E_EMAIL;
  const password = process.env.E2E_PASSWORD;
  if (!email || !password) {
    throw new Error(
      "E2E_EMAIL and E2E_PASSWORD must be set; unauthenticated suites are skipped instead.",
    );
  }

  await page.goto("/login");
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL("/");
}
