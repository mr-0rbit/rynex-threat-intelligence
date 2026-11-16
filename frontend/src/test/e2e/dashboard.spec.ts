import { test, expect } from "@playwright/test";
import { e2eCredentialsConfigured, loginAsAdmin } from "./helpers";

test.describe("Dashboard (requires auth)", () => {
  test.skip(!e2eCredentialsConfigured, "Set E2E_EMAIL and E2E_PASSWORD to run authenticated E2E tests");

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("should load dashboard with stat cards", async ({ page }) => {
    await expect(page.locator("h1")).toContainText("Dashboard");
    // Stat cards should be visible
    await expect(page.locator("text=Alerts")).toBeVisible();
    await expect(page.locator("text=IOCs")).toBeVisible();
    await expect(page.locator("text=Vulnerabilities")).toBeVisible();
    await expect(page.locator("text=Breaches")).toBeVisible();
  });

  test("should navigate to alerts page", async ({ page }) => {
    await page.click('a[href="/alerts"] >> text=Alerts');
    await expect(page).toHaveURL(/\/alerts/);
    await expect(page.locator("h1")).toContainText("Alerts");
  });

  test("should navigate to vulnerabilities page", async ({ page }) => {
    await page.click('a[href="/vulnerabilities"] >> text=Vulnerabilities');
    await expect(page).toHaveURL(/\/vulnerabilities/);
    await expect(page.locator("h1")).toContainText("Vulnerabilities");
  });

  test("should navigate to IOCs page", async ({ page }) => {
    await page.click('a[href="/iocs"] >> text=IOC');
    await expect(page).toHaveURL(/\/iocs/);
    await expect(page.locator("h1")).toContainText("IOC");
  });

  test("should navigate to breaches page", async ({ page }) => {
    await page.click('a[href="/breaches"] >> text=Breach');
    await expect(page).toHaveURL(/\/breaches/);
    await expect(page.locator("h1")).toContainText("Breach");
  });

  test("should have global search accessible", async ({ page }) => {
    await expect(page.locator('input[placeholder*="Search"]')).toBeVisible();
  });
});

test.describe("Navigation", () => {
  test.skip(!e2eCredentialsConfigured, "Set E2E_EMAIL and E2E_PASSWORD to run authenticated E2E tests");

  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);
  });

  test("should navigate to investigations", async ({ page }) => {
    await page.click('a[href="/investigations"]');
    await expect(page).toHaveURL(/\/investigations/);
  });

  test("should navigate to assets", async ({ page }) => {
    await page.click('a[href="/assets"]');
    await expect(page).toHaveURL(/\/assets/);
  });

  test("should navigate to dark web", async ({ page }) => {
    await page.click('a[href="/darkweb"]');
    await expect(page).toHaveURL(/\/darkweb/);
  });

  test("should navigate to MITRE", async ({ page }) => {
    await page.click('a[href="/mitre"]');
    await expect(page).toHaveURL(/\/mitre/);
  });

  test("should navigate to integrations", async ({ page }) => {
    await page.click('a[href="/integrations"]');
    await expect(page).toHaveURL(/\/integrations/);
  });

  test("should navigate to news", async ({ page }) => {
    await page.click('a[href="/news"]');
    await expect(page).toHaveURL(/\/news/);
  });

  test("should navigate to sources", async ({ page }) => {
    await page.click('a[href="/sources"]');
    await expect(page).toHaveURL(/\/sources/);
  });
});