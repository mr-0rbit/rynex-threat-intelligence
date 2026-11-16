import { test, expect } from "@playwright/test";

test.describe("Login Page", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/login");
  });

  test("should display the login form", async ({ page }) => {
    await expect(page.locator("h1")).toContainText("Sign In");
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test("should show error for invalid credentials", async ({ page }) => {
    await page.fill('input[type="email"]', "wrong@test.com");
    await page.fill('input[type="password"]', "wrongpassword");
    await page.click('button[type="submit"]');
    await expect(page.locator('[role="alert"], .error, text=Invalid')).toBeVisible({ timeout: 5000 });
  });

  test("should validate email format", async ({ page }) => {
    await page.fill('input[type="email"]', "not-an-email");
    await page.fill('input[type="password"]', "password");
    await page.click('button[type="submit"]');
    // HTML5 validation should prevent submission
    await expect(page.locator('input[type="email"]:invalid')).toBeVisible();
  });

  test("should have accessible labels", async ({ page }) => {
    await expect(page.locator('label[for="email"]')).toBeVisible();
    await expect(page.locator('label[for="password"]')).toBeVisible();
  });
});

test.describe("Protected Route Redirect", () => {
  test("should redirect to login when accessing protected route", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
  });
});