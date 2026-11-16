import { randomBytes } from "node:crypto";
import { defineConfig, devices } from "@playwright/test";

const e2eEmail = process.env.E2E_EMAIL;
const e2ePassword = process.env.E2E_PASSWORD;
const skipBackend = process.env.PLAYWRIGHT_SKIP_BACKEND === "1";
const dbPath = process.env.E2E_DB_PATH ?? "/tmp/rtip-playwright.db";

// Per-run secrets for the throwaway SQLite test database. Never reuse these
// outside the Playwright run.
const testJwtSecret = randomBytes(32).toString("hex");
const testAuditKey = randomBytes(32).toString("hex");

const webServer = [
  {
    command: "bash -c 'rm -f \"$E2E_DB_PATH\" && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000'",
    cwd: "../backend",
    url: "http://127.0.0.1:8000/healthz",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      DATABASE_URL: `sqlite+aiosqlite:///${dbPath}`,
      ENVIRONMENT: "development",
      DEBUG: "false",
      RATE_LIMIT_ENABLED: "false",
      JWT_SECRET_KEY: testJwtSecret,
      AUDIT_HMAC_KEY: testAuditKey,
      ADMIN_EMAIL: e2eEmail ?? "playwright-admin@rtip.test",
      ADMIN_PASSWORD: e2ePassword ?? randomBytes(24).toString("base64url"),
      E2E_DB_PATH: dbPath,
    },
  },
  {
    command: "npm run dev",
    url: "http://localhost:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
];

export default defineConfig({
  testDir: "./src/test/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || "http://localhost:5173",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
  ],
  webServer: skipBackend
    ? webServer.slice(1)
    : webServer,
});
