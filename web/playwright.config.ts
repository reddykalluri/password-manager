import { defineConfig } from '@playwright/test';

// Accessibility gate: build then preview the static SPA and run axe against the
// unauthenticated surfaces (landing, enrolment, unlock). Authenticated screens
// require a seeded backend and are covered by manual audits (spec 7.1).
export default defineConfig({
  testDir: 'tests',
  fullyParallel: true,
  reporter: 'list',
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    port: 4173,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  },
  use: {
    baseURL: 'http://localhost:4173'
  }
});
