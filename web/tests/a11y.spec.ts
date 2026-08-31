import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

// The web-technology surfaces reachable without authentication. New
// automated-detectable AA violations fail the build (accessibility spec: CI gate).
const pages = [
  { path: '/', name: 'landing' },
  { path: '/enroll', name: 'enrolment' },
  { path: '/unlock', name: 'unlock' }
];

for (const p of pages) {
  test(`no axe violations: ${p.name}`, async ({ page }) => {
    await page.goto(p.path);
    // Let the WASM engine initialise and dynamic content settle.
    await page.waitForLoadState('networkidle');
    const results = await new AxeBuilder({ page }).withTags(WCAG).analyze();
    expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
  });
}
