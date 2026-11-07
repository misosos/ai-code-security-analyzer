import { defineConfig, devices } from '@playwright/test';

const previewPort = process.env.BROWSER_TEST_PREVIEW_PORT ?? '4175';

export default defineConfig({
  testDir: './browser-tests',
  testMatch: ['**/webkit-compatibility.spec.ts', '**/evidence-revocation.spec.ts'],
  fullyParallel: false,
  workers: 1,
  reporter: 'list',
  use: { ...devices['Desktop Safari'], baseURL: `http://127.0.0.1:${previewPort}`, trace: 'off', screenshot: 'off', video: 'off' },
  webServer: { command: `npm run preview -- --host 127.0.0.1 --port ${previewPort} --strictPort`, port: Number(previewPort), reuseExistingServer: false, timeout: 30_000 },
});
