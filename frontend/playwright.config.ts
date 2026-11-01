import { defineConfig, devices } from '@playwright/test';

const previewPort = process.env.BROWSER_TEST_PREVIEW_PORT ?? '4173';

export default defineConfig({
  testDir: './browser-tests',
  fullyParallel: false,
  reporter: 'list',
  testIgnore: '**/real-*.spec.ts',
  use: { ...devices['Desktop Chrome'], baseURL: `http://127.0.0.1:${previewPort}`, trace: 'off', screenshot: 'off', video: 'off' },
  webServer: { command: `npm run preview -- --host 127.0.0.1 --port ${previewPort} --strictPort`, port: Number(previewPort), reuseExistingServer: !process.env.CI, timeout: 30_000 },
});
