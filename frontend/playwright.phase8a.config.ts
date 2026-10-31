import { defineConfig, devices } from '@playwright/test';

const port = 4187;

export default defineConfig({
  testDir: './browser-tests',
  testIgnore: '**/real-semgrep.spec.ts',
  fullyParallel: false,
  reporter: 'list',
  use: { ...devices['Desktop Chrome'], baseURL: `http://127.0.0.1:${port}`, trace: 'off', screenshot: 'off', video: 'off' },
  webServer: { command: `npm run preview -- --host 127.0.0.1 --port ${port} --strictPort`, port, reuseExistingServer: false, timeout: 30_000 },
});
