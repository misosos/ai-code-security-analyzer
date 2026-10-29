import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.BROWSER_E2E_BASE_URL;
const outputDir = process.env.BROWSER_E2E_OUTPUT_DIR;
if (!baseURL || !process.env.BROWSER_E2E_API_TOKEN || !outputDir || process.env.SEMGREP_REQUIRED !== '1') {
  throw new Error('real_browser_semgrep_e2e_configuration_required');
}
let parsedBaseURL: URL;
try {
  parsedBaseURL = new URL(baseURL);
} catch {
  throw new Error('real_browser_semgrep_e2e_must_use_loopback');
}
if (
  parsedBaseURL.protocol !== 'http:' || parsedBaseURL.hostname !== '127.0.0.1' ||
  parsedBaseURL.port !== '8765' || parsedBaseURL.pathname !== '/' ||
  parsedBaseURL.username || parsedBaseURL.password || parsedBaseURL.search || parsedBaseURL.hash
) {
  throw new Error('real_browser_semgrep_e2e_must_use_loopback');
}

export default defineConfig({
  testDir: './browser-tests',
  testMatch: '**/real-semgrep.spec.ts',
  fullyParallel: false,
  reporter: 'dot',
  outputDir,
  timeout: 90_000,
  use: { ...devices['Desktop Chrome'], baseURL, trace: 'off', screenshot: 'off', video: 'off' },
});
