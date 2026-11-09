// P6-A-R: run the `window` cases as classic (sloppy) scripts in real Chromium.
//
// Safety: an empty about:blank page with no network; each case is our own synthetic file and the only
// evaluated code is the fixed probe string. Uses the frontend's locked @playwright/test dev dependency
// (run `npm ci` in frontend/ first).
//
//   node experiments/p6a-dynamic-eval/semantics/browser_window_cases.cjs
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const repo = path.resolve(__dirname, '..', '..', '..');
const { chromium } = require(require.resolve('@playwright/test', { paths: [path.join(repo, 'frontend')] }));
const cases = ['P07_const_window_eval', 'P11_window_member', 'N07_local_window_object'];
const PROBE = 'typeof arguments';

(async () => {
  const browser = await chromium.launch();
  const lines = [`# Chromium ${browser.version()} — node experiments/p6a-dynamic-eval/semantics/browser_window_cases.cjs`, `# probe: ${JSON.stringify(PROBE)}`];
  try {
    for (const name of cases) {
      const page = await browser.newPage();
      await page.route('**/*', (route) => route.abort());
      const source = fs.readFileSync(path.join(__dirname, '..', 'cases', `${name}.js`), 'utf8');
      await page.addScriptTag({ content: source });
      const outcome = await page.evaluate((probe) => {
        try {
          const value = run(probe);
          return value === 'object' ? 'direct-eval' : value === 'undefined' ? 'indirect-eval' : `no-eval (returned ${JSON.stringify(value)})`;
        } catch (error) {
          return `no-eval (${error.name}: ${error.message})`;
        }
      }, PROBE);
      lines.push(`${name.padEnd(28)} ${outcome}`);
      await page.close();
    }
  } finally {
    await browser.close();
  }
  console.log(lines.join('\n'));
})();
