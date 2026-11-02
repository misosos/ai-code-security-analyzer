import type { Page } from '@playwright/test';

const selectors = [
  '.workspace-title',
  '.scan-context',
  '.context-primary',
  '.context-identifiers',
  '.context-identifiers > span',
  '.export-note',
  '.scan-banner',
  '.overview-grid.analyst-overview-core',
  '.overview-analysis-grid',
  '.analyst-review-summary',
  '.analyst-review-summary-heading',
  '.analyst-review-counts',
  '.analyst-review-count',
  '.analyst-review-scope',
  '.severity-counts',
  '.severity-count',
  '.scan-comparison-compact',
  '.comparison-compact-copy',
  '.results-heading',
  '.filter-row',
  '.results-layout',
  '.finding-row',
];

export async function measureAnalystLayout(page: Page) {
  return page.evaluate((items) => {
    const root = getComputedStyle(document.documentElement);
    const body = getComputedStyle(document.body);
    const main = document.querySelector<HTMLElement>('#main-content');
    const mainStyle = main ? getComputedStyle(main) : null;
    const environment = {
      viewport: { width: innerWidth, height: innerHeight, dpr: devicePixelRatio },
      rootFontSize: root.fontSize,
      readabilityLineVariable: root.getPropertyValue('--readability-line').trim(),
      bodyFont: body.fontFamily,
      bodyFontSize: body.fontSize,
      bodyLineHeight: body.lineHeight,
      mainFontSize: mainStyle?.fontSize,
      mainLineHeight: mainStyle?.lineHeight,
    };
    const layout = Object.fromEntries(items.map((selector) => {
      const elements = [...document.querySelectorAll<HTMLElement>(selector)];
      return [selector, elements.map((element) => {
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        x: Math.round(rect.x * 100) / 100,
        documentY: Math.round((rect.y + window.scrollY) * 100) / 100,
        width: Math.round(rect.width * 100) / 100,
        height: Math.round(rect.height * 100) / 100,
        marginTop: style.marginTop,
        marginBottom: style.marginBottom,
        paddingTop: style.paddingTop,
        paddingBottom: style.paddingBottom,
        fontSize: style.fontSize,
        lineHeight: style.lineHeight,
        display: style.display,
        gridTemplateRows: style.gridTemplateRows,
        textLines: (() => {
          const range = document.createRange();
          range.selectNodeContents(element);
          return new Set([...range.getClientRects()].map((line) => Math.round(line.top * 2) / 2)).size;
        })(),
      };
      })];
    }));
    return { environment, layout };
  }, selectors);
}
