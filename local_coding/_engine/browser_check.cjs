'use strict';

// Trusted, packet-owned browser assertions. The rendered HTML remains untrusted.
const fs = require('node:fs');
const path = require('node:path');
const {fileURLToPath, pathToFileURL} = require('node:url');

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}

function boundedPush(array, value) {
  if (array.length < 20) array.push(String(value).slice(0, 2000));
}

async function main() {
  if (process.argv.length !== 3) throw new Error('One trusted specification file is required');
  const specification = process.argv[2];
  const specStat = fs.lstatSync(specification);
  if (!specStat.isFile() || specStat.isSymbolicLink() || specStat.size > 65536) throw new Error('Invalid specification');
  const spec = JSON.parse(fs.readFileSync(specification, 'utf8'));
  const candidate = fs.realpathSync(spec.candidate);
  const scratch = fs.realpathSync(spec.scratch);
  if (inside(candidate, scratch)) throw new Error('Browser scratch must be outside the source candidate');
  const pack = spec.pack;
  if (pack.type !== 'html-browser' || !Array.isArray(pack.widths) || pack.widths.length > 3) throw new Error('Invalid browser pack');
  const target = path.resolve(candidate, pack.path);
  if (!inside(candidate, target) || fs.realpathSync(target) !== target) throw new Error('Unsafe HTML path');
  const targetStat = fs.lstatSync(target);
  if (!targetStat.isFile() || targetStat.size > 128 * 1024) throw new Error('Invalid HTML target');
  if (!spec.runtime || Object.keys(spec.runtime).sort().join(',') !== 'chrome,playwright') {
    throw new Error('Explicit trusted browser runtime is required');
  }
  for (const name of ['chrome', 'playwright']) {
    const filename = spec.runtime[name];
    if (typeof filename !== 'string' || !path.isAbsolute(filename) ||
        fs.realpathSync(filename) !== filename || !fs.lstatSync(filename).isFile()) {
      throw new Error('Invalid trusted browser runtime path');
    }
  }
  const {chromium} = require(spec.runtime.playwright);
  const CHROME = spec.runtime.chrome;
  const screenshots = path.join(scratch, 'screenshots');
  fs.mkdirSync(screenshots);
  const result = {type: 'html-browser', passed: true, executed: true, external_resources: [],
    console_errors: [], page_errors: [], viewports: [], browser: 'existing-google-chrome',
    profile_policy: 'fresh-task-scratch-only', network_policy: 'OS-restricted-and-browser-route-block',
    accessibility_coverage: 'not-assessed-no-axe'};

  for (const width of pack.widths) {
    if (!Number.isInteger(width) || width < 320 || width > 1920) throw new Error('Invalid viewport');
    const profile = path.join(scratch, 'profile-' + width);
    if (fs.existsSync(profile)) throw new Error('Browser profile must be new');
    let context;
    const viewport = {width, height: 900, expected_text: [], clicks: [], passed: false};
    try {
      context = await chromium.launchPersistentContext(profile, {
        executablePath: CHROME, headless: true, chromiumSandbox: true,
        viewport: {width, height: 900}, serviceWorkers: 'block', acceptDownloads: false,
        timeout: 15000,
      });
      await context.route('**/*', async route => {
        const url = route.request().url();
        let allowed = false;
        try {
          const parsed = new URL(url);
          if (parsed.protocol === 'file:') {
            const requested = fileURLToPath(parsed);
            allowed = inside(candidate, requested) && fs.realpathSync(requested) === requested;
          } else if (parsed.protocol === 'data:' || parsed.protocol === 'blob:') {
            allowed = true;
          }
        } catch (_) { /* invalid and nonexistent paths remain denied */ }
        if (allowed) return route.continue();
        boundedPush(result.external_resources, url);
        return route.abort('blockedbyclient');
      });
      if (typeof context.routeWebSocket !== 'function') throw new Error('WebSocket blocking capability is unavailable');
      await context.routeWebSocket('**/*', socket => {
        boundedPush(result.external_resources, socket.url());
        socket.close();
      });
      const page = context.pages()[0] || await context.newPage();
      page.setDefaultTimeout(2500);
      page.on('console', message => { if (message.type() === 'error') boundedPush(result.console_errors, message.text()); });
      page.on('pageerror', error => boundedPush(result.page_errors, error.message));
      page.on('dialog', dialog => dialog.dismiss());
      page.on('download', download => { boundedPush(result.external_resources, 'download:' + download.url()); download.cancel(); });
      context.on('page', popup => { if (popup !== page) { boundedPush(result.external_resources, 'unexpected-popup'); popup.close(); } });
      await page.goto(pathToFileURL(target).href, {waitUntil: 'domcontentloaded', timeout: 8000});
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      for (const text of pack.expected_text) {
        const visible = await page.getByText(text, {exact: false}).first().isVisible();
        viewport.expected_text.push({text, visible});
      }
      for (const click of pack.clicks) {
        const beforeVisible = await page.getByText(click.expect_text, {exact: false}).first().isVisible();
        if (beforeVisible) {
          viewport.clicks.push({selector: click.selector, expect_text: click.expect_text,
            before_visible: true, after_visible: true, passed: false, reason: 'expected-change-already-visible'});
          throw new Error('Click expectation was already visible before the action');
        }
        await page.locator(click.selector).click();
        await page.getByText(click.expect_text, {exact: false}).first().waitFor({state: 'visible'});
        viewport.clicks.push({selector: click.selector, expect_text: click.expect_text,
          before_visible: false, after_visible: true, passed: true});
      }
      viewport.layout = await page.evaluate(() => ({
        viewport_width: window.innerWidth,
        document_width: document.documentElement.scrollWidth,
        horizontal_overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
        body_present: !!document.body,
      }));
      viewport.screenshot = path.join(screenshots, 'viewport-' + width + '.png');
      await page.screenshot({path: viewport.screenshot, fullPage: false, timeout: 5000});
      viewport.passed = viewport.layout.body_present && !viewport.layout.horizontal_overflow &&
        viewport.expected_text.every(assertion => assertion.visible) && viewport.clicks.length === pack.clicks.length;
    } catch (error) {
      const message = String(error.message || error);
      const failures = message.split('\n').filter(line => /\[err\]|exitCode=|signal=|sandbox|ERROR|FATAL/.test(line));
      viewport.error = (failures.length ? failures.join('\n') : message).slice(-4000);
    } finally {
      if (context) await context.close().catch(error => { viewport.passed = false; viewport.close_error = String(error.message).slice(0, 500); });
    }
    result.viewports.push(viewport);
  }
  result.passed = result.viewports.length === pack.widths.length && result.viewports.every(viewport => viewport.passed) &&
    result.external_resources.length === 0 && result.console_errors.length === 0 && result.page_errors.length === 0;
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exitCode = result.passed ? 0 : 1;
}

main().catch(error => {
  process.stdout.write(JSON.stringify({type: 'html-browser', passed: false, executed: true,
    error: String(error.message || error).slice(0, 2000)}) + '\n');
  process.exitCode = 1;
});
