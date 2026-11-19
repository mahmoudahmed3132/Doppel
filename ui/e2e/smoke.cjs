// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// UI end-to-end smoke test against a fresh development Hub (see ui/README.md).
// Usage: node ui/e2e/smoke.cjs <screenshot-dir>
// Env: TS_E2E_BASE (default http://127.0.0.1:18080), TS_E2E_SETUP_TOKEN.
// Requires Playwright with Chromium (not a project dependency).
const { chromium } = require('playwright');
const base = process.env.TS_E2E_BASE || 'http://127.0.0.1:18080';
const SETUP_TOKEN = process.env.TS_E2E_SETUP_TOKEN || 'e2e-setup-token-0123456789abcdef';
const shots = process.argv[2] || '.';
const uuid7 = () => {
  const b = require('crypto').randomBytes(16); const t = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((t >> BigInt(8 * (5 - i))) & 0xffn);
  b[6] = (b[6] & 0x0f) | 0x70; b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex'); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
};
const PW = 'correct-horse-battery-staple-42';
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const problems = [];
  page.on('console', (m) => { if (m.type() === 'error' || /Content Security Policy|Refused to/.test(m.text())) problems.push('console: ' + m.text()); });
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  const step = async (name, fn) => { try { await fn(); console.log('ok  ', name); } catch (e) { console.log('FAIL', name, e.message.split('\n')[0]); problems.push(name); } };
  const shot = (n) => page.screenshot({ path: `${shots}/${n}.png`, fullPage: true });

  await step('setup', async () => {
    await page.goto(base + '/');
    await page.getByLabel('Setup token').fill(SETUP_TOKEN);
    await page.getByLabel('Admin password').fill(PW);
    await page.getByLabel('Confirm password').fill(PW);
    await page.getByText('Strong').or(page.getByText('Good')).first().waitFor();
    await shot('01-setup');
    await page.getByRole('button', { name: 'Complete setup' }).click();
    await page.getByRole('heading', { name: 'Sign in' }).waitFor();
  });
  await step('wrong password message', async () => {
    await page.getByLabel('Password').fill('nope-nope-nope');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByText('Incorrect password.').waitFor();
  });
  await step('login', async () => {
    await page.getByLabel('Password').fill(PW);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByRole('heading', { name: 'Dashboard' }).waitFor();
    await page.locator('.live-open').waitFor({ timeout: 5000 });
  });
  let key = '';
  await step('create node, key shown once', async () => {
    await page.getByRole('link', { name: 'Fleet' }).first().click();
    await page.getByRole('button', { name: 'Create node' }).click();
    await page.getByLabel('Alias').fill('cairo-dmz-01');
    await page.getByLabel('Tags').fill('dmz, pci');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByText('shown only once').waitFor();
    key = (await page.locator('.secret-value').first().textContent()).trim();
    if (!/^tsk_[0-9a-f]{64}$/.test(key)) throw new Error('bad key ' + key);
    const cmd = await page.locator('.secret-value').nth(1).textContent();
    if (!cmd.includes('doppel link') || !cmd.startsWith('TS_NODE_KEY=')) throw new Error('bad command ' + cmd);
    await shot('02-node-key');
    if (await page.getByRole('button', { name: 'Done' }).isEnabled()) throw new Error('Done enabled before ack');
    await page.getByLabel('I have stored the key').check();
    await page.getByRole('button', { name: 'Done' }).click();
    await page.getByRole('link', { name: 'cairo-dmz-01' }).click();
    await page.getByRole('heading', { name: 'cairo-dmz-01' }).waitFor();
  });
  await step('add sensor via generated form', async () => {
    await page.getByRole('button', { name: 'Add sensor' }).click();
    const item = page.locator('.cat-item', { hasText: 'TCP tarpit' });
    await item.getByRole('button', { name: 'Configure' }).click();
    await page.getByLabel('TS_PORTS *').waitFor();
    await page.getByRole('button', { name: 'Add sensor', exact: true }).last().click();
    await page.getByText('Required').first().waitFor();   // client-side validation
    await page.getByLabel('TS_PORTS *').fill('2222, 99999');
    await page.getByRole('button', { name: 'Preview compose' }).click();
    await page.getByText('Port must be 1–65535').waitFor();
    await page.getByLabel('TS_PORTS *').fill('2222,2323');
    await page.getByRole('button', { name: 'Preview compose' }).click();
    await page.getByText('Compose preview (secrets redacted)').waitFor();
    await shot('03-sensor-form');
    await page.getByRole('button', { name: 'Add sensor', exact: true }).last().click();
    await page.locator('td.mono', { hasText: 'tcp-tarpit' }).first().waitFor();
  });
  await step('port conflict surfaced', async () => {
    await page.getByRole('button', { name: 'Add sensor' }).click();
    await page.locator('.cat-item', { hasText: 'TCP tarpit' }).getByRole('button', { name: 'Configure' }).click();
    await page.getByLabel('Instance name (optional)').fill('second');
    await page.getByLabel('TS_PORTS *').fill('2222');
    await page.getByRole('button', { name: 'Add sensor', exact: true }).last().click();
    await page.getByText(/Port conflict/).waitFor();
    await page.keyboard.press('Escape');
  });
  // Ingest events with the node key, as a sensor would.
  const node = await (await page.request.get(base + '/api/v3/nodes')).json();
  const nodeId = node.nodes[0].id;
  const detail = await (await page.request.get(base + `/api/v3/nodes/${nodeId}`)).json();
  const sensorId = detail.node.sensors[0].id;
  const ingest = async (n, extra = {}) => {
    const events = [];
    for (let i = 0; i < n; i++) events.push({
      event_id: uuid7(), sensor_id: sensorId, trigger: 'tcp_connection', severity: i % 3 ? 'medium' : 'critical',
      occurred_at: new Date().toISOString(), source: `203.0.113.${10 + i}`, target: '10.0.0.5:2222',
      details: { payload: '<img src=x onerror=alert(1)>', port: 2222, ...extra },
    });
    const r = await fetch(base + '/v3/ingest/events', { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body: JSON.stringify({ events }) });
    const txt = await r.text();
    if (!r.ok) throw new Error('ingest ' + r.status + ' ' + txt);
  };
  await step('events page + live notice + drawer escapes HTML', async () => {
    await ingest(5);
    await page.getByRole('link', { name: /^Events/ }).click();
    await page.locator('.events-table tbody tr').first().waitFor();
    await ingest(2);
    await page.getByText(/2 new events since/).waitFor({ timeout: 5000 });
    await page.getByRole('button', { name: 'Show', exact: true }).click();
    await page.waitForFunction(() => document.querySelectorAll('.events-table tbody tr').length === 7, null, { timeout: 5000 });
    const badge = await page.locator('.badge').textContent();
    await shot('04-events');
    await page.locator('.events-table tbody tr').first().click();
    await page.getByText('Details', { exact: true }).waitFor();
    const pre = await page.locator('dialog[open] pre.code').textContent();
    if (!pre.includes('<img src=x onerror=alert(1)>')) throw new Error('details not shown as text');
    if (await page.locator('dialog[open] img').count()) throw new Error('HTML injected');
    await shot('05-event-drawer');
    await page.keyboard.press('Escape');
    console.log('     unread badge was', badge);
  });
  await step('severity filter', async () => {
    await page.locator('label.chip-critical').click();
    await page.getByRole('button', { name: 'Apply' }).click();
    await page.waitForTimeout(400);
    const sevs = await page.locator('.events-table tbody .sev').allTextContents();
    if (!sevs.length || sevs.some((s) => s !== 'critical')) throw new Error('filter ' + sevs);
  });
  await step('dashboard renders charts', async () => {
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await page.locator('svg.chart').waitFor();
    await page.locator('.sevbars').waitFor();
    await page.locator('svg.heatmap').waitFor();
    await shot('06-dashboard');
  });
  await step('settings tabs', async () => {
    await page.getByRole('link', { name: 'Settings' }).click();
    for (const t of ['General', 'Source lists', 'Retention', 'SIEM output', 'Webhook', 'Security', 'Danger zone']) {
      await page.getByRole('tab', { name: t }).click();
      await page.waitForTimeout(150);
    }
    await page.getByRole('tab', { name: 'Security' }).click();
    await page.getByText('The TOTP module is not installed').waitFor();
    await page.getByRole('tab', { name: 'Retention' }).click();
    await page.getByLabel('Archive events after (days)').fill('90');
    await page.getByRole('button', { name: 'Save retention' }).click();
    await page.getByText('Settings saved').waitFor();
    await page.getByRole('tab', { name: 'Danger zone' }).click();
    await page.getByRole('button', { name: 'Delete all events' }).click();
    const confirm = page.locator('dialog[open]').getByRole('button', { name: 'Delete all events' });
    if (await confirm.isEnabled()) throw new Error('confirm enabled before typing');
    await page.getByLabel('Type DELETE ALL EVENTS to confirm').fill('DELETE ALL EVENTS');
    await shot('07-danger');
    await page.keyboard.press('Escape');
  });
  await step('module shells', async () => {
    for (const [l, txt] of [['Beacons', 'module not installed'], ['ATT&CK', 'module not installed'], ['Geo map', 'module not installed'], ['Honeytokens', 'No honeytokens']]) {
      await page.getByRole('link', { name: l, exact: true }).click();
      await page.getByText(txt).first().waitFor();
    }
  });
  await step('light theme', async () => {
    await page.getByRole('button', { name: /Switch to light theme/ }).click();
    await page.getByRole('link', { name: 'Fleet' }).first().click();
    await page.getByRole('link', { name: 'cairo-dmz-01' }).click();
    await page.getByRole('heading', { name: 'cairo-dmz-01' }).waitFor();
    await shot('08-node-light');
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await page.locator('svg.heatmap').waitFor();
    await shot('09-dashboard-light');
  });
  await step('keyboard: tab reaches nav and rows', async () => {
    await page.goto(base + '/events');
    await page.locator('.events-table').waitFor();
    for (let i = 0; i < 90; i++) {
      await page.keyboard.press('Tab');
      if (await page.evaluate(() => document.activeElement?.classList.contains('row-click'))) {
        await page.keyboard.press('Enter');
        await page.locator('dialog[open]').waitFor();
        return;
      }
    }
    throw new Error('no focusable row');
  });
  await step('logout ends live feed and returns to login', async () => {
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByRole('heading', { name: 'Sign in' }).waitFor();
  });
  // CSP header present on the SPA document
  const r = await page.request.get(base + '/fleet');
  if (!/default-src 'self'/.test(r.headers()['content-security-policy'] || '')) problems.push('no CSP on SPA');
  await browser.close();
  const real = problems.filter((p) => !/status of 40[134]|status of 409|status of 422/.test(p));
  console.log(real.length ? 'PROBLEMS:\n' + real.join('\n') : 'no CSP violations or page errors');
  process.exit(real.length ? 1 : 0);
})();
