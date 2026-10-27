// Real-browser comparison for the bounded visible chain filter.
//
// Oracle: pinned playwright-core@1.64.1 driving the workspace Chrome, resolving
// the same authored selectors. Probe: the production MATCH_QUERY realm fed real
// Element handles from the same page. This is not a CDP/native-daemon proof:
// no agent-browser daemon or secure-field inventory participates.
//
// Run: PLAYWRIGHT_CORE_DIR=/path/to/playwright-core@1.64.1 \
//        node cli/tests/fixtures/native-observation-visible-chain-browser.cjs
// Requires an already installed playwright-core 1.64.1 (set PLAYWRIGHT_CORE_DIR
// to its extracted package directory). Never installs anything.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const coreDir = process.env.PLAYWRIGHT_CORE_DIR;
if (!coreDir) {
  console.error('PLAYWRIGHT_CORE_DIR must point at an extracted playwright-core@1.64.1 package');
  process.exit(2);
}
const { chromium } = require(coreDir);
const chrome = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const sourcePath = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const script = require('./native-observation-script.cjs')(sourcePath, 'MATCH_QUERY');

const PAGE = `<!doctype html><html><head><style>
  .box { width: 10px; height: 10px; }
</style></head><body>
<div id="shown" class="box">shown</div>
<div id="display-none" style="display:none">none</div>
<div id="visibility-hidden" style="visibility:hidden" class="box">hidden</div>
<div id="visibility-collapse" style="visibility:collapse" class="box">collapse</div>
<div id="zero-area" style="width:0;height:0;overflow:hidden">zero</div>
<div id="opacity-zero" style="opacity:0" class="box">opacity</div>
<div id="content-skipped" style="content-visibility:hidden" class="box">skipped</div>
<div id="contents-empty" style="display:contents"></div>
<div id="contents-child" style="display:contents"><span id="contents-visible-child" class="box">child</span></div>
<div id="contents-zero-child" style="display:contents"><span id="contents-zero-grandchild" style="display:none">zero child</span></div>
<div id="contents-text" style="display:contents">painted text</div>
<div id="contents-zero-text" style="display:contents"><span style="display:none">x</span></div>
<div id="contents-hidden-text" style="display:contents;visibility:hidden">invisible text</div>
<div id="contents-override" style="display:contents;visibility:hidden"><span id="contents-override-child" style="visibility:visible" class="box">override</span></div>
<div id="inert-node" inert class="box">inert</div>
<div id="aria-hidden-node" aria-hidden="true" class="box">aria</div>
<div id="hidden-attribute" class="box" hidden>hidden attr</div>
<details id="details"><summary id="summary">s</summary><span id="folded" class="box">folded</span></details>
<input id="inp" class="box" value="x">
<ul id="rows">
  <li id="row-1" style="display:none"><span class="box">one</span></li>
  <li id="row-2"><span class="box">two</span></li>
  <li id="row-3" style="visibility:hidden"><span class="box">three</span></li>
  <li id="row-4"><span class="box">four</span></li>
</ul>
<div id="open-host" class="box"></div>
<div id="closed-host" class="box"></div>
<div id="contents-host" style="display:contents"></div>
<script>
  const openRoot = document.getElementById('open-host').attachShadow({ mode: 'open' });
  openRoot.innerHTML = '<div id="open-inner" class="box">inner</div><div id="open-shown" class="box">shown</div>';
  const closedRoot = document.getElementById('closed-host').attachShadow({ mode: 'closed' });
  closedRoot.innerHTML = '<div id="closed-inner" class="box">closed</div>';
  const contentsRoot = document.getElementById('contents-host').attachShadow({ mode: 'open' });
  contentsRoot.innerHTML = '<span id="contents-shadow-child" class="box">shadow</span>';
</script>
</body></html>`;

// Production `author_query_ids` walks light DOM and open shadow roots. Mirror
// that inventory shape here so chain results can be mapped back to elements.
const INVENTORY = `() => {
  const out = [];
  const visit = root => {
    for (const element of root.querySelectorAll('*')) {
      out.push(element);
      if (element.shadowRoot) visit(element.shadowRoot);
    }
  };
  visit(document);
  return out;
}`;

// Each case is the exact part list the production Rust parser produces for the
// authored selector string in `selector` (asserted by selector.rs tests). The
// oracle still receives the authored string, so no second chain parser lives
// here.
const CASES = [
  { selector: 'visible=true', parts: [{ engine: 'visible', body: 'true' }] },
  { selector: 'visible=false', parts: [{ engine: 'visible', body: 'false' }] },
  { selector: 'visible=', parts: [{ engine: 'visible', body: '' }] },
  { selector: 'visible=TRUE', parts: [{ engine: 'visible', body: 'TRUE' }] },
  { selector: 'visible= true', parts: [{ engine: 'visible', body: ' true' }] },
  { selector: '* >> visible=true', parts: [{ engine: 'css', body: '*' }, { engine: 'visible', body: 'true' }] },
  { selector: '* >> visible=false', parts: [{ engine: 'css', body: '*' }, { engine: 'visible', body: 'false' }] },
  { selector: '.box >> visible=true', parts: [{ engine: 'css', body: '.box' }, { engine: 'visible', body: 'true' }] },
  { selector: '.box >> visible=false', parts: [{ engine: 'css', body: '.box' }, { engine: 'visible', body: 'false' }] },
  { selector: '#rows >> li >> visible=true', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'true' }] },
  { selector: '#rows >> li >> visible=false', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'false' }] },
  { selector: '#rows >> li >> nth=0 >> visible=true', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'nth', body: '0' }, { engine: 'visible', body: 'true' }] },
  { selector: '#rows >> li >> nth=0 >> visible=false', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'nth', body: '0' }, { engine: 'visible', body: 'false' }] },
  { selector: '#rows >> li >> visible=true >> nth=0', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'true' }, { engine: 'nth', body: '0' }] },
  { selector: '#rows >> li >> visible=true >> nth=-1', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'true' }, { engine: 'nth', body: '-1' }] },
  { selector: '#rows >> li >> visible=false >> nth=1', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'false' }, { engine: 'nth', body: '1' }] },
  { selector: '#contents-child >> visible=true >> span', parts: [{ engine: 'css', body: '#contents-child' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: 'span' }] },
  { selector: '#contents-zero-child >> visible=true >> span', parts: [{ engine: 'css', body: '#contents-zero-child' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: 'span' }] },
  { selector: '#open-host >> visible=true >> css=#open-shown', parts: [{ engine: 'css', body: '#open-host' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: '#open-shown' }] },
  { selector: '* >> visible=true >> css=#open-inner', parts: [{ engine: 'css', body: '*' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: '#open-inner' }] },
  { selector: '* >> visible=true >> css=#closed-inner', parts: [{ engine: 'css', body: '*' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: '#closed-inner' }] },
  { selector: '* >> visible=true >> css=#contents-shadow-child', parts: [{ engine: 'css', body: '*' }, { engine: 'visible', body: 'true' }, { engine: 'css', body: '#contents-shadow-child' }] },
  { selector: '#shown >> visible=true >> visible=false', parts: [{ engine: 'css', body: '#shown' }, { engine: 'visible', body: 'true' }, { engine: 'visible', body: 'false' }] },
  { selector: '#shown >> visible=true >> visible=true', parts: [{ engine: 'css', body: '#shown' }, { engine: 'visible', body: 'true' }, { engine: 'visible', body: 'true' }] },
  // Final capture only: native validation refuses a capture before the last
  // part, so these are the forms it accepts. Playwright's capture rewrite and
  // the native root filter agree on the result for both.
  { selector: '.box >> *visible=true', parts: [{ engine: 'css', body: '.box' }, { engine: 'visible', body: 'true' }] },
  { selector: '.box >> *visible=false', parts: [{ engine: 'css', body: '.box' }, { engine: 'visible', body: 'false' }] },
  { selector: '#rows >> li >> *visible=false', parts: [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }, { engine: 'visible', body: 'false' }] },
  // The body boundary in a real document: body/html are Elements, unlike the
  // document root itself.
  { selector: 'body >> visible=true', parts: [{ engine: 'css', body: 'body' }, { engine: 'visible', body: 'true' }] },
  { selector: 'body >> visible=false', parts: [{ engine: 'css', body: 'body' }, { engine: 'visible', body: 'false' }] },
  { selector: 'body >> visible=', parts: [{ engine: 'css', body: 'body' }, { engine: 'visible', body: '' }] },
  { selector: 'html >> visible=true', parts: [{ engine: 'css', body: 'html' }, { engine: 'visible', body: 'true' }] },
  { selector: 'html >> visible=false', parts: [{ engine: 'css', body: 'html' }, { engine: 'visible', body: 'false' }] },
];
const IDS = [
  'shown', 'display-none', 'visibility-hidden', 'visibility-collapse', 'zero-area',
  'opacity-zero', 'content-skipped', 'contents-empty', 'contents-child', 'contents-visible-child',
  'contents-zero-child', 'contents-zero-grandchild', 'contents-text', 'contents-zero-text',
  'contents-hidden-text', 'contents-override', 'contents-override-child', 'inert-node',
  'aria-hidden-node', 'hidden-attribute', 'details', 'summary', 'folded', 'inp',
  'row-1', 'row-2', 'row-3', 'row-4', 'open-host', 'open-inner', 'open-shown', 'closed-host',
  'closed-inner', 'contents-host', 'contents-shadow-child',
];

(async () => {
  const browser = await chromium.launch({ executablePath: chrome, headless: true });
  const page = await browser.newPage();
  await page.setContent(PAGE);

  let checks = 0;
  let mismatches = 0;
  const report = [];
  async function oracle(selector) {
    try {
      return await page.locator(selector).evaluateAll(els => els.map(e => e.id || e.tagName));
    } catch (error) {
      return { error: String(error.message).split('\n')[0] };
    }
  }
  async function probe(parts) {
    const result = await page.evaluate(({ script, inventory, parts }) => {
      const els = eval(`(${inventory})`)();
      const fn = eval(`(${script})`);
      const data = els.map(() => ({ states: { secure: false, hidden: false } }));
      return fn(
        { kind: 'selector', nativeParts: parts },
        data, els.map(() => []), els.map(() => null), '.secure', els.map(() => false), ...els,
      );
    }, { script, inventory: INVENTORY, parts });
    if (result.error) return { error: result.error };
    return await page.evaluate(({ inventory, indices }) => {
      const els = eval(`(${inventory})`)();
      return indices.map(i => els[i].id || els[i].tagName);
    }, { inventory: INVENTORY, indices: result.indices });
  }
  async function probeHas(source, inner) {
    const result = await page.evaluate(({ script, inventory, source, inner }) => {
      const els = eval(`(${inventory})`)();
      const fn = eval(`(${script})`);
      const data = els.map(() => ({ states: { secure: false, hidden: false } }));
      return fn(
        {
          kind: 'filter',
          source: { kind: 'selector', nativeParts: source },
          has: { kind: 'selector', nativeParts: inner },
        },
        data, els.map(() => []), els.map(() => null), '.secure', els.map(() => false), ...els,
      );
    }, { script, inventory: INVENTORY, source, inner });
    if (result.error) return { error: result.error };
    return await page.evaluate(({ inventory, indices }) => {
      const els = eval(`(${inventory})`)();
      return indices.map(i => els[i].id || els[i].tagName);
    }, { inventory: INVENTORY, indices: result.indices });
  }
  for (const { selector, parts } of CASES) {
    const expected = await oracle(selector);
    const actual = await probe(parts);
    const equal = JSON.stringify(sorted(expected)) === JSON.stringify(sorted(actual));
    checks++;
    if (!equal) { mismatches++; report.push({ selector, expected, actual }); }
  }
  // Element root in a chain: Playwright's `has` engine evaluates the inner
  // selector with the candidate element as its root, so the first `visible`
  // step filters that element itself before the next step searches below it.
  for (const body of ['true', 'false']) {
    const expected = await page
      .locator('#rows >> li')
      .filter({ has: page.locator(`visible=${body} >> css=span`) })
      .evaluateAll(els => els.map(e => e.id));
    const actual = await probeHas(
      [{ engine: 'css', body: '#rows' }, { engine: 'css', body: 'li' }],
      [{ engine: 'visible', body }, { engine: 'css', body: 'span' }],
    );
    const equal = JSON.stringify(sorted(expected)) === JSON.stringify(sorted(actual));
    checks++;
    if (!equal) { mismatches++; report.push({ selector: `filter(has: visible=${body} >> span)`, expected, actual }); }
  }
  // Terminal Element root: the inner chain ends on `visible`, so the candidate
  // element is the only possible match. Both directions plus both negatives.
  // CSS `:scope` is the pre-existing form of the same root match.
  for (const [source, inner] of [
    ['#shown', 'visible=true'],
    ['#display-none', 'visible=false'],
    ['#shown', 'visible=false'],
    ['#display-none', 'visible=true'],
    ['#shown', ':scope'],
  ]) {
    const expected = await page
      .locator(source)
      .filter({ has: page.locator(inner) })
      .evaluateAll(els => els.map(e => e.id || e.tagName));
    const actual = await probeHas(
      [{ engine: 'css', body: source }],
      inner === ':scope'
        ? [{ engine: 'css', body: ':scope' }]
        : [{ engine: 'visible', body: inner.slice('visible='.length) }],
    );
    const equal = JSON.stringify(sorted(expected)) === JSON.stringify(sorted(actual));
    checks++;
    if (!equal) { mismatches++; report.push({ selector: `terminal filter(has: ${inner}) on ${source}`, expected, actual }); }
  }
  // Per-element oracle: each element id filtered in both directions.
  for (const id of IDS) {
    for (const body of ['true', 'false', '', 'TRUE', ' true']) {
      const selector = `#${id} >> visible=${body}`;
      const expected = await oracle(selector);
      const actual = await probe([
        { engine: 'css', body: `#${id}` },
        { engine: 'visible', body },
      ]);
      const equal = JSON.stringify(sorted(expected)) === JSON.stringify(sorted(actual));
      checks++;
      if (!equal) { mismatches++; report.push({ selector, expected, actual }); }
    }
  }
  await browser.close();
  if (report.length) {
    console.error(JSON.stringify(report, null, 1));
    console.error(`FAIL: ${mismatches}/${checks} visible-chain comparisons disagreed with playwright-core@1.64.1`);
    process.exit(1);
  }
  console.log(`PASS: ${checks} visible-chain comparisons agree with pinned playwright-core@1.64.1 in a real Chrome page. Not a native-daemon proof.`);
})().catch(error => { console.error(error); process.exit(1); });

function sorted(value) {
  if (!Array.isArray(value)) return value;
  return value.slice().sort();
}

