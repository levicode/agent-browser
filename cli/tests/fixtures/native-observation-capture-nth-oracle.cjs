// Real-browser oracle for the pinned capture-with-nth refusal.
//
// Oracle: pinned playwright-core@1.64.1 driving the workspace Chrome. Each case
// below is the authored selector the native parser must classify the same way,
// limited to the bounded subset this adapter implements (a single final
// capture). The verdicts are Playwright's, not this adapter's re-derivation:
// the fixture only asserts what the pinned engine does with the same text.
//
// Run: PLAYWRIGHT_CORE_DIR=/path/to/playwright-core@1.64.1 \
//        node cli/tests/fixtures/native-observation-capture-nth-oracle.cjs
// Requires an already installed playwright-core 1.64.1 (set PLAYWRIGHT_CORE_DIR
// to its extracted package directory). Never installs anything.
//
// This is not a native-daemon proof: no agent-browser daemon, parser, or secure
// field inventory participates. It records the contract the Rust unit tests
// encode.
const coreDir = process.env.PLAYWRIGHT_CORE_DIR;
if (!coreDir) {
  console.error('PLAYWRIGHT_CORE_DIR must point at an extracted playwright-core@1.64.1 package');
  process.exit(2);
}
const { chromium } = require(coreDir);
const chrome = process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

const PAGE = `<ul id="rows"><li id="row-1">one</li><li id="row-2">two</li></ul>
<main><div data-testid="row"><i data-test-id="cell">c</i></div></main>`;

// [selector, expected, note]. `expected` is pinned Playwright's verdict:
// 'nth-capture' is the specific Can't query n-th element refusal, 'accept'
// means the selector resolves (possibly to zero matches).
const CASES = [
  // Any nth with a capture is refused, wherever the nth sits.
  ['css=li >> nth=0 >> *visible=true', 'nth-capture'],
  ['css=li >> nth=0 >> *visible=false', 'nth-capture'],
  ['css=li >> nth=0 >> *css=div', 'nth-capture'],
  ['css=li >> nth=0 >> *css:light=div', 'nth-capture'],
  ['css=li >> nth=0 >> *xpath=//li', 'nth-capture'],
  ['css=li >> nth=0 >> *data-testid=row', 'nth-capture'],
  ['css=li >> nth=0 >> *data-testid:light=row', 'nth-capture'],
  ['css=li >> nth=0 >> *data-test-id=cell', 'nth-capture'],
  ['css=li >> nth=0 >> *id=row-1', 'nth-capture'],
  ['css=li >> *css=div >> nth=0', 'nth-capture'],
  ['css=li >> *visible=true >> nth=0', 'nth-capture'],
  // Negative, repeated, coerced and empty position bodies still count.
  ['css=li >> nth=-1 >> *visible=true', 'nth-capture'],
  ['css=li >> nth=-2 >> *data-testid=row', 'nth-capture'],
  ['css=li >> nth=NaN >> *css=div', 'nth-capture'],
  ['css=li >> nth= >> *css=div', 'nth-capture'],
  ['css=li >> nth=Infinity >> *css=div', 'nth-capture'],
  ['css=li >> nth=0 >> nth=1 >> *css=div', 'nth-capture'],
  // The captured part may itself be nth; xpath does not change the rule.
  ['li >> *nth=0', 'nth-capture'],
  ['*nth=0', 'nth-capture'],
  ['nth=0 >> *css=li', 'nth-capture'],
  ['xpath=//li >> nth=0 >> *css=div', 'nth-capture'],
  // No capture: nth stays legal in every position, sign and repetition.
  ['li >> nth=0', 'accept'],
  ['li >> nth=-1', 'accept'],
  ['li >> nth=0 >> nth=1', 'accept'],
  ['css=ul >> nth=2 >> div', 'accept'],
  ['section >> nth=NaN', 'accept'],
  ['css=ul >> xpath=//li >> nth=-1', 'accept'],
  // No nth: a capture stays legal, including on its own.
  ['*css=li', 'accept'],
  ['ul >> *css=li', 'accept'],
  ['*visible=true', 'accept'],
  ['div >> *visible=false', 'accept'],
  ['*data-testid=row', 'accept'],
  ['*xpath=//li', 'accept'],
  ['css=ul >> *visible=true', 'accept'],
  // Playwright's public locator layer refuses a `:light` match as deprecated
  // above the engine (see selector-NOTICE.md), so the capture verdict is
  // observable only through that outer refusal.
  ['css=div >> *data-test-id:light=cell', 'light-deprecated'],
  // Only the parsed engine name counts; these characters are literal data.
  ['div:nth-child(1) >> *css=span', 'accept'],
  ['div[data-x="nth=0"] >> *css=span', 'accept'],
  ['data-testid=nth=0 >> *css=span', 'accept'],
  ['*css=nth', 'accept'],
  ['nth >> *css=div', 'accept'],
  ['css=li >> nth >> *css=div', 'accept'],
];

// Kept out of CASES because the two implementations deliberately differ: the
// adapter requires the single capture to be the final part, while pinned
// Playwright rewrites a mid-chain capture into has(...). Recorded here so the
// difference stays visible rather than silently assumed.
const KNOWN_DIVERGENCE = ['css=div >> *css=span >> css=b'];

(async () => {
  const browser = await chromium.launch({ executablePath: chrome, headless: true });
  const page = await browser.newPage();
  await page.setContent(PAGE);

  let checks = 0;
  const report = [];
  for (const [selector, expected] of CASES) {
    let verdict;
    let detail;
    try {
      verdict = 'accept';
      detail = `count=${await page.locator(selector).count()}`;
    } catch (error) {
      const first = String(error.message).split('\n')[0];
      verdict = /Can't query n-th element in a request with the capture/.test(first)
        ? 'nth-capture'
        : /selector is not supported/.test(first)
          ? 'light-deprecated'
          : 'other-error';
      detail = first;
    }
    checks++;
    if (verdict !== expected) {
      report.push({ selector, expected, verdict, detail });
    }
  }

  // The documented divergence must still be accepted by pinned Playwright; if
  // that ever changes, the adapter's extra strictness is no longer a superset
  // of the pinned rule and this fixture should be revisited.
  for (const selector of KNOWN_DIVERGENCE) {
    let accepted = true;
    let detail = '';
    try {
      detail = `count=${await page.locator(selector).count()}`;
    } catch (error) {
      accepted = false;
      detail = String(error.message).split('\n')[0];
    }
    checks++;
    if (!accepted) {
      report.push({ selector, expected: 'accept (known divergence)', verdict: 'nth-capture', detail });
    }
  }

  await browser.close();
  if (report.length) {
    console.error(JSON.stringify(report, null, 1));
    console.error(`FAIL: ${report.length}/${checks} capture-with-nth verdicts disagreed with playwright-core@1.64.1`);
    process.exit(1);
  }
  console.log(`PASS: ${checks} capture-with-nth verdicts agree with pinned playwright-core@1.64.1 in a real Chrome page. Not a native-daemon proof.`);
})().catch(error => { console.error(error); process.exit(1); });
