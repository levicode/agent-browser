// Deterministic renderer contract probe; Chromium remains the rendering oracle.
// Run: node cli/tests/fixtures/native-observation-visibility.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../src/native/client_observation.rs'), 'utf8');
const body = source.match(/ function renderVisible\(root\) \{([\s\S]*?)\n \}\n const hidden=/)[1];
const doc = {
  defaultView: { getComputedStyle: node => node.style },
  createRange: () => ({ selectNode(node) { this.node = node; }, getBoundingClientRect() { return this.node.box; } }),
};
const visible = new Function('doc', `return function(root) {${body}}`)(doc);
function element(options = {}) {
  return {
    nodeType: 1, childNodes: [], parentElement: null, assignedSlot: null,
    style: { display: 'block', visibility: 'visible', contentVisibility: 'visible' },
    box: { width: 10, height: 10 }, nativeVisible: true,
    getRootNode() { return {}; }, getBoundingClientRect() { return this.box; },
    checkVisibility(flags) {
      assert.deepEqual(flags, { visibilityProperty: true, opacityProperty: false, contentVisibilityAuto: false });
      return this.nativeVisible;
    },
    ...options,
  };
}
assert.equal(visible(element()), true);
assert.equal(visible(element({ nativeVisible: false })), false); // folded/skipped native result
assert.equal(visible(element({ box: { width: 0, height: 10 } })), false);
const contents = (children, visibility = 'visible') => element({
  style: { display: 'contents', visibility }, childNodes: children,
  checkVisibility() { throw Error('No native box exists on display:contents'); },
});
assert.equal(visible(contents([])), false);
assert.equal(visible(contents([element()])), true);
assert.equal(visible(contents([element()], 'hidden')), true); // child visibility can override
const text = { nodeType: 3, box: { width: 15, height: 10 } };
assert.equal(visible(contents([text])), true);
assert.equal(visible(contents([text], 'hidden')), false);
const skipped = contents([text]);
skipped.parentElement = element({ style: { contentVisibility: 'hidden' } });
assert.equal(visible(skipped), false);
const slotted = contents([text]);
slotted.assignedSlot = skipped.parentElement;
assert.equal(visible(slotted), false);
console.log('PASS: native rendering flags, contents descendants/text, zero-area and flat-tree suppression');
const foldedContents = contents([text]);
foldedContents.parentElement = element({ localName: 'details', open: false, children: [] });
assert.equal(visible(foldedContents), false);
const summary = element({ localName: 'summary' });
const inSummary = contents([text]);
inSummary.parentElement = summary;
summary.parentElement = element({ localName: 'details', open: false, children: [summary] });
assert.equal(visible(inSummary), true);
