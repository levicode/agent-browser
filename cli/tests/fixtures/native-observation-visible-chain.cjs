// Browser-free fixture for the bounded `visible=` chain filter.
// Run: node cli/tests/fixtures/native-observation-visible-chain.cjs It executes the
// production MATCH_QUERY realm (same extraction as the other native-observation
// fixtures) against an explicit DOM double. The double supplies the browser
// visibility primitives (computed style, checkVisibility, client rects, text
// range boxes) as fixed per-node facts, so this proves interpreter wiring only:
// body equality, document/Element roots, chain and nth order, open shadow
// traversal and the existing matcher budget. It is not a browser visibility
// proof; Chromium remains the rendering oracle.
const assert = require('node:assert/strict');
const path = require('node:path');
const sourcePath = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const script = require('./native-observation-script.cjs')(sourcePath, 'MATCH_QUERY');

class Node {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this._children = [];
    this.parentNode = null;
    this.box = { width: 0, height: 0 };
  }
  get childNodes() { return this._children; }
  get firstChild() { return this._children[0] || null; }
  get nextSibling() {
    const parent = this.parentNode;
    if (!parent) return null;
    const index = parent._children.indexOf(this);
    return parent._children[index + 1] || null;
  }
  get ownerDocument() { return document; }
  get isConnected() { return true; }
  get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
  getRootNode() { let node = this; while (node.parentNode) node = node.parentNode; return node; }
  append(...children) { for (const child of children) { child.parentNode = this; this._children.push(child); } return this; }
  descendants() {
    const found = [];
    const pending = [...this._children].reverse();
    while (pending.length) {
      const node = pending.pop();
      found.push(node);
      for (let i = node._children.length - 1; i >= 0; i--) pending.push(node._children[i]);
    }
    return found;
  }
  querySelectorAll(css) {
    if (css === '*') return this.descendants().filter(node => node.nodeType === 1);
    if (css === ':scope') return [];
    if (/^[a-zA-Z][a-zA-Z0-9-]*$/.test(css)) {
      const tag = css.toLowerCase();
      return this.descendants().filter(node => node.nodeType === 1 && node.localName === tag);
    }
    const id = css.match(/^#([A-Za-z_][A-Za-z0-9_-]*)$/);
    if (id) return this.descendants().filter(node => node.nodeType === 1 && node.getAttribute('id') === id[1]);
    throw new SyntaxError(`fixture DOM does not implement ${css}`);
  }
}
class Element extends Node {
  constructor(tag = 'div', id = '') {
    super(1);
    this.localName = tag;
    this.nodeName = tag.toUpperCase();
    this.attributes = new Map();
    this.shadowRoot = null;
    this.style = { display: 'block', visibility: 'visible', contentVisibility: 'visible' };
    this.rect = { width: 10, height: 10 };
    this.visibleByBrowser = true;
    this.id = id;
  }
  get id() { return this.attributes.get('id') ?? ''; }
  set id(value) { this.attributes.set('id', String(value)); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  get hasAttribute() { return name => this.attributes.has(name); }
  matches() { return false; }
  getBoundingClientRect() { return this.rect; }
  // `checkVisibility()` with no arguments is what Playwright 1.64.1 calls;
  // the double fails if the interpreter passes flags Playwright never uses.
  checkVisibility(...args) {
    assert.equal(args.length, 0, 'Playwright calls checkVisibility() with no flags');
    return this.visibleByBrowser;
  }
  attachShadow(mode) { const root = new Node(11); root.host = this; if (mode === 'open') this.shadowRoot = root; return root; }
}
class Text extends Node { constructor(value, box) { super(3); this.nodeValue = value; this.box = box || { width: 10, height: 10 }; } }

global.Node = Node; global.Element = Element;
const document = global.document = new Node(9);
document.documentElement = new Element('html');
document.head = new Element('head');
document.append(document.head, document.documentElement);
document.defaultView = { getComputedStyle: node => node.style };
document.createRange = () => ({ selectNode(node) { this.node = node; }, getBoundingClientRect() { return this.node.box; } });
document.evaluate = () => { throw new Error('fixture DOM has no XPath'); };

const elements = [];
function add(parent, tag, id, facts = {}) {
  const element = new Element(tag, id);
  if ('display' in facts || 'visibility' in facts || 'contentVisibility' in facts) {
    element.style = { ...element.style, ...pick(facts, ['display', 'visibility', 'contentVisibility']) };
  }
  if ('rect' in facts) element.rect = facts.rect;
  if ('check' in facts) element.visibleByBrowser = facts.check;
  if ('attributes' in facts) for (const [name, value] of Object.entries(facts.attributes)) element.setAttribute(name, value);
  parent.append(element);
  if (facts.inventory !== false) elements.push(element);
  return element;
}
function pick(object, keys) { const out = {}; for (const key of keys) if (key in object) out[key] = object[key]; return out; }
function text(parent, value, box) { const node = new Text(value, box); parent.append(node); return node; }

const body = add(document.documentElement, 'body', 'body');
const main = add(body, 'main', 'main');
add(main, 'div', 'shown');
add(main, 'div', 'display-none', { display: 'none', check: false, rect: { width: 0, height: 0 } });
add(main, 'div', 'visibility-hidden', { visibility: 'hidden', check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'visibility-collapse', { visibility: 'collapse', check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'zero-area', { rect: { width: 0, height: 0 } });
add(main, 'div', 'content-skipped', { check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'opacity-zero', { check: true, rect: { width: 10, height: 10 } });
// display:contents has no box; Playwright looks at children and text ranges.
add(main, 'div', 'contents-empty', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
const contentsChild = add(main, 'div', 'contents-child', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
add(contentsChild, 'span', 'contents-visible-child', { rect: { width: 10, height: 10 } });
const contentsHiddenChild = add(main, 'div', 'contents-hidden-child', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
add(contentsHiddenChild, 'span', 'contents-none-child', { display: 'none', check: false, rect: { width: 0, height: 0 } });
const contentsHiddenText = add(main, 'div', 'contents-hidden-text', { display: 'contents', visibility: 'hidden', check: false, rect: { width: 0, height: 0 } });
text(contentsHiddenText, 'invisible text');
const contentsText = add(main, 'div', 'contents-text', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
text(contentsText, 'painted text', { width: 12, height: 10 });
const contentsZeroText = add(main, 'div', 'contents-zero-text', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
text(contentsZeroText, 'clipped text', { width: 0, height: 0 });
// A contents element whose element child overrides a hidden visibility still
// paints, so Playwright reports the parent visible (the child's own style wins).
const contentsOverride = add(main, 'div', 'contents-override', { display: 'contents', visibility: 'hidden', check: false, rect: { width: 0, height: 0 } });
add(contentsOverride, 'span', 'contents-override-child', { visibility: 'visible', rect: { width: 10, height: 10 } });
const openHost = add(main, 'div', 'open-host');
const openRoot = openHost.attachShadow('open');
add(openRoot, 'div', 'open-inner');
add(openRoot, 'div', 'open-shown');
// A display:contents host only inspects light children, never its shadow root.
const contentsHost = add(main, 'div', 'contents-host', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
const contentsShadow = contentsHost.attachShadow('open');
add(contentsShadow, 'span', 'contents-shadow-child');
const closedHost = add(main, 'div', 'closed-host');
const closedRoot = closedHost.attachShadow('closed');
add(closedRoot, 'div', 'closed-inner');
assert.equal(closedHost.shadowRoot, null, 'closed roots are not exposed');
// Ordered rows: visible, hidden, visible, visible. nth runs before a following
// visible step, and after it when the filter comes first.
const rows = add(main, 'ul', 'rows');
add(rows, 'li', 'row-1', { display: 'none', check: false, rect: { width: 0, height: 0 } });
add(rows, 'li', 'row-2');
add(rows, 'li', 'row-3', { visibility: 'hidden', check: true });
add(rows, 'li', 'row-4');

const matchQuery = eval(`(${script})`);
function run(expr) {
  const data = elements.map(() => ({ states: { secure: false, hidden: false } }));
  const labels = elements.map(() => []);
  const names = elements.map(() => null);
  const protectedAncestors = elements.map(() => false);
  const result = matchQuery(expr, data, labels, names, '.secure', protectedAncestors, ...elements);
  assert.equal(result.error, undefined, JSON.stringify(result));
  return result.indices.map(index => elements[index].id || elements[index].localName);
}
const ids = selector => run({ kind: 'selector', nativeParts: selector });
const engine = (name, body) => ({ engine: name, body });

let checks = 0;
function expect(name, actual, expected) {
  assert.deepEqual(actual, expected, `${name}: ${JSON.stringify(actual)}`);
  checks++;
}
// A single-root chain keeps each visibility fact independent of search order.
function one(id, body) { return ids([engine('css', '#' + id), engine('visible', body)]); }

// Playwright compares the authored body to the exact string "true"; every
// other body, including the empty one and case variants, asks for invisible
// roots. A document root is not an Element, so it never survives the filter.
expect('visible=true at document root', ids([engine('visible', 'true')]), []);
expect('visible=false at document root', ids([engine('visible', 'false')]), []);
expect('visible= at document root', ids([engine('visible', '')]), []);
expect('true keeps visible root', one('shown', 'true'), ['shown']);
expect('true drops invisible root', one('display-none', 'true'), []);
expect('false keeps invisible root', one('display-none', 'false'), ['display-none']);
expect('false drops visible root', one('shown', 'false'), []);
expect('empty body means false', one('display-none', ''), ['display-none']);
expect('empty body drops visible root', one('shown', ''), []);
expect('TRUE is not true', one('display-none', 'TRUE'), ['display-none']);
expect('leading space is not true', one('display-none', ' true'), ['display-none']);
expect('quoted true is not true', one('display-none', '"true"'), ['display-none']);

// Pinned visibility facts, supplied by the double as fixed browser answers.
expect('display none', one('display-none', 'false'), ['display-none']);
expect('visibility hidden', one('visibility-hidden', 'false'), ['visibility-hidden']);
expect('visibility collapse', one('visibility-collapse', 'false'), ['visibility-collapse']);
expect('zero area', one('zero-area', 'false'), ['zero-area']);
expect('opacity zero is still visible', one('opacity-zero', 'true'), ['opacity-zero']);
expect('contents empty', one('contents-empty', 'false'), ['contents-empty']);
expect('contents with visible element child', one('contents-child', 'true'), ['contents-child']);
expect('contents with display:none child', one('contents-hidden-child', 'false'), ['contents-hidden-child']);
// display:contents ignores its own visibility and inspects children/text only.
expect('contents hidden text still paints', one('contents-hidden-text', 'true'), ['contents-hidden-text']);
expect('contents painted text', one('contents-text', 'true'), ['contents-text']);
expect('contents zero text', one('contents-zero-text', 'false'), ['contents-zero-text']);
expect('contents child overrides visibility', one('contents-override', 'true'), ['contents-override']);

// `visible` filters the current roots; it never widens the chain.
expect('visible then css keeps visible descendants', ids([engine('css', '#contents-child'), engine('visible', 'true'), engine('css', 'span')]), ['contents-visible-child']);
expect('invisible root excludes descendants', ids([engine('css', '#contents-hidden-child'), engine('visible', 'true'), engine('css', 'span')]), []);
expect('two visible steps intersect true/false', ids([engine('css', '#shown'), engine('visible', 'true'), engine('visible', 'false')]), []);
expect('visible twice true', ids([engine('css', '#shown'), engine('visible', 'true'), engine('visible', 'true')]), ['shown']);

// Positions keep Playwright's order: nth selects before the following filter.
expect('nth selects a hidden root then visible drops it', ids([engine('css', '#rows'), engine('css', 'li'), engine('nth', '0'), engine('visible', 'true')]), []);
expect('nth selects a hidden root then false keeps it', ids([engine('css', '#rows'), engine('css', 'li'), engine('nth', '0'), engine('visible', 'false')]), ['row-1']);
expect('visible filters before nth', ids([engine('css', '#rows'), engine('css', 'li'), engine('visible', 'true'), engine('nth', '0')]), ['row-2']);
expect('visible filters before negative nth', ids([engine('css', '#rows'), engine('css', 'li'), engine('visible', 'true'), engine('nth', '-1')]), ['row-4']);
expect('visible false before nth', ids([engine('css', '#rows'), engine('css', 'li'), engine('visible', 'false'), engine('nth', '1')]), ['row-3']);

// Existing open-shadow traversal stays: visible filters reachable roots only.
expect('visible then open shadow css', ids([engine('css', '#open-inner'), engine('visible', 'true')]), ['open-inner']);
expect('visible then css inside open shadow', ids([engine('css', '*'), engine('visible', 'true'), engine('css', '#open-shown')]), ['open-shown']);
expect('visible never enters closed root', ids([engine('css', '*'), engine('visible', 'true'), engine('css', '#closed-inner')]), []);
expect('contents host ignores shadow children', ids([engine('css', '#contents-host'), engine('visible', 'true'), engine('css', 'span')]), []);

// A visible step applied to an Element root filters that root itself: an
// `has` chain is evaluated with the candidate element as its root. A document
// root never yields an element, so the same first step alone is empty above.
function hasVisible(source, body, rest = []) {
  return run({
    kind: 'filter',
    source: { kind: 'selector', nativeParts: source },
    has: { kind: 'selector', nativeParts: [engine('visible', body), ...rest] },
  });
}
expect('element root stays for visible step', hasVisible([engine('css', '#contents-child')], 'true', [engine('css', 'span')]), ['contents-child']);
expect('element root dropped for visible step', hasVisible([engine('css', '#contents-hidden-child')], 'true', [engine('css', 'span')]), []);

// Repeated visibility work stays inside the existing matcher budget.
const limited = elements.map(() => ({ states: { secure: false, hidden: false } }));
const budget = matchQuery(
  { kind: 'selector', nativeParts: [engine('css', '*'), engine('visible', 'true')] },
  limited, elements.map(() => []), elements.map(() => null), '.secure', elements.map(() => false), ...elements,
);
assert.equal(budget.error, undefined);
checks++;

console.log(`PASS: ${checks} visible chain interpreter checks against an explicit DOM double. Not a browser/E2E proof.`);
