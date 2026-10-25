// Browser-free fixtures execute the production realm matcher, not a copy.
// Original contract: Web locators.ts filter.hasText delegates to Playwright's
// elementText (pinned 1.64.1): raw light DOM/open-root text, not innerText.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs'), 'utf8');
const script = source.match(/const MATCH_QUERY: &str = r#"([\s\S]*?)"#;/)[1];
const matchQuery = eval(`(${script})`);
let document;
class Node {
  constructor(nodeType) { this.nodeType = nodeType; this.childNodes = []; this.parentNode = null; this.connected = true; }
  get ownerDocument() { return document; }
  get isConnected() { return this.connected; }
  get parentElement() { return this.parentNode?.nodeType === 1 ? this.parentNode : null; }
  append(...children) { for (const child of children) { child.parentNode = this; this.childNodes.push(child); } return this; }
  getRootNode() { let node = this; while (node.parentNode) node = node.parentNode; return node; }
  contains(target) { for (let node = target; node; node = node.parentNode) if (node === this) return true; return false; }
}
class Element extends Node {
  constructor(tag = 'div', id = '') { super(1); this.localName = tag; this.nodeName = tag.toUpperCase(); this.id = id; this.shadowRoot = null; this.secure = false; }
  matches(selector) {
    if (selector === '*') return true;
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('input:not(')) return this.localName === 'textarea' || this.localName === 'select' || this.localName === 'input' && !['checkbox', 'radio'].includes(this.type);
    if (selector.startsWith('input[type="password" i],')) return this.localName === 'input' && this.type === 'password' || this.secure;
    throw Error(`Unexpected fixture selector: ${selector}`);
  }
  attachShadow(mode) { const root = new Node(11); root.host = this; if (mode === 'open') this.shadowRoot = root; return root; }
}
class Input extends Element {
  constructor(type = 'text', id = '') { super('input', id); this.type = type; }
}
class Text extends Node { constructor(value) { super(3); this.nodeValue = value; } }
global.Node = Node; global.Element = Element; global.HTMLInputElement = Input;
document = global.document = new Node(9);
document.head = new Element('head'); document.append(document.head);
const text = value => new Text(value);
const str = (value, exact = false) => ({ kind: 'string', value, exact });
const regexp = (source, flags = '') => ({ kind: 'regexp', source, flags });
const selector = id => ({ kind: 'selector', selector: `#${id}` });
const filter = (source, hasText) => ({ kind: 'filter', source, hasText });
const index = (source, index) => ({ kind: 'index', source, index });
const displayValue = value => ({ kind: 'query', query: { kind: 'displayValue', value: str(value, true) } });
const semantic = (extra = {}) => ({ states: {}, attributes: {}, ...extra });
function run(expression, elements, data = elements.map(() => semantic()), protectedAncestors = elements.map(() => false)) {
  const labels = elements.map(() => []), names = elements.map(() => null);
  // The optional source argument allows proving the fixture fails at the old
  // implementation without changing the tested expressions or DOM.
  if (!script.includes('secureSelector, protectedAncestors')) return matchQuery(expression, data, labels, names, ...elements);
  return matchQuery(expression, data, labels, names, '.secure', protectedAncestors, ...elements);
}
function matched(expression, elements, data, protectedAncestors) {
  const result = run(expression, elements, data, protectedAncestors);
  assert.equal(result.error, undefined);
  assert.deepEqual(Object.keys(result).sort(), ['indices', 'redacted']);
  return result.indices;
}
function forbid(object, property, label) { Object.defineProperty(object, property, { configurable: true, get() { throw Error(`${label || property} was acquired`); } }); }

// The unchanged lifecycle dv1 assertions: positions use current display value,
// whereas hasText sees the textarea's initial child text and no input values.
const first = new Input('text', 'first'), other = new Input('text', 'other'), second = new Input('text', 'second');
const third = new Element('textarea', 'third').append(text('shared'));
const controls = [first, other, second, third];
for (const node of controls) { document.append(node); forbid(node, 'value', 'editable current value'); forbid(node, 'innerText', 'rendered display text'); }
const data = ['First', 'Other', 'Second', 'Third'].map((name, i) => semantic({ name, value: i === 1 ? 'different' : 'shared', text: '' }));
const shared = displayValue('shared');
assert.deepEqual(matched(shared, controls, data), [0, 2, 3]);
assert.deepEqual(matched(index(shared, 'first'), controls, data), [0]);
assert.deepEqual(matched(index(shared, 1), controls, data), [2]);
assert.deepEqual(matched(index(shared, 'last'), controls, data), [3]);
assert.deepEqual(matched(index(shared, 3), controls, data), []);
assert.deepEqual(matched(index(index(shared, 'last'), 'first'), controls, data), [3]);
assert.deepEqual(matched(filter(shared, str('shared')), controls, data), [3]);
assert.deepEqual(matched(filter(shared, str('nowhere')), controls, data), []);
assert.deepEqual(matched(filter(index(shared, 'last'), str('shared')), controls, data), [3]);
assert.deepEqual(matched(filter(index(shared, 'first'), str('shared')), controls, data), []);
assert.deepEqual(matched({ kind: 'filter', source: index(shared, 'last'), has: { kind: 'query', query: { kind: 'role', value: str('textbox') } } }, controls, data), []);
data[3].value = 'edited';
assert.deepEqual(matched(shared, controls, data), [0, 2]);
assert.deepEqual(matched(filter(displayValue('edited'), str('shared')), controls, data), [3]);
assert.deepEqual(matched(filter(displayValue('edited'), str('edited')), controls, data), []);
assert.equal(data[3].text, '');
assert.equal(JSON.stringify(run(filter(displayValue('edited'), str('shared')), controls, data)).includes('shared'), false);
console.log('PASS: original displayValue positions/filters, initial textarea text, no editable values or public text changes');

// Matcher normalization follows hasText, not SemanticNode.text: string exact
// is deliberately ignored by the original locator's Playwright filter option.
const raw = new Element('div', 'raw').append(text('  A\u200b\u00ad\t b\u200c\u200d\nC  '));
for (const pattern of [str('a B\u200c\u200d c', true), regexp('^  A\\u200b\\u00ad\\t b\\u200c\\u200d\\nC  $', 'u'), regexp('^C', 'm'), regexp('a.*c', 'is')]) {
  assert.deepEqual(matched(filter(selector('raw'), pattern), [raw]), [0]);
}
assert.deepEqual(matched(filter(selector('raw'), str('a b c')), [raw]), []);
assert.deepEqual(matched(filter(selector('raw'), regexp('A b')), [raw]), []);
const twins = [new Element('div', 'one').append(text('same')), new Element('div', 'two').append(text('same'))];
for (const flags of ['g', 'y', 'gy', 'iu']) assert.deepEqual(matched(filter({ kind: 'selector', selector: '*' }, regexp('same', flags)), twins), [0, 1]);
assert.deepEqual(run(filter(selector('raw'), regexp('[', 'u')), [raw]), { error: 'invalid-arguments' });
console.log('PASS: raw regexp flags, per-element regex state, exact-ignored substring and original whitespace normalization');

// Text order is light children first, then open shadow text. Closed author
// roots remain native candidates, but do not contribute through their host.
const host = new Element('section', 'host').append(text('Light '));
const open = host.attachShadow('open'); open.append(new Element('span').append(text('Open')));
assert.deepEqual(matched(filter(selector('host'), regexp('^Light Open$')), [host]), [0]);
const closedHost = new Element('section', 'closed-host').append(text('Outside'));
const closed = closedHost.attachShadow('closed');
const inside = new Element('span', 'inside').append(text('Closed token')); closed.append(inside);
assert.deepEqual(matched(filter(selector('closed-host'), str('Closed token')), [closedHost, inside]), []);
assert.deepEqual(matched(filter(selector('inside'), str('Closed token')), [closedHost, inside]), [1]);
const hidden = new Element('span'); hidden.hidden = true; hidden.append(text('Hidden author text'));
const wrapper = new Element('div', 'wrapper').append(hidden);
forbid(wrapper, 'innerText'); forbid(wrapper, 'textContent');
assert.deepEqual(matched(filter(selector('wrapper'), str('Hidden author text')), [wrapper, hidden]), [0]);
console.log('PASS: light/open root ordering, closed-root boundary, hidden DOM text independent from rendered metadata');

for (const tag of ['script', 'style', 'noscript']) {
  const skipped = new Element(tag).append(text('forbidden token'));
  forbid(skipped.childNodes[0], 'nodeValue', 'excluded tag text');
  const parent = new Element('div', 'parent').append(text('safe'), skipped);
  assert.deepEqual(matched(filter(selector('parent'), str('safe')), [parent, skipped]), [0]);
}
const headChild = new Element('title', 'head-child').append(text('head token')); document.head.append(headChild);
forbid(headChild.childNodes[0], 'nodeValue', 'head text');
assert.deepEqual(matched(filter(selector('head-child'), str('head token')), [headChild]), []);
const template = new Element('template', 'template'); template.content = new Node(11).append(text('inert template contents'));
assert.deepEqual(matched(filter(selector('template'), str('inert template contents')), [template]), []);
const commented = new Element('div', 'commented').append(text('A'), new Node(8), text('B'));
forbid(commented.childNodes[1], 'nodeValue', 'comment text');
assert.deepEqual(matched(filter(selector('commented'), regexp('^AB$')), [commented]), [0]);
// Playwright's skipped tag names are HTML nodeName tokens, not localName:
// an SVG style node has lowercase nodeName and is not an HTML STYLE node.
const svgStyle = new Element('style', 'svg-style'); svgStyle.nodeName = 'style'; svgStyle.append(text('SVG authored text'));
assert.deepEqual(matched(filter(selector('svg-style'), str('SVG authored text')), [svgStyle]), [0]);
const blocks = new Element('div', 'blocks').append(text('A'), new Element('div').append(text('B')), text('C'));
assert.deepEqual(matched(filter(selector('blocks'), regexp('^ABC$')), [blocks]), [0]);
console.log('PASS: HTML script/style/noscript/head exclusions, SVG distinction, comments/templates and unrendered block boundaries');

for (const type of ['submit', 'button', 'reset']) {
  const button = new Input(type, 'button'); button.value = `Public ${type}`;
  assert.deepEqual(matched(filter(selector('button'), str(`PUBLIC ${type}`)), [button]), [0]);
  assert.deepEqual(matched(filter(selector('button'), regexp(`^Public ${type}$`)), [button]), [0]);
  button.secure = true; forbid(button, 'value', 'secure button value');
  assert.deepEqual(matched(filter(selector('button'), regexp('.*')), [button]), []);
}
const editableButton = new Input('button', 'editable-button'); editableButton.isContentEditable = true; forbid(editableButton, 'value');
assert.deepEqual(matched(filter(selector('editable-button'), regexp('.*')), [editableButton]), []);
console.log('PASS: pinned public submit/button/reset labels only, security and editable ambiguity fail closed');

// Safety refusal is not empty text: even empty and negative-lookahead patterns
// must not produce positive matches for protected nodes or ancestors.
const secret = new Element('textarea', 'secret').append(text('never acquire this')); secret.secure = true;
forbid(secret.childNodes[0], 'nodeValue', 'secure textarea initial text'); forbid(secret, 'value');
const secureParent = new Element('div', 'secure-parent').append(text('public sibling'), secret);
for (const pattern of [str(''), regexp('.*'), regexp('^(?!never)')]) {
  assert.deepEqual(matched(filter(selector('secret'), pattern), [secret]), []);
  assert.deepEqual(matched(filter(selector('secure-parent'), pattern), [secureParent, secret]), []);
}
secret.secure = false;
assert.deepEqual(matched(filter(selector('secret'), regexp('.*')), [secret], [semantic({ states: { secure: true } })]), []);
const password = new Input('password', 'password'); forbid(password, 'value');
assert.deepEqual(matched(filter(selector('password'), regexp('.*')), [password]), []);
const secureHost = new Element('div', 'secure-host'); secureHost.secure = true;
const protectedClosed = secureHost.attachShadow('closed');
const protectedInside = new Element('span', 'protected-inside').append(text('hidden secret')); protectedClosed.append(protectedInside);
forbid(protectedInside.childNodes[0], 'nodeValue', 'secure composed ancestor text');
assert.deepEqual(matched(filter(selector('protected-inside'), regexp('.*')), [protectedInside]), []);
secureHost.secure = false;
assert.deepEqual(matched(filter(selector('protected-inside'), regexp('.*')), [secureHost, protectedInside], [semantic({ states: { secure: true } }), semantic()]), []);
const nativeAncestor = new Element('div', 'native-ancestor');
forbid(nativeAncestor, 'childNodes', 'native proven closed-root secure ancestor');
assert.deepEqual(matched(filter(selector('native-ancestor'), regexp('.*')), [nativeAncestor], [semantic()], [true]), []);
const plain = new Element('div', 'plain');
assert.deepEqual(matched(filter(selector('plain'), regexp('^$')), [plain]), [0]);
console.log('PASS: live/native secure nodes, descendants, closed-root ancestry and native ancestor proof never yield text or guessed matches');

// CSS/role queries do not acquire any matcher text or impose matcher budgets.
const lazy = new Element('button', 'lazy'); forbid(lazy, 'childNodes'); forbid(lazy, 'value');
assert.deepEqual(matched(selector('lazy'), [lazy]), [0]);
assert.deepEqual(matched({ kind: 'query', query: { kind: 'role', value: str('button'), name: str('Named') } }, [lazy], [semantic({ role: 'button', name: 'Named' })]), [0]);
const cached = new Element('div', 'cached').append(text('stable')); let acquisitions = 0;
Object.defineProperty(cached.childNodes[0], 'nodeValue', { get() { acquisitions++; return 'stable'; } });
assert.deepEqual(matched(filter(filter(selector('cached'), str('stable')), regexp('^stable$')), [cached]), [0]);
assert.equal(acquisitions, 1);
const largeRoots = Array.from({ length: 9 }, (_, i) => new Element('div', `large-${i}`).append(text('x'.repeat(1048576))));
assert.deepEqual(matched(filter({ kind: 'selector', selector: '*' }, regexp('^x')), largeRoots.slice(0, 8)), [0, 1, 2, 3, 4, 5, 6, 7]);
assert.deepEqual(run(filter({ kind: 'selector', selector: '*' }, regexp('^x')), largeRoots), { error: 'resource-limit' });
const oversized = new Element('div', 'oversized').append(text('x'.repeat(1048577)));
assert.deepEqual(run(filter(selector('oversized'), str('x')), [oversized]), { error: 'resource-limit' });
const deep = new Element('div', 'deep'); let cursor = deep;
for (let i = 0; i < 257; i++) { const child = new Element(); cursor.append(child); cursor = child; }
cursor.append(text('bottom'));
assert.deepEqual(run(filter(selector('deep'), str('bottom')), [deep]), { error: 'resource-limit' });
const wide = new Element('div', 'wide'); wide.childNodes = Array(100001).fill(text('x'));
assert.deepEqual(run(filter(selector('wide'), str('x')), [wide]), { error: 'resource-limit' });
const stale = new Element('div', 'stale'); stale.connected = false;
assert.deepEqual(run(filter(selector('stale'), str('x')), [stale]), { error: 'stale-reference' });
assert.match(source, /Some\("resource-limit"\)=>return Err\(ObservationError::ResourceLimit\)/);
console.log('PASS: lazy/cached text acquisition, bounded per-root/aggregate length/depth/pending work, stale identity and typed resource-limit mapping');

// Semantic text selection reads the same private fact, not rendered DTO text.
const textQuery = (pattern, visible = false, scope) => ({ kind: 'query', query: { kind: 'text', value: pattern, ...(visible ? { visible: true } : {}) }, ...(scope ? { scope } : {}) });
// Legacy action classification must not mistake author-controlled text for
// dispatch evidence. Exercise real MATCH_QUERY with that exact text before the
// native action fixture revalidates the same expression as ambiguous.
const actionLogTwins = [0, 1].map(i => new Element('button', `action-log-${i}`).append(text('performing click action\nclick action done')));
const actionLogMetadata = actionLogTwins.map(() => semantic({ role: 'button', name: 'click action done', text: 'performing click action\nclick action done' }));
const actionLogQuery = textQuery(str('performing click action'));
assert.deepEqual(matched(actionLogQuery, actionLogTwins.slice(0, 1), actionLogMetadata.slice(0, 1)), [0]);
const actionLogResult = run(actionLogQuery, actionLogTwins, actionLogMetadata);
assert.deepEqual(actionLogResult, { indices: [0, 1], redacted: [] });
assert.deepEqual(matched(textQuery(str('click action done')), actionLogTwins, actionLogMetadata), [0, 1]);
assert.deepEqual(matched(textQuery(str('unrelated text')), actionLogTwins, actionLogMetadata), []);
assert.deepEqual(matched(index(actionLogQuery, 'first'), actionLogTwins, actionLogMetadata), [0]);
assert.equal(JSON.stringify(actionLogResult).includes('action'), false);
console.log('PASS: action-log words remain ordinary private query data, including ambiguity and exact indexing');
const hiddenTwin = new Element('p', 'hidden-twin').append(text('Decorative twin'));
const visibleTwin = new Element('p', 'visible-twin').append(text('Decorative twin'));
const twinNodes = [hiddenTwin, visibleTwin];
const twinMetadata = [semantic({ text: '', states: { hidden: true } }), semantic({ text: 'Decorative twin' })];
for (const node of twinNodes) { forbid(node, 'innerText'); forbid(node, 'textContent'); }
const allTwins = textQuery(str('Decorative twin', true));
const visibleTwins = textQuery(str('Decorative twin', true), true);
assert.deepEqual(matched(allTwins, twinNodes, twinMetadata), [0, 1]);
assert.deepEqual(matched(index(allTwins, 'first'), twinNodes, twinMetadata), [0]);
for (const position of ['first', 'last', 0]) assert.deepEqual(matched(index(visibleTwins, position), twinNodes, twinMetadata), [1]);
assert.deepEqual(matched(index(visibleTwins, 1), twinNodes, twinMetadata), []);
assert.deepEqual(matched(filter(visibleTwins, str('twin')), twinNodes, twinMetadata), [1]);
assert.equal(twinMetadata[0].text, '');
assert.equal(JSON.stringify(run(allTwins, twinNodes, twinMetadata)).includes('Decorative'), false);
const scopedPanel = new Element('section', 'panel').append(hiddenTwin, visibleTwin);
assert.deepEqual(matched(textQuery(str('Decorative twin', true), true, selector('panel')), [scopedPanel, ...twinNodes], [semantic(), ...twinMetadata]), [2]);
const hasVisibleTwin = { kind: 'filter', source: selector('panel'), has: visibleTwins };
assert.deepEqual(matched(hasVisibleTwin, [scopedPanel, ...twinNodes], [semantic(), ...twinMetadata]), [0]);
// Retained expressions reevaluate current candidate order after insertion.
const insertedTwin = new Element('p', 'inserted-twin').append(text('Decorative twin'));
assert.deepEqual(matched(index(visibleTwins, 'first'), [insertedTwin, ...twinNodes], [semantic(), ...twinMetadata]), [0]);
for (const pattern of [str('A b\u200c\u200d C', true), regexp('^  A\\u200b\\u00ad\\t b\\u200c\\u200d\\nC  $', 'u')]) assert.deepEqual(matched(textQuery(pattern), [raw]), [0]);
assert.deepEqual(matched(textQuery(str('A b C', true)), [raw]), []);
// Immediate matching descendants suppress their parent even when hidden. A
// closed-root match never suppresses a matching light-domain host.
const visibleParent = new Element('div', 'visible-parent').append(new Element('span').append(text('Only text')));
assert.deepEqual(matched(textQuery(str('Only text', true), true), [visibleParent, visibleParent.childNodes[0]], [semantic(), semantic({ states: { hidden: true } })]), []);
const closedTextHost = new Element('div').append(text('Same text'));
const closedTextRoot = closedTextHost.attachShadow('closed');
const closedTextChild = new Element('span').append(text('Same text')); closedTextRoot.append(closedTextChild);
assert.deepEqual(matched(textQuery(str('Same text', true)), [closedTextHost, closedTextChild]), [0, 1]);
const openTextHost = new Element('div'); openTextHost.attachShadow('open').append(new Element('span').append(text('Open only')));
assert.deepEqual(matched(textQuery(str('Open only', true)), [openTextHost]), []);
for (const pattern of [str(''), regexp('.*'), regexp('^(?!never)')]) {
  assert.deepEqual(matched(textQuery(pattern), [password]), []);
  assert.deepEqual(matched(textQuery(pattern), [nativeAncestor], [semantic()], [true]), []);
}
console.log('PASS: private semantic text covers hidden twins, exact/regex, scope/filter/index/live reevaluation and open/closed/security boundaries');

// Original unit/locators cases 7/9: retain both hasText and has predicates,
// distinguishing a filter-before-index from a filter-after-index. This uses
// the production MATCH_QUERY above, not an adapter-side matcher.
{
  const candidates = ['wrong-child-role', 'wrong-text', 'matching', 'wrong-value'].map((id, i) => {
    const candidate = new Element('select', id).append(text(i === 1 ? 'without match' : 'x'));
    const child = new Element('option', `${id}-child`);
    candidate.append(child);
    return { candidate, child };
  });
  const elements = candidates.flatMap(({ candidate, child }) => [candidate, child]);
  const metadata = candidates.flatMap((_, i) => [
    semantic({ value: i === 3 ? 'different' : 'shared' }),
    semantic({ role: i === 0 ? 'button' : 'textbox' }),
  ]);
  const textbox = { kind: 'query', query: { kind: 'role', value: str('textbox', true) } };
  const both = source => ({ kind: 'filter', source, hasText: str('x'), has: textbox });
  assert.deepEqual(matched(index(both(displayValue('shared')), 0), elements, metadata), [4]);
  assert.deepEqual(matched(both(index(displayValue('shared'), 'first')), elements, metadata), []);
  assert.deepEqual(matched(both(index(displayValue('shared'), 'last')), elements, metadata), [4]);
  assert.deepEqual(matched(both(displayValue('shared')), elements, metadata), [4]);
  assert.equal(metadata[4].value, 'shared');
  console.log('PASS: original displayValue hasText+has predicates remain before/after index without reordering or dropping either predicate');
}

// Original applyPostSteps case 14 requires an access trace, not just matching
// results: last may ask c only; first must ask a only even though c would match.
{
  const asked = [];
  const elements = ['a', 'b', 'c'].map(id => {
    const element = new Element('select', id).append(text(id === 'c' ? 'x' : 'no-match'));
    const children = element.childNodes;
    Object.defineProperty(element, 'childNodes', { configurable: true, get() { asked.push(`${id}:x`); return children; } });
    return element;
  });
  const metadata = elements.map(() => semantic({ value: 'shared' }));
  const last = matched(filter(index(displayValue('shared'), 'last'), str('x')), elements, metadata);
  assert.deepEqual(last.map(i => elements[i].id), ['c']);
  assert.deepEqual(asked, ['c:x']);
  asked.length = 0;
  assert.deepEqual(matched(filter(index(displayValue('shared'), 'first'), str('x')), elements, metadata), []);
  assert.deepEqual(asked, ['a:x']);
  console.log('PASS: original post-position filter evaluates only the previously selected match, including exact candidate access traces');
}

// The original candidate locator excludes checkbox/radio, not all inputs.
// Assert the actual selector passed by MATCH_QUERY as well as fixture results;
// the scripted DOM's selector shortcut alone is not evidence of that selector.
{
  const elements = [new Input('checkbox'), new Input('radio'), new Input('text'), new Element('textarea'), new Element('select')];
  const selectors = [];
  for (const element of elements) {
    element.matches = function(selector) { selectors.push(selector); return Element.prototype.matches.call(this, selector); };
  }
  const metadata = elements.map(() => semantic({ value: 'shared' }));
  assert.deepEqual(matched(displayValue('shared'), elements, metadata), [2, 3, 4]);
  assert.deepEqual(selectors, elements.map(() => 'input:not([type="checkbox" i]):not([type="radio" i]),textarea,select'));
  console.log('PASS: original displayValue candidate selector retains text inputs/textarea/select and exactly excludes checkbox/radio');
}
