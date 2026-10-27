// Browser-free execution of production METADATA/MATCH_QUERY. Scripted DOM is
// not a browser/AX oracle; Rust tests separately cover projection/publication.
const assert = require('node:assert/strict');
const path = require('node:path');
const source = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const extract = name => eval(`(${require('./native-observation-script.cjs')(source, name)})`);
const read = extract('METADATA');
const match = extract('MATCH_QUERY');
let document;
class Node {
  get ownerDocument() { return document; }
  get isConnected() { return true; }
  getRootNode() { return document; }
  contains(node) { return node === this || this.childNodes?.some(child => child.contains(node)) || false; }
}
class Element extends Node {
  constructor(tag = 'div', children = [], attrs = {}) {
    super(); this.nodeType = 1; this.localName = tag; this.nodeName = tag.toUpperCase();
    this.childNodes = children; this.parentElement = null; this.parentNode = null;
    this.labels = []; this.id = ''; this.onclick = null; this.attributes = Object.entries(attrs).map(([name, value]) => ({ name, value }));
    for (const child of children) child.parentElement = child.parentNode = this;
  }
  getAttribute(name) { return this.attributes.find(attribute => attribute.name === name)?.value ?? null; }
  hasAttribute(name) { return this.getAttribute(name) !== null; }
  matches(selector) {
    if (selector === ':disabled') return false;
    if (selector === '.secure' || selector.startsWith('input[type="password" i],')) return this.hasAttribute('data-secure');
    return selector.split(',').includes(this.localName);
  }
  querySelector() { return null; }
  getClientRects() { return [{}]; }
  getBoundingClientRect() { return { x: 0, y: 0, width: 100, height: 30 }; }
  checkVisibility() { return true; }
}
class Text extends Node { constructor(value) { super(); this.nodeType = 3; this.nodeValue = this.textContent = value; } }
Object.assign(global, { Node, Element, HTMLElement: Element, HTMLInputElement: class extends Element { constructor() { super('input'); } }, HTMLButtonElement: class extends Element {}, HTMLSelectElement: class extends Element {}, HTMLTextAreaElement: class extends Element {}, HTMLOptionElement: class extends Element {}, SVGSVGElement: class extends Element {}, CSS: { escape: value => value } });
const style = (element, pseudo) => ({ display: ['span', 's', 'strong'].includes(element.localName) ? 'inline' : 'block', visibility: element.hidden ? 'hidden' : 'visible', content: pseudo && element.generated ? '"generated"' : 'none', contentVisibility: 'visible', getPropertyValue: () => 'auto' });
document = global.document = { documentElement: new Element(), activeElement: null, defaultView: { getComputedStyle: style }, getElementById: () => null };
const el = (tag, ...children) => new Element(tag, children.map(child => typeof child === 'string' ? new Text(child) : child));
const fact = (node, local = true) => read.call(node, 'data-testid', '.secure', true, false, true, false, local).completeContentNameFact;
const cases = [
  [el('li', el('span', 'report.pdf')), 'report.pdf'],
  [el('li', el('div', el('p', 'Wireless Headphones'), el('p', el('s', '$80.00'), ' ', el('strong', '$40.00'), ' ', el('span', '50% OFF'))), el('p', 'Order confirmed')), 'Wireless Headphones $80.00 $40.00 50% OFF Order confirmed'],
  [el('li', el('span', el('strong', 'Cabin fresh'), ' 7 Pine Way, Bend'), el('button', 'Delete')), 'Cabin fresh 7 Pine Way, Bend Delete'],
];
for (const [node, name] of cases) assert.deepEqual(fact(node), { source: 'listitem', name });
for (const role of ['listitem', 'status', 'alert']) {
  const node = new Element('div', [el('span', 'Message'), el('button', 'Dismiss')], { role });
  assert.deepEqual(fact(node), { source: role, name: 'Message Dismiss' });
}
console.log('PASS: unchanged frozen-case shapes and exactly three historical content roles');
// Visibility is not author-graph suppression: inert/aria-hidden receivers and
// their ignored descendants can still supply valid content facts. Rust must
// decline AX-omitted li facts and reach compaction, not reject the whole graph.
for (const [attribute, value] of [['inert', ''], ['aria-hidden', 'true']]) {
  for (const ancestor of [false, true]) {
    const row = el('li', el('span', 'Suppressed row'));
    const parent = el('ul', row);
    const suppressed = ancestor ? parent : row;
    suppressed.attributes.push({ name: attribute, value });
    const rowMetadata = read.call(row, 'data-testid', '.secure', true, false, true, false, true);
    const parentMetadata = read.call(parent, 'data-testid', '.secure', true, false, true, false, true);
    assert.deepEqual(rowMetadata.completeContentNameFact, { source: 'listitem', name: attribute === 'aria-hidden' && !ancestor ? '' : 'Suppressed row' });
    assert.equal(rowMetadata.states.hidden, false);
    assert.equal(rowMetadata.author.suppress, !ancestor);
    assert.equal(parentMetadata.author.suppress, ancestor);
  }
}
console.log('PASS: own and ancestor inert/aria-hidden facts reach the native AX-omission boundary');

for (const attr of ['aria-label', 'aria-labelledby']) {
  const node = el('li', 'Content'); node.attributes.push({ name: attr, value: 'Explicit' });
  assert.equal(fact(node), null);
  const descendant = el('span', 'Content'); descendant.attributes.push({ name: attr, value: 'Explicit' });
  assert.equal(fact(el('li', descendant)), null);
}
assert.deepEqual(fact(el('li')), { source: 'listitem', name: '' });
assert.equal(fact(el('li', 'Complete'), false), null);
assert.equal(fact(el('li', 'x'.repeat(513))), null);
assert.equal(fact(el('li', ...Array.from({ length: 513 }, () => 'x'))), null);
let deep = el('span', 'Content'); for (let i = 0; i < 65; i++) deep = el('span', deep);
assert.equal(fact(el('li', deep)), null);
const shadow = el('span', 'Content'); shadow.shadowRoot = {};
assert.equal(fact(el('li', shadow)), null);
const pseudo = el('span', 'Content'); pseudo.generated = true;
assert.equal(fact(el('li', pseudo)), null);
const secure = el('span', 'secret'); secure.attributes.push({ name: 'data-secure', value: '' });
assert.equal(fact(el('li', secure)), null);
const control = new global.HTMLInputElement(); control.type = 'text'; control.value = 'private value';
assert.equal(fact(el('li', control)), null);
const button = el('button', 'Visible'); button.value = 'Must not contribute';
assert.deepEqual(fact(el('li', button)), { source: 'listitem', name: 'Visible' });
console.log('PASS: explicit names, security, incomplete inventory, author roots, generated text and all proof bounds refuse fallback');
const str = value => ({ kind: 'string', value, exact: true });
function indices(role, name, node, projected) {
  const result = match({ kind: 'query', query: { kind: 'role', value: str(role), name: str(name) } }, [projected], [[]], [null], '.secure', [false], node);
  assert.equal(result.error, undefined); return result.indices;
}
for (const role of ['listitem', 'status', 'alert']) {
  const node = new Element('div', [], { role });
  // These are the private Rust query payloads, not the public name projection.
  const anonymous = { role, states: {}, attributes: {} };
  assert.deepEqual(indices(role, 'Content', node, anonymous), []);
  assert.deepEqual(indices(role, '', node, anonymous), [0]);
  assert.deepEqual(indices(role, 'Explicit', node, { ...anonymous, name: 'Explicit' }), [0]);
}
console.log('PASS: content does not widen real role-name selection; explicit names still match');
