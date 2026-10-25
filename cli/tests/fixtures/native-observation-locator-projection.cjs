// Browser-free execution of unchanged production METADATA and MATCH_QUERY.
// Only the scripted DOM and projected Rust metadata are fixtures. This is not
// a browser, native dispatch, frame inventory, or accessible-name oracle.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs'), 'utf8');
const extract = name => {
  const found = source.match(new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`));
  assert.ok(found, `${name} production script is present`);
  return eval(`(${found[1]})`);
};
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
  constructor(attrs = {}) {
    super();
    this.nodeType = 1; this.localName = 'div'; this.nodeName = 'DIV';
    this.childNodes = []; this.parentElement = null; this.parentNode = null;
    this.labels = []; this.id = ''; this.onclick = null;
    this.attributes = Object.entries(attrs).map(([name, value]) => ({ name, value }));
  }
  getAttribute(name) { return this.attributes.find(attribute => attribute.name === name)?.value ?? null; }
  hasAttribute(name) { return this.getAttribute(name) !== null; }
  matches(selector) {
    if (selector === ':disabled' || selector === '.secure' || selector.startsWith('input[type="password" i],')) return false;
    return selector.split(',').includes(this.localName);
  }
  querySelector() { return null; }
  getClientRects() { return [{}]; }
  getBoundingClientRect() { return { x: 0, y: 0, width: 10, height: 10 }; }
  checkVisibility() { return true; }
}
Object.assign(global, { Node, Element, HTMLElement: Element, HTMLInputElement: class extends Element {}, HTMLOptionElement: class extends Element {}, CSS: { escape: value => value } });
let interactivity = 'auto';
const style = { display: 'block', visibility: 'visible', content: 'none', contentVisibility: 'visible', getPropertyValue(name) { assert.equal(name, 'interactivity'); return interactivity; } };
document = global.document = { documentElement: new Element(), activeElement: null, defaultView: { getComputedStyle: () => style }, getElementById: () => null };
assert.equal(style.getPropertyValue('interactivity'), 'auto');
assert.throws(() => style.getPropertyValue('unexpected-css-property'), assert.AssertionError);
assert.equal(read.call(new Element(), 'data-testid', '.secure', true).author.suppress, false);
interactivity = 'inert';
assert.equal(read.call(new Element(), 'data-testid', '.secure', true).author.suppress, true);
interactivity = 'auto';
assert.equal(read.call(new Element(), 'data-testid', '.secure', true).author.suppress, false);
const str = (value, exact = true) => ({ kind: 'string', value, exact });
const query = (kind, value, extra = {}) => ({ kind: 'query', query: { kind, value: str(value), ...extra } });
function indices(expression, elements, facts) {
  const result = match(expression, facts, elements.map(() => []), elements.map(() => null), '.secure', elements.map(() => false), ...elements);
  assert.equal(result.error, undefined);
  assert.deepEqual(Object.keys(result).sort(), ['indices', 'redacted']);
  return result.indices;
}

// Original unit/locators case3: the configured attribute is a literal name.
function testIds(attribute, values, pattern) {
  const elements = values.map(value => new Element({ [attribute]: value, 'data-testid': 'wrong-default-attribute' }));
  const facts = elements.map(element => read.call(element, attribute, '.secure', true));
  assert.deepEqual(facts.map(fact => fact.testId), values);
  return indices({ kind: 'query', query: { kind: 'testId', value: pattern } }, elements, facts);
}
assert.deepEqual(testIds('data-qa', ['save "draft"', 'save draft', 'Save "draft"', 'save "draft" extra'], str('save "draft"')), [0]);
assert.deepEqual(testIds('data-qa', ['save', 'Save', 'save draft', 'autosave'], str('save', false)), [0]);
assert.deepEqual(testIds('data-test-id', ['row-1', 'ROW-42', 'row-x', 'prefix-row-1'], { kind: 'regexp', source: '^row-\\d+$', flags: 'i' }), [0, 1]);
assert.deepEqual(testIds('a,b', ['x', 'X', 'x extra'], str('x')), [0]);
console.log('PASS: original configured testId literals, quote/comma attributes, exact case-sensitive strings and flagged regexp');

// Original case4: selection uses level and all explicitly requested states.
// Rust's separately executed private_query_payload_preserves_false_states test
// proves that explicit false is retained before this production matcher.
{
  const elements = Array.from({ length: 8 }, () => new Element());
  const facts = [
    { role: 'heading', name: 'Dashboard', level: 1 },
    { role: 'heading', name: 'Dashboard', level: 2 },
    { role: 'heading', name: 'Dashboard extra', level: 1 },
    { role: 'heading', name: 'dashboard', level: 1 },
    { role: 'checkbox', states: { checked: true, disabled: false } },
    { role: 'checkbox', states: { checked: false, disabled: false } },
    { role: 'checkbox', states: { checked: true, disabled: true } },
    { role: 'checkbox', states: { checked: true } },
  ].map(fact => ({ states: {}, attributes: {}, ...fact }));
  assert.deepEqual(indices(query('role', 'heading', { name: str('Dashboard'), level: 1 }), elements, facts), [0]);
  assert.deepEqual(indices(query('role', 'checkbox', { states: { checked: true, disabled: false } }), elements, facts), [4]);
  console.log('PASS: original heading level/name and checked:true disabled:false remain exact matching predicates');
}

// Original case5 and the additional upstream union case. Native projection
// owns img -> image (separate Rust witness); the matcher consumes public roles.
{
  const elements = Array.from({ length: 6 }, () => new Element());
  const facts = [
    { role: 'image', name: 'Map' }, { role: 'image', name: 'Map extra' },
    { role: 'tablist' }, { role: 'textbox' }, { role: 'button' }, { role: 'textbox' },
  ].map(fact => ({ states: {}, attributes: {}, ...fact }));
  assert.deepEqual(indices(query('role', 'image', { name: str('Map') }), elements, facts), [0]);
  assert.deepEqual(indices(query('role', 'tablist'), elements, facts), [2]);
  const union = (left, right) => ({ kind: 'union', left, right });
  assert.deepEqual(indices(union(query('role', 'textbox'), query('role', 'button')), elements, facts), [3, 4, 5]);
  assert.deepEqual(indices(union(query('role', 'textbox'), query('role', 'textbox')), elements, facts), [3, 5]);
  console.log('PASS: original image/Map and tablist vocabulary, plus ordered deduplicated textbox/button union');
}
