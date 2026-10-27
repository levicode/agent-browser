// Browser-free fixture for the bounded attribute engines. It executes the
// production MATCH_QUERY realm (same extraction as the other native-observation
// fixtures) against an explicit DOM double. The double only accepts the CSS
// shapes this interpreter can emit: `[attr="<json string>"]`, `*`, `:scope`.
// CSS string escapes are decoded per the CSS Syntax spec so the test exercises
// Playwright's JSON.stringify-to-CSS bridge instead of assuming it.
const assert = require('node:assert/strict');
const path = require('node:path');
const sourcePath = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const script = require('./native-observation-script.cjs')(sourcePath, 'MATCH_QUERY');

function cssStringValue(text) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch !== '\\') { result += ch; continue; }
    i++;
    if (i >= text.length) break;
    const next = text[i];
    if (next === '\n' || next === '\f') continue;
    if (next === '\r') { if (text[i + 1] === '\n') i++; continue; }
    if (/[0-9a-fA-F]/.test(next)) {
      let hex = next;
      while (hex.length < 6 && i + 1 < text.length && /[0-9a-fA-F]/.test(text[i + 1])) hex += text[++i];
      if (i + 1 < text.length && /[ \t\n\r\f]/.test(text[i + 1])) i++;
      let code = parseInt(hex, 16);
      if (code === 0 || (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff) code = 0xfffd;
      result += String.fromCodePoint(code);
      continue;
    }
    result += next;
  }
  return result;
}

const ATTRIBUTE_CSS = /^\[([A-Za-z_][A-Za-z0-9_-]*)=("(?:[^"\\]|\\.)*")\]$/;

class Node {
  constructor(nodeType) { this.nodeType = nodeType; this._children = []; this.parentNode = null; }
  get childNodes() { return this._children; }
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
    const match = css.match(ATTRIBUTE_CSS);
    if (!match) throw new SyntaxError(`fixture DOM does not implement ${css}`);
    const name = match[1];
    const value = cssStringValue(match[2].slice(1, -1));
    return this.descendants().filter(node => node.nodeType === 1 && node.getAttribute(name) === value);
  }
}
class Element extends Node {
  constructor(tag = 'div', id = '') { super(1); this.localName = tag; this.nodeName = tag.toUpperCase(); this.attributes = new Map(); this.shadowRoot = null; this.id = id; }
  // The id property reflects to the attribute, as in a real DOM.
  get id() { return this.attributes.get('id') ?? ''; }
  set id(value) { this.attributes.set('id', String(value)); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  get hasAttribute() { return name => this.attributes.has(name); }
  matches() { return false; }
  attachShadow(mode) { const root = new Node(11); root.host = this; if (mode === 'open') this.shadowRoot = root; return root; }
}
class Text extends Node { constructor(value) { super(3); this.nodeValue = value; } }

global.Node = Node; global.Element = Element;
document = global.document = new Node(9);
document.documentElement = new Element('html');
document.head = new Element('head');
document.append(document.head, document.documentElement);
document.evaluate = () => { throw new Error('fixture DOM has no XPath'); };

const elements = [];
function add(parent, tag, id, attributes = {}) {
  const element = new Element(tag, id);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  parent.append(element);
  elements.push(element);
  return element;
}
const body = add(document.documentElement, 'body', 'body');
const main = add(body, 'main', 'main');
add(main, 'div', 'light-plain', { id: 'light-plain', 'data-testid': 'one', 'data-test-id': 'dtid', 'data-test': 'dt' });
add(main, 'div', 'light-empty', { 'data-testid': '', 'data-test-id': '', 'data-test': '' });
add(main, 'div', 'light-missing', {});
add(main, 'div', 'light-quote', { 'data-testid': 'a"b' });
add(main, 'div', 'light-backslash', { 'data-testid': 'a\\b' });
add(main, 'div', 'light-bracket', { 'data-testid': 'x[y' });
add(main, 'div', 'light-unicode', { 'data-testid': '日本' });
add(main, 'div', 'light-arrow', { 'data-testid': 'a >> b' });
add(main, 'div', 'light-case', { 'data-testid': 'TID' });
add(main, 'div', 'data-test-id-only', { 'data-test-id': 'only-id' });
add(main, 'div', 'data-test-only', { 'data-test': 'only-test' });
// Playwright stringifies the body into a CSS string, so a real newline body
// becomes `\n` and CSS decodes that to the single character `n`. `\f`
// likewise leaves the hex escape `fb` (which consumes the following `b` as a
// sixth hex digit), and `\u0000` leaves the literal text `u0000`. All three
// are the upstream bridge, not a native reinterpretation.
add(main, 'div', 'light-newline-decoy', { 'data-testid': 'anb' });
add(main, 'div', 'light-formfeed-decoy', { 'data-testid': 'a\u00fb' });
add(main, 'div', 'light-nul-decoy', { 'data-testid': 'au0000b' });
add(main, 'div', 'light-equals', { 'data-testid': 'a=b' });
// An element whose `id` attribute is empty, so `id=` has a positive target.
add(main, 'mark', '', {});
const openHost = add(main, 'div', 'open-host');
const openRoot = openHost.attachShadow('open');
const openInner = new Element('div', 'open-inner');
openInner.setAttribute('data-testid', 'inner-open');
openInner.setAttribute('data-test-id', 'inner-open');
openInner.setAttribute('data-test', 'inner-open');
openRoot.append(openInner); elements.push(openInner);
const openNestedHost = new Element('section', 'open-nested');
openRoot.append(openNestedHost); elements.push(openNestedHost);
const nestedRoot = openNestedHost.attachShadow('open');
const nestedInner = new Element('div', 'nested-inner');
nestedInner.setAttribute('data-testid', 'inner-nested');
nestedRoot.append(nestedInner); elements.push(nestedInner);
const closedHost = add(main, 'div', 'closed-host');
const closedRoot = closedHost.attachShadow('closed');
const closedInner = new Element('div', 'closed-inner');
closedInner.setAttribute('data-testid', 'inner-closed');
closedInner.setAttribute('data-test-id', 'inner-closed');
closedInner.setAttribute('data-test', 'inner-closed');
closedRoot.append(closedInner); elements.push(closedInner);
assert.equal(closedHost.shadowRoot, null, 'closed roots are not exposed');
assert.ok(!main.descendants().includes(closedInner), 'closed roots are unreachable from light traversal');

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

let checks = 0;
function expect(name, actual, expected, label) {
  assert.deepEqual(actual, expected, `${label || ''} ${name}: ${JSON.stringify(actual)}`);
  checks++;
}
function engine(name, body) { return { engine: name, body }; }
function chain(...parts) { return parts; }

// Exact attribute mapping: each engine reads only its own attribute.
expect('id', ids(chain(engine('id', 'light-plain'))), ['light-plain']);
expect('data-testid', ids(chain(engine('data-testid', 'one'))), ['light-plain']);
expect('data-test-id', ids(chain(engine('data-test-id', 'dtid'))), ['light-plain']);
expect('data-test', ids(chain(engine('data-test', 'dt'))), ['light-plain']);
expect('data-test-id-only', ids(chain(engine('data-test-id', 'only-id'))), ['data-test-id-only']);
expect('data-test-only', ids(chain(engine('data-test', 'only-test'))), ['data-test-only']);
expect('cross engine miss', ids(chain(engine('data-testid', 'dtid'))), []);
expect('cross engine miss 2', ids(chain(engine('data-test-id', 'dt'))), []);
expect('case sensitive', ids(chain(engine('data-testid', 'tid'))), []);
expect('case sensitive exact', ids(chain(engine('data-testid', 'TID'))), ['light-case']);

// Empty body matches an empty attribute; a quoted pair is a literal two-quote
// value, and an absent attribute never matches.
expect('empty body', ids(chain(engine('data-testid', ''))), ['light-empty']);
expect('quoted empty body', ids(chain(engine('data-testid', '""'))), []);
expect('single quoted empty body', ids(chain(engine('data-testid', "''"))), []);
expect('empty id', ids(chain(engine('id', ''))), ['mark']);
expect('missing not empty', ids(chain(engine('data-testid', 'missing'))), []);

// Quotes, backslashes, brackets, Unicode and literal arrows.
expect('raw quote body', ids(chain(engine('data-testid', 'a"b'))), ['light-quote']);
expect('quoted quote body', ids(chain(engine('data-testid', '"a\\"b"'))), []);
expect('single quote body', ids(chain(engine('data-testid', "a'b"))), []);
expect('raw backslash body', ids(chain(engine('data-testid', 'a\\b'))), ['light-backslash']);
expect('double backslash body', ids(chain(engine('data-testid', 'a\\\\b'))), []);
expect('quoted backslash body', ids(chain(engine('data-testid', '"a\\\\b"'))), []);
expect('bracket body', ids(chain(engine('data-testid', 'x[y'))), ['light-bracket']);
expect('quoted bracket body', ids(chain(engine('data-testid', '"x[y"'))), []);
expect('unicode body', ids(chain(engine('data-testid', '日本'))), ['light-unicode']);
expect('quoted unicode body', ids(chain(engine('data-testid', '"日本"'))), []);
expect('literal arrow body', ids(chain(engine('data-testid', '"a >> b"'))), []);
expect('arrow with escaped delimiters', ids(chain(engine('data-testid', 'a\\>\\>b'))), []);
// The Rust parser splits a raw `>>` before compilation, so this body cannot
// reach the interpreter. If it ever did, it must remain data and never be
// reparsed as a second selector chain.
expect('raw arrow body stays data', ids(chain(engine('data-testid', 'a >> b'))), ['light-arrow']);
// JSON.stringify turns a real newline into `\n`, and CSS then decodes that to
// the single character `n`; Playwright has the same documented bridge.
expect('newline body decodes through CSS', ids(chain(engine('data-testid', 'a\nb'))), ['light-newline-decoy']);
expect('decoded newline alias', ids(chain(engine('data-testid', 'anb'))), ['light-newline-decoy']);
expect('formfeed body decodes to a hex escape', ids(chain(engine('data-testid', 'a\fb'))), ['light-formfeed-decoy']);
expect('nul body decodes to literal u0000', ids(chain(engine('data-testid', 'a\u0000b'))), ['light-nul-decoy']);
expect('equals stays inside the value', ids(chain(engine('data-testid', 'a=b'))), ['light-equals']);

// Plain engines follow the existing open-shadow traversal; :light does not.
expect('plain pierces open', ids(chain(engine('data-testid', 'inner-open'))), ['open-inner']);
expect('plain pierces nested open', ids(chain(engine('data-testid', 'inner-nested'))), ['nested-inner']);
expect('plain id pierces open', ids(chain(engine('id', 'open-inner'))), ['open-inner']);
expect('light stays in light', ids(chain(engine('data-testid:light', 'inner-open'))), []);
expect('light id stays in light', ids(chain(engine('id:light', 'open-inner'))), []);
expect('light still sees light matches', ids(chain(engine('data-testid:light', 'one'))), ['light-plain']);
expect('light data-test-id stays in light', ids(chain(engine('data-test-id:light', 'inner-open'))), []);

// Neither variant can reach a closed root.
expect('closed root plain', ids(chain(engine('data-testid', 'inner-closed'))), []);
expect('closed root light', ids(chain(engine('data-testid:light', 'inner-closed'))), []);
expect('closed root id', ids(chain(engine('id', 'closed-inner'))), []);
expect('closed root id light', ids(chain(engine('id:light', 'closed-inner'))), []);

// The existing chain order, scoping and position rules keep working.
expect('chain scope', ids(chain(engine('css', 'main'), engine('data-testid', 'one'))), ['light-plain']);
expect('chain scope light', ids(chain(engine('css', 'main'), engine('data-testid:light', 'one'))), ['light-plain']);
expect('chain after shadow', ids(chain(engine('css', 'main'), engine('data-testid', 'inner-open'), engine('css', 'div'))), []);
expect('chain through shadow', ids(chain(engine('css', '#open-host'), engine('css', 'section'), engine('data-testid', 'inner-nested'))), ['nested-inner']);
expect('nth after attribute', ids(chain(engine('data-testid', 'one'), engine('nth', '0'))), ['light-plain']);
expect('nth misses', ids(chain(engine('data-testid', 'one'), engine('nth', '1'))), []);
expect('nth negative', ids(chain(engine('data-testid', 'one'), engine('nth', '-1'))), ['light-plain']);

// A body that is not a chain is a literal body, and unrelated engines still
// fail closed rather than being treated as CSS.
expect('attribute body is not css', ids(chain(engine('data-testid', 'div'))), []);
assert.throws(() => run({ kind: 'selector', nativeParts: [{ engine: 'unknown', body: 'x' }] }), undefined);
console.log(`PASS: ${checks} attribute selector interpreter checks against an explicit DOM double. Not a browser/E2E proof.`);
