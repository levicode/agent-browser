// Browser-free producer tests execute production METADATA, MATCH_QUERY,
// SECURITY_INVENTORY and FRESH_FIELDS. Real RAF/CDP acceptance remains separate.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const native = path.join(__dirname, '../../src/native');
const sourceFile = process.argv[2] || path.join(native, 'client_observation.rs');
const source = fs.readFileSync(sourceFile, 'utf8');
const freshSource = fs.readFileSync(process.argv[3] || path.join(native, 'client_observation/fresh_query.rs'), 'utf8');
function extract(text, name) {
  const direct = text.match(new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`));
  if (direct) return eval(`(${direct[1]})`);
  const start = text.indexOf(`const ${name}: &str = concat!(`); assert.notEqual(start, -1, name);
  const section = text.slice(start, text.indexOf('\n);', start));
  const parts = [...section.matchAll(/r#"([\s\S]*?)"#|include_str!\("([^"]+)"\)/g)].map(part => part[1] ?? fs.readFileSync(path.join(path.dirname(sourceFile), part[2]), 'utf8'));
  assert.ok(parts.length, name); return eval(`(${parts.join('')})`);
}
const read = extract(source, 'METADATA'), match = extract(source, 'MATCH_QUERY'), security = extract(source, 'SECURITY_INVENTORY');
const fresh = extract(freshSource, 'FRESH_FIELDS');
let document;
class Node {
  constructor(type) { this.nodeType = type; this.childNodes = []; this.parentNode = null; this.connected = true; }
  get isConnected() { return this.connected && (!this.parentNode || this.parentNode.isConnected); }
  get ownerDocument() { return this === document ? null : document; }
  get parentElement() { return this.parentNode instanceof Element ? this.parentNode : null; }
  getRootNode() { let node = this; while (node.parentNode) node = node.parentNode; return node; }
  append(...nodes) { for (const node of nodes) { node.parentNode = this; this.childNodes.push(node); } return this; }
  replaceWith(next) { const p = this.parentNode; assert.ok(p); p.childNodes[p.childNodes.indexOf(this)] = next; next.parentNode = p; this.parentNode = null; this.connected = false; }
  remove() { const p = this.parentNode; p.childNodes.splice(p.childNodes.indexOf(this), 1); this.parentNode = null; this.connected = false; }
  contains(other) { for (let node = other; node; node = node.parentNode) if (node === this) return true; return false; }
  get textContent() { return this.nodeType === 3 ? this.nodeValue : this.childNodes.map(n => n.textContent).join(''); }
  get children() { return this.childNodes.filter(n => n.nodeType === 1); }
  querySelectorAll(selector) { const result = [], pending = [...this.childNodes].reverse(); while (pending.length) { const n = pending.pop(); if (n.nodeType === 1 && n.matches(selector)) result.push(n); pending.push(...n.childNodes.slice().reverse()); } return result; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
class Element extends Node {
  constructor(tag = 'div', attrs = {}) { super(1); this.localName = tag; this.nodeName = tag.toUpperCase(); this.attrs = attrs; this.shadowRoot = null; this.hidden = false; }
  get attributes() { return Object.entries(this.attrs).map(([name, value]) => ({ name, value })); }
  getAttribute(name) { return this.attrs[name] ?? null; }
  hasAttribute(name) { return Object.hasOwn(this.attrs, name); }
  get id() { return this.getAttribute('id') || ''; }
  get innerText() { return this.textContent; }
  get previousElementSibling() { const a = this.parentElement?.children || []; return a[a.indexOf(this) - 1] || null; }
  get nextElementSibling() { const a = this.parentElement?.children || []; return a[a.indexOf(this) + 1] || null; }
  matches(selector) {
    if (selector === '*') return true;
    if (selector === ':disabled') return this.hasAttribute('disabled');
    if (selector.startsWith('input[type="password" i]')) return this instanceof Input && this.type === 'password';
    if (selector.startsWith('input:not(')) return ['textarea', 'select'].includes(this.localName) || this instanceof Input && !['checkbox', 'radio'].includes(this.type);
    return selector.split(',').some(s => s === this.localName);
  }
  closest(selector) { for (let p = this; p; p = p.parentElement) if (p.matches(selector)) return p; return null; }
  getClientRects() { return this.hidden ? [] : [{}]; }
  getBoundingClientRect() { return { x: 1, y: 1, width: this.hidden ? 0 : 20, height: this.hidden ? 0 : 10 }; }
  checkVisibility() { return !this.hidden; }
}
class Input extends Element { constructor(attrs = {}, value = '') { super('input', attrs); this.value = value; this.selectionStart = 0; this.selectionEnd = 0; }
  get type() { return this.getAttribute('type') || 'text'; }
  get labels() { const result = []; for (let p = this.parentElement; p; p = p.parentElement) if (p.localName === 'label') result.push(p); return result; }
}
class TextArea extends Input { constructor(attrs, value) { super(attrs, value); this.localName = 'textarea'; this.nodeName = 'TEXTAREA'; } }
class Document extends Node {
  constructor() { super(9); }
  get activeElement() { return this.active || null; }
  getElementById(id) { return this.querySelectorAll('*').find(n => n.id === id) || null; }
}
class ShadowRoot extends Node {
  constructor(host, mode) { super(11); this.owner = host; this.mode = mode; if (mode === 'open') host.shadowRoot = this; }
  get host() { return this.owner; }
  get isConnected() { return this.host.isConnected; }
  get activeElement() { return this.active || null; }
  getElementById(id) { return this.querySelectorAll('*').find(n => n.id === id) || null; }
}
class Text extends Node { constructor(value) { super(3); this.nodeValue = value; } }
Object.assign(global, { Node, Element, HTMLElement: Element, HTMLInputElement: Input, HTMLTextAreaElement: TextArea, HTMLSelectElement: class extends Element {}, HTMLOptionElement: class extends Element {}, HTMLButtonElement: class extends Element {}, SVGSVGElement: class extends Element {}, SVGTitleElement: class extends Element {}, Document, ShadowRoot, CSS: { escape: value => value } });
function reset() {
  document = global.document = new Document();
  document.documentElement = new Element('html'); document.append(document.documentElement);
  document.head = new Element('head'); document.body = new Element('body'); document.documentElement.append(document.head, document.body);
  document.defaultView = { getComputedStyle: node => ({ display: node.localName === 'span' ? 'inline' : 'block', visibility: node.hidden ? 'hidden' : 'visible', content: 'none', contentVisibility: 'visible', getPropertyValue: () => 'auto' }) };
  return document;
}
const query = (kind, value, extra = {}) => ({ kind: 'query', query: { kind, value: { kind: 'string', value, exact: true }, ...extra } });
function field(label, id, value, parent = document.body) { const node = new Input({ 'data-testid': id }, value); parent.append(new Element('label').append(new Text(label), node)); return node; }
function sample(expression, fields = ['states'], roots = [document], domains = roots.map((_, i) => i)) {
  return fresh(expression, fields, 'data-testid', 'input[type="password" i]', roots.map(() => true), domains, read, match, security, ...roots);
}
function shown(expression, roots, domains) { const out = sample(expression, ['states'], roots, domains); assert.equal(out.error, undefined); assert.equal(out.requiresAx, undefined); assert.equal(out.values.length, 1); assert.equal(out.values[0].states.hidden, false); return out.values[0]; }

reset();
let nickname = field('Nickname', 'nickname', 'ada');
const city = field('City', 'city', 'paris');
const exprs = [query('testId', 'nickname'), query('label', 'Nickname'), query('displayValue', 'ada')];
// A deterministic protocol gap: retain the old native candidate, then replace
// it before reading metadata. Baseline refuses before the matcher can select City.
const old = nickname;
nickname = new Input({ 'data-testid': 'nickname' }, 'ada'); old.replaceWith(nickname);
const stale = read.call(old, 'data-testid', 'input[type="password" i]');
assert.equal(stale.__nativeStatus, 'stale-reference');
assert.deepEqual(match(query('label', 'City'), [], [], [], 'input[type="password" i]', [], city, old), { error: 'stale-reference' });
if (process.env.EXPECT_OLD_TO_PASS === '1') assert.equal(stale.states?.hidden, false, 'the old multi-call acquisition cannot return the live visible field');
for (let round = 0; round < 30; round++) {
  const previous = nickname; nickname = new Input({ 'data-testid': 'nickname' }, 'ada'); previous.replaceWith(nickname);
  for (const expression of exprs) shown(expression);
  shown(query('label', 'City')); shown(query('displayValue', 'paris'));
}
console.log('PASS: exact old acquisition is stale; 30 fresh replacement rounds and stable neighbor samples remain visible');

reset();
for (let i = 0; i < 250; i++) field(`Churn ${i}`, `churn-${i}`, `c${i}`);
field('City', 'city', 'paris');
for (let round = 0; round < 5; round++) {
  for (const input of document.querySelectorAll('*').filter(n => n instanceof Input && n.value !== 'paris')) input.replaceWith(new Input({ ...input.attrs }, input.value));
  shown(query('label', 'City')); shown(query('displayValue', 'paris'));
  assert.deepEqual(sample(query('label', 'Nickname')).values, []);
  assert.deepEqual(sample(query('displayValue', 'ada')).values, []);
}
console.log('PASS: 250 churning candidates never stale a stable match or block genuine absence');

reset(); nickname = field('Nickname', 'nickname', 'ada');
for (const expression of exprs) shown(expression);
nickname.remove(); for (const expression of exprs) assert.deepEqual(sample(expression).values, []);
const first = field('Shared', 'a', 'same'), second = field('Shared', 'b', 'same');
const shared = query('displayValue', 'same');
assert.equal(sample(shared).values.length, 2);
assert.equal(sample({ kind: 'index', source: shared, index: 'last' }, ['testId']).values[0].testId, 'b');
assert.equal(sample({ kind: 'union', left: query('testId', 'b'), right: query('testId', 'a') }, ['testId']).values[0].testId, 'a');
assert.equal(sample({ kind: 'filter', source: shared, hasText: { kind: 'string', value: 'absent', exact: false } }).values.length, 0);
second.hidden = true; assert.equal(sample({ kind: 'index', source: shared, index: 'last' }).values[0].states.hidden, true);
console.log('PASS: genuine removal, ambiguity, index/union order, filter, and real hidden state');

reset();
const host = new Element('section'); document.body.append(host);
const closed = new ShadowRoot(host, 'closed');
const inside = field('Closed city', 'inside', 'paris', closed);
shown(query('label', 'Closed city'), [document, closed]);
closed.active = inside; document.active = host;
assert.equal(shown(query('testId', 'inside'), [document, closed]).states.focused, true);
const password = new Input({ type: 'password', 'data-testid': 'secret', 'aria-label': 'Password' }); closed.append(password);
Object.defineProperty(password, 'value', { get() { throw Error('password value was acquired'); } });
const secure = shown(query('testId', 'secret'), [document, closed]); assert.equal(secure.states.secure, true); assert.equal(secure.value, null);
assert.deepEqual(sample(query('displayValue', 'secret'), ['states'], [document, closed]).values, []);
host.connected = false; assert.deepEqual(sample(query('testId', 'missing'), ['states'], [document, closed]), { error: 'stale-reference' });
console.log('PASS: closed-root query/focus/security, forbidden secret getter, and retired root fail-closed (not absence)');

reset();
const widget = field('Widget', 'widget', 'value'); widget.attrs.role = 'combobox';
assert.deepEqual(sample(query('testId', 'widget')), { requiresAx: true });
assert.equal(sample(query('testId', 'widget'), ['value']).values[0].value, 'value');
delete widget.attrs.role; widget.parentElement.attrs['aria-disabled'] = 'true';
assert.deepEqual(sample(query('testId', 'widget')), { requiresAx: true });
console.log('PASS: incomplete AX state proof declines the entire sample; metadata-only fields remain atomic');

reset();
const withoutId = new Input({}, 'paris'); document.body.append(new Element('label').append(new Text('No ID'), withoutId));
let counted = sample(query('label', 'No ID'), ['testId']);
assert.equal(counted.values.length, 1); assert.equal(counted.values[0].testId, null);
const noIdPassword = new Input({ type: 'password', 'aria-label': 'Password without ID' }); document.body.append(noIdPassword);
Object.defineProperty(noIdPassword, 'value', { get() { throw Error('count acquired secure value'); } });
counted = sample(query('label', 'Password without ID'), ['testId']);
assert.equal(counted.values.length, 1); assert.equal(counted.values[0].testId, null); assert.equal(counted.values[0].states.secure, true);
console.log('PASS: count projection retains rows without testId, including secure fields, without reading secrets');
const openHost = new Element('div'); document.body.append(openHost);
const newOpen = new ShadowRoot(openHost, 'open'); field('New root', 'new-root', 'x', newOpen);
assert.deepEqual(sample(query('testId', 'missing')), { error: 'stale-reference' });
shown(query('testId', 'new-root'), [document, newOpen], [0]);
console.log('PASS: a newly discovered open root invalidates policy before sampling instead of producing false absence');

reset();
const emptyIdPassword = new Input({ type: 'password', id: '' }); document.body.append(emptyIdPassword);
Object.defineProperty(emptyIdPassword, 'value', { get() { throw Error('empty-ID password read'); } });
field('Still visible', 'stable-empty-id', 'safe');
shown(query('label', 'Still visible'));
const sensitive = new Element('span', { id: 'sensitive' }); document.body.append(sensitive);
sensitive.append(new Input({ type: 'password' }));
const labelled = new Input({ 'data-testid': 'labelled', 'aria-labelledby': 'plain\u0085sensitive' }, 'public'); document.body.append(labelled);
assert.equal(sample(query('testId', 'labelled'), ['value']).values[0].value, null);
labelled.attrs['aria-labelledby'] = 'plain\ufeffsensitive';
assert.equal(sample(query('testId', 'labelled'), ['value']).values[0].value, 'public');
console.log('PASS: native apply_security White_Space semantics, empty-ID nonmatch, NEL protection and FEFF distinction');

reset();
const scope = new Element('section', { 'data-testid': 'scope' }); document.body.append(scope);
const leaf = field('Scoped city', 'scoped', 'paris', scope);
field('Scoped city', 'outside', 'paris');
const scoped = query('label', 'Scoped city'); scoped.scope = query('testId', 'scope');
assert.equal(sample(scoped, ['testId']).values[0].testId, 'scoped');
const has = { kind: 'filter', source: query('testId', 'scope'), has: query('label', 'Scoped city') };
assert.equal(sample(has, ['testId']).values[0].testId, 'scope');
assert.equal(sample({ kind: 'filter', source: query('testId', 'scope'), has: query('label', 'Absent') }, ['testId']).values.length, 0);
assert.equal(sample({ kind: 'query', query: query('displayValue', 'paris').query, scope: { kind: 'index', source: query('testId', 'scope'), index: 'first' } }, ['value']).values.length, 1);
console.log('PASS: scope and filter.has retain nonleaf query roots, absent descendants, and unrelated label associations');

reset();
// A root whose child list is already over the bound must fail before indexing
// the list or calling querySelectorAll in the shared security reader.
document.childNodes = new Proxy({ length: 100001 }, { get(target, name) { if (name === 'length') return target.length; throw Error('unbounded child list enumerated'); } });
document.querySelectorAll = () => { throw Error('unbounded NodeList allocated'); };
assert.deepEqual(sample(query('testId', 'anything')), { error: 'resource-limit' });
console.log('PASS: oversized domain refused before NodeList allocation or child-list enumeration');

reset();
for (const [i, glyph] of ['\ue000', '\uf8ff', '\u{f0000}', '\u{ffffd}', '\u{100000}', '\u{10fffd}'].entries()) {
  const id = `icon-${i}`; field(`${glyph} Email ${i}`, id, 'value');
  assert.equal(shown(query('label', `Email ${i}`)).testId, id);
}
const iconOnly = new Input({ 'aria-label': '\uE800', 'data-testid': 'icon-only' }); document.body.append(iconOnly);
assert.equal(shown(query('label', '')).testId, 'icon-only');
field('X\u0085Y', 'nel-label', 'value');
assert.equal(shown(query('label', 'X\u0085Y')).testId, 'nel-label');
assert.equal(sample(query('label', 'X Y')).values.length, 0);
field('X\ufffeY', 'non-pua-label', 'value');
assert.equal(sample(query('label', 'X Y')).values.length, 0);
console.log('PASS: public label normalization matches all three PUA ranges, glyph-only labels, ECMAScript whitespace and non-PUA boundaries');

for (const mode of ['open', 'closed']) {
  reset();
  const slotHost = new Element('div'); document.body.append(slotHost);
  const slotRoot = new ShadowRoot(slotHost, mode);
  const disabledSlotParent = new Element('div', { 'aria-disabled': 'true' }); slotRoot.append(disabledSlotParent);
  const slot = new Element('slot'); disabledSlotParent.append(slot);
  const slotted = field('Slotted', 'slotted', 'safe', slotHost);
  // Closed roots need not expose assignedSlot. The native host inventory
  // still proves that this light edge cannot certify an AX-complete state bag.
  if (mode === 'open') slotted.parentElement.assignedSlot = slot;
  assert.deepEqual(sample(query('testId', 'slotted'), ['states'], [document, slotRoot], mode === 'open' ? [0] : [0, 1]), { requiresAx: true });
  assert.equal(sample(query('testId', 'slotted'), ['value'], [document, slotRoot], mode === 'open' ? [0] : [0, 1]).values[0].value, 'safe');
}
reset();
const owned = field('Owned', 'owned', 'safe'); owned.attrs.id = 'owned';
document.body.append(new Element('div', { 'aria-owns': 'owned', 'aria-disabled': 'true' }));
assert.deepEqual(sample(query('testId', 'owned')), { requiresAx: true });
console.log('PASS: open/closed slot and aria-owned AX state ancestry decline complete state sampling without changing metadata-only values');

reset();
document.body.append(new Element('span', { id: 'shared-id' }).append(new Text('Public label')));
const crossRoot = new Input({ 'data-testid': 'cross-root-label', 'aria-labelledby': 'shared-id' }, 'public value'); document.body.append(crossRoot);
const crossHost = new Element('section'); document.body.append(crossHost);
const crossClosed = new ShadowRoot(crossHost, 'closed');
const protectedCaption = new Element('span', { id: 'shared-id' }); crossClosed.append(protectedCaption);
const crossPassword = new Input({ type: 'password' }); protectedCaption.append(crossPassword);
Object.defineProperty(crossPassword, 'value', { get() { throw Error('cross-root password acquired'); } });
// Existing apply_security uses a frame-global label_ids set, not IDREF root
// resolution. Keep that conservative policy instead of weakening it here.
assert.equal(sample(query('testId', 'cross-root-label'), ['value'], [document, crossClosed]).values[0].value, null);
crossPassword.remove();
assert.equal(sample(query('testId', 'cross-root-label'), ['value'], [document, crossClosed]).values[0].value, 'public value');
console.log('PASS: duplicate ID across closed roots preserves the existing global label_ids protection and does not protect unrelated nonsecure IDs');
