// Run without a browser to check bounded metadata and shadow-root redaction.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../src/native/client_observation.rs'), 'utf8');
const script = source.match(/const METADATA: &str = r#"([\s\S]*?)"#;/)[1];
let document;
class Node {
  get isConnected() { return true; }
  get ownerDocument() { return document; }
}
class Element extends Node {
  constructor() {
    super(); Object.assign(this, { nodeType: 1, localName: 'div', attributes: [], labels: [], childNodes: [], parentElement: null, onclick: null, id: '' });
  }
  matches(selector) { return this.secure === true && selector.includes('.secure'); }
  querySelector() { return null; }
  getRootNode() { return document; }
  getAttribute() { return null; }
  hasAttribute() { return false; }
  getClientRects() { return [{}]; }
  getBoundingClientRect() { return { x: 0, y: 0, width: 10, height: 10 }; }
  checkVisibility() { return true; }
}
class InputControl extends Element { constructor(type, checked) { super(); this.localName='input'; this.type=type; this.checked=checked; this.value='on'; } }
class OptionControl extends Element { constructor(selected) { super(); this.localName='option'; this.selected=selected; this.value='Poland'; } }
global.HTMLInputElement=InputControl; global.HTMLOptionElement=OptionControl;
class ButtonControl extends Element { constructor() { super(); this.localName='button'; } }
class EmptySvg extends Element { constructor() { super(); this.localName='svg'; } }
global.HTMLButtonElement=ButtonControl; global.SVGSVGElement=EmptySvg;
class Text extends Node {
  constructor(value, host) { super(); this.nodeType = 3; this.nodeValue = value; this.textContent = value; this.parentElement = null; this.host = host; }
  getRootNode() { return { host: this.host }; }
}
global.Node = Node; global.Element = Element; global.HTMLElement = Element; global.CSS = { escape: value => value };
document = global.document = { documentElement: new Element(), activeElement: null,
  defaultView: { getComputedStyle: () => ({ visibility: 'visible', display: 'block' }) },
  getElementById: () => null, createRange: () => ({ selectNode() {}, getBoundingClientRect() { return { width: 10, height: 10 }; } }),
};
const read = eval(`(${script})`);
const host = new Element();
const ordinary = read.call(new Text('Hello   shadow', host), 'data-testid', '.secure', true);
assert.equal(ordinary.author.visible, true);
assert.equal(ordinary.author.text, 'Hello shadow');
const long = read.call(new Text('😀'.repeat(600), host), 'data-testid', '.secure', true);
assert.equal(Array.from(long.author.text).length, 513);
assert.equal(long.author.text.includes('\ud83d\ud83d'), false);
host.secure = true;
const protectedNode = read.call(new Text('never-transmit-this', host), 'data-testid', '.secure', true);
assert.equal(protectedNode.states.secure, true);
assert.equal(protectedNode.author.text, '');
assert.equal(protectedNode.text, null);
assert.equal(JSON.stringify(protectedNode).includes('never-transmit-this'), false);
console.log('PASS: shared author metadata bounds Unicode, reads direct shadow text, and redacts secure host content');

// Observation must not evaluate the preexisting full-text getter at all.
host.secure = false;
const large = new Text('x'.repeat(100000), host);
Object.defineProperty(large, 'textContent', { get() { throw Error('Full text materialized'); } });
const bounded = read.call(large, 'data-testid', '.secure', true);
assert.equal(bounded.text, null);
assert.equal(bounded.author.text.length, 513);
const ancestor = new Element();
Object.defineProperty(ancestor, 'innerText', { get() { throw Error('Ancestor text materialized'); } });
assert.equal(read.call(ancestor, 'data-testid', '.secure', true).text, null);
const full = new Text(' '.repeat(20000) + 'full direct read', host);
assert.equal(read.call(full, 'data-testid', '.secure').text, full.textContent);
assert.equal(read.call(full, 'data-testid', '.secure', true).__nativeStatus, 'resource-limit');
const elementRead = new Element(); elementRead.innerText = 'Full fixture text';
assert.equal(read.call(elementRead, 'data-testid', '.secure').text, 'Full fixture text');
console.log('PASS: bounded observation never materializes full Text/ancestor text; direct reads retain full text');

// Author tree suppression accepts ARIA boolean values case-insensitively;
// this does not rewrite raw layout visibility or direct-read text.
for (const value of ['true', 'TRUE', 'TrUe']) {
  const hidden = new Element(); hidden.innerText = 'Still readable by exact reference';
  hidden.getAttribute = name => name === 'aria-hidden' ? value : null;
  const facts = read.call(hidden, 'data-testid', '.secure', true);
  assert.equal(facts.author.suppress, true);
  assert.equal(facts.states.hidden, false);
  assert.equal(read.call(hidden, 'data-testid', '.secure').text, hidden.innerText);
}
const shown = new Element();
shown.getAttribute = name => name === 'aria-hidden' ? 'FALSE' : null;
assert.equal(read.call(shown, 'data-testid', '.secure', true).author.suppress, false);
console.log('PASS: aria-hidden suppression is case-insensitive without changing raw visibility or exact reads');

const editor = new Element(); editor.isContentEditable = true; editor.innerText = '  Keep spaces\n\nnext  '; editor.textContent = '  Keep spacesnext  ';
assert.equal(read.call(editor, 'data-testid', '.secure').value, editor.innerText);
assert.equal(read.call(editor, 'data-testid', '.secure', true).editingHost, true);
editor.innerText = 'x'.repeat(2000); editor.textContent = editor.innerText;
assert.equal(read.call(editor, 'data-testid', '.secure', true).value.length, 512);
assert.equal(read.call(editor, 'data-testid', '.secure').value.length, 2000);
for (const [rendered, raw, value] of [['\n\n', '\n\n', '\n\n'], ['\n', '', ''], ['\n', '  ', ''], ['   ', '   ', '   '], ['hi\n\ufeff', 'hi\ufeff', 'hi\n']]) {
  editor.innerText = rendered; editor.textContent = raw;
  assert.equal(read.call(editor, 'data-testid', '.secure').value, value);
}
for (const tag of ['canvas', 'svg', 'iframe', 'a', 'button', 'input', 'textarea', 'select']) {
  editor.localName = tag;
  assert.equal(read.call(editor, 'data-testid', '.secure', true).editingHost, false);
}
editor.localName = 'article';
const editableParent = new Element(); editableParent.isContentEditable = true; editor.parentElement = editableParent;
assert.equal(read.call(editor, 'data-testid', '.secure', true).editingHost, false);
editableParent.isContentEditable = false;
assert.equal(read.call(editor, 'data-testid', '.secure', true).editingHost, true);
editor.parentElement = null; editor.secure = true;
Object.defineProperty(editor, 'innerText', { get() { throw Error('Secure editor content read'); } });
assert.equal(read.call(editor, 'data-testid', '.secure', true).value, null);
editor.secure = false;
const originalQuerySelector = Element.prototype.querySelector;
Element.prototype.querySelector = function() { return this === editor ? new Element() : null; };
assert.equal(read.call(editor, 'data-testid', '.secure', true).value, null);
Element.prototype.querySelector = originalQuerySelector;
console.log('PASS: editing-host rendered value, boundaries, exclusions, and secure protection');

const matchScript = source.match(/const MATCH_QUERY: &str = r#"([\s\S]*?)"#;/)[1];
const matchQuery = eval(`(${matchScript})`);
const target = new Element();
const projected = [{ role: 'button', name: 'Log out', states: {}, attributes: {} }];
for (const name of [{ kind: 'string', value: 'Log out', exact: true }, { kind: 'regexp', source: '^Log out$', flags: 'u' }]) {
  const expression = { kind: 'query', query: { kind: 'role', value: { kind: 'string', value: 'button', exact: true }, name } };
  assert.deepEqual(matchQuery(expression, projected, [[]], [null], ".secure", [false], target).indices, [0]);
}
console.log('PASS: string and regexp role queries consume the same reported name');

// Native open/closed-shadow security inventory marks exact ancestor IDs before
// metadata acquisition. The renderer must not read that editor's value at all.
const nativeProtected = new Element(); nativeProtected.isContentEditable = true;
Object.defineProperty(nativeProtected, 'innerText', { get() { throw Error('Native-proven sensitive editor acquired'); } });
Object.defineProperty(nativeProtected, 'textContent', { get() { throw Error('Native-proven sensitive editor acquired'); } });
assert.equal(read.call(nativeProtected, 'data-testid', '.secure', true, true).value, null);
assert.equal(read.call(nativeProtected, 'data-testid', '.secure', false, true).value, null);
assert.equal(read.call(nativeProtected, 'data-testid', '.secure', false, true).text, null);
console.log('PASS: native-proven sensitive editor blocks value acquisition before renderer return');

const slot = new Element(); slot.localName = 'slot'; slot.checkVisibility = () => false;
assert.equal(read.call(slot, 'data-testid', '.secure', true).states.hidden, true);
assert.equal(read.call(slot, 'data-testid', '.secure', true).author.lineVisible, true);
const originalStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = () => ({ visibility: 'hidden', display: 'contents' });
assert.equal(read.call(slot, 'data-testid', '.secure', true).author.lineVisible, false);
document.defaultView.getComputedStyle = originalStyle;
console.log('PASS: slot line-flow visibility stays distinct from raw node visibility');

// MAIN-world property reads are a separate side-effect-restricted CDP hint.
// Isolated metadata never invokes a page handler getter or the handler itself.
document.defaultView.getComputedStyle = () => ({ visibility: 'visible', display: 'inline' });
const propertyEndpoint = new Element();
Object.defineProperty(propertyEndpoint, 'onclick', { get() { throw Error('Isolated handler getter invoked'); } });
const propertyFacts = read.call(propertyEndpoint, 'data-testid', '.secure', true);
assert.equal(propertyFacts.handlerProbe, true);
assert.equal(propertyFacts.author.action, false);
assert.equal(read.call(propertyEndpoint, 'data-testid', '.secure', false).handlerProbe, false);
propertyEndpoint.checkVisibility = () => false;
assert.equal(read.call(propertyEndpoint, 'data-testid', '.secure', true).handlerProbe, false);
propertyEndpoint.checkVisibility = () => true;
const attributeEndpoint = new Element(); attributeEndpoint.hasAttribute = name => name === 'onclick';
const attributeFacts = read.call(attributeEndpoint, 'data-testid', '.secure', true);
assert.equal(attributeFacts.handlerProbe, false);
assert.equal(attributeFacts.author.action, true);
const hint = eval(`(${source.match(/const MAIN_ONCLICK_HINT: &str = "([^"]+)";/)[1]})`);
assert.equal(hint.call({ onclick: null }), false);
assert.equal(hint.call({ onclick() { throw Error('Handler invoked'); } }), true);
assert.equal(hint.call({ addEventListener() {} }), false);
console.log('PASS: isolated metadata gates main-world handler hint without invoking handler getters');

// A landmark's author section scope crosses the exact receiver's shadow root.
Node.prototype.getRootNode = function() { return this.nativeRoot || document; };
const baseMatches = Element.prototype.matches;
Element.prototype.matches = function(selector) {
  if (selector.startsWith('article,aside,')) return this.sectionScope === true;
  return baseMatches.call(this, selector);
};
for (const tag of ['header', 'footer']) {
  const landmark = new Element(); landmark.localName = tag;
  assert.equal(read.call(landmark, 'data-testid', '.secure', true).pageLevelLandmark, true);
  const sectionHost = new Element(); sectionHost.sectionScope = true;
  landmark.nativeRoot = { host: sectionHost };
  assert.equal(read.call(landmark, 'data-testid', '.secure', true).pageLevelLandmark, false);
  sectionHost.sectionScope = false;
  assert.equal(read.call(landmark, 'data-testid', '.secure', true).pageLevelLandmark, true);
  landmark.parentElement = landmark;
  assert.equal(read.call(landmark, 'data-testid', '.secure', true).__nativeStatus, 'resource-limit');
}
Element.prototype.matches = baseMatches;
console.log('PASS: author landmark scope crosses shadow hosts with a bounded walk');

// Associated labels exclude decorative aria-hidden content. This is not the
// IDREF-root hidden policy, which intentionally remains a separate code path.
const associatedLabel = new Element(); associatedLabel.localName = 'label';
const marker = new Element(); marker.localName = 'span';
marker.getAttribute = name => name === 'aria-hidden' ? 'TrUe' : null;
marker.childNodes = [new Text('*', marker)];
associatedLabel.childNodes = [new Text('Name', associatedLabel), marker];
const labelledControl = new Element(); labelledControl.labels = [associatedLabel];
assert.deepEqual(read.call(labelledControl, 'data-testid', '.secure', false).labels, ['Name']);
associatedLabel.getAttribute = name => name === 'aria-hidden' ? 'true' : null;
assert.deepEqual(read.call(labelledControl, 'data-testid', '.secure', false).labels, []);
associatedLabel.getAttribute = () => null;
marker.secure = true;
marker.getAttribute = () => null;
assert.deepEqual(read.call(labelledControl, 'data-testid', '.secure', false).labels, ['Name']);
console.log('PASS: associated-label text drops aria-hidden markers without weakening secure exclusion');

const simpleStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: 'none' });
const simpleLabel = new Element(); simpleLabel.localName = 'label';
const unnamedControl = new Element(); unnamedControl.localName = 'input'; unnamedControl.labels = [simpleLabel];
simpleLabel.childNodes = [new Text('Name', simpleLabel), unnamedControl];
const completeName = () => read.call(unnamedControl, 'data-testid', '.secure', false, false, true).simpleAssociatedName;
assert.equal(completeName(), 'Name');
assert.equal(read.call(unnamedControl, 'data-testid', '.secure', false).simpleAssociatedName, null);
assert.equal(read.call(unnamedControl, 'data-testid', '.secure', false, true, true).simpleAssociatedName, null);
unnamedControl.getAttribute = name => name === 'aria-labelledby' ? 'other' : null;
assert.equal(completeName(), null); unnamedControl.getAttribute = () => null;
for (const tag of ['input', 'svg', 'slot']) {
  const rich = new Element(); rich.localName = tag;
  const old = Element.prototype.matches;
  Element.prototype.matches = function(selector) { return this === rich && selector.includes(tag) || old.call(this, selector); };
  simpleLabel.childNodes.push(rich); assert.equal(completeName(), null); simpleLabel.childNodes.pop();
  Element.prototype.matches = old;
}
const authored = new Element(); authored.hasAttribute = name => name === 'title';
simpleLabel.childNodes.push(authored); assert.equal(completeName(), null); simpleLabel.childNodes.pop();
document.defaultView.getComputedStyle = (_node, pseudo) => ({ display: 'inline', visibility: 'visible', content: pseudo ? '"icon"' : 'none' });
assert.equal(completeName(), null);
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: 'none' });
simpleLabel.childNodes = [new Text('x'.repeat(513), simpleLabel)]; assert.equal(completeName(), null);
simpleLabel.childNodes = [new Text('Name', simpleLabel)]; simpleLabel.secure = true; assert.equal(completeName(), null);
document.defaultView.getComputedStyle = simpleStyle;
console.log('PASS: complete simple label facts require native inventory and reject rich/secure/overflow content');

// Accessible-name boundaries are not line-text inline-flow boundaries.
simpleLabel.secure = false;
document.defaultView.getComputedStyle = node => ({ display: node.nameDisplay || 'inline', visibility: 'visible', content: 'none' });
for (const display of ['inline-block', 'inline-flex', 'inline-grid', 'contents']) {
  const child = new Element(); child.localName = 'span'; child.nameDisplay = display;
  child.childNodes = [new Text('B', child)];
  simpleLabel.childNodes = [new Text('A', simpleLabel), child];
  assert.equal(completeName(), 'A B');
}
const lineBreak = new Element(); lineBreak.localName = 'br';
simpleLabel.childNodes = [new Text('A', simpleLabel), lineBreak, new Text('B', simpleLabel)];
assert.equal(completeName(), 'A B');
document.defaultView.getComputedStyle = simpleStyle;
console.log('PASS: simple associated names preserve BR and non-inline child boundaries');

const referenceTarget = new Element(); referenceTarget.localName = 'span';
referenceTarget.getAttribute = name => name === 'title' ? 'Spaced reference' : null;
referenceTarget.childNodes = [new Text(' \t', referenceTarget)];
const referenceControl = new Element(); referenceControl.getAttribute = name => name === 'aria-labelledby' ? 'reference' : null;
const savedLookup = document.getElementById;
document.getElementById = id => id === 'reference' ? referenceTarget : null;
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: 'none' });
const emptyReference = () => read.call(referenceControl, 'data-testid', '.secure', false, false, true).completeEmptyReference;
assert.equal(emptyReference(), true);
assert.equal(read.call(referenceControl, 'data-testid', '.secure', false).completeEmptyReference, false);
referenceTarget.childNodes = [new Text('\uFEFF', referenceTarget)]; assert.equal(emptyReference(), true);
for (const text of ['', '\u0085', 'named', ' '.repeat(513)]) {
  referenceTarget.childNodes = [new Text(text, referenceTarget)]; assert.equal(emptyReference(), false);
}
referenceTarget.childNodes = [new Text(' ', referenceTarget), new Element()]; assert.equal(emptyReference(), false);
referenceTarget.childNodes = [new Text(' ', referenceTarget)];
referenceTarget.getAttribute = name => name === 'aria-label' ? 'Named target' : null; assert.equal(emptyReference(), false);
referenceTarget.getAttribute = () => null;
referenceTarget.secure = true; assert.equal(emptyReference(), false); referenceTarget.secure = false;
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: '"generated"' });
assert.equal(emptyReference(), false);
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;
console.log('PASS: complete-empty IDREF facts require exact native-gated whitespace-only complete targets');

// A document ID with the same spelling cannot complete another tree's IDREF.
document.getElementById = id => id === 'reference' ? referenceTarget : null;
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: 'none' });
referenceControl.nativeRoot = { host: new Element(), getElementById: () => referenceTarget };
assert.equal(emptyReference(), false); delete referenceControl.nativeRoot;
referenceTarget.hasAttribute = name => name === 'role'; assert.equal(emptyReference(), false);
referenceTarget.hasAttribute = () => false;
referenceTarget.localName = 'textarea'; assert.equal(emptyReference(), false); referenceTarget.localName = 'span';
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;

// Chained authored references remain outside this intentionally simple proof.
document.getElementById = id => id === 'reference' ? referenceTarget : null;
document.defaultView.getComputedStyle = () => ({ display: 'inline', visibility: 'visible', content: 'none' });
referenceTarget.hasAttribute = name => name === 'aria-labelledby';
referenceTarget.getAttribute = name => name === 'aria-labelledby' ? 'another-name' : null;
assert.equal(emptyReference(), false);
referenceTarget.hasAttribute = () => false; referenceTarget.getAttribute = () => null;
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;

const skippingBox = new Element(); skippingBox.innerText = '';
document.defaultView.getComputedStyle = () => ({ display: 'block', visibility: 'visible', contentVisibility: 'hidden', content: 'none' });
const skippingFacts = read.call(skippingBox, 'data-testid', '.secure', true);
assert.equal(skippingFacts.author.skipsContent, true);
assert.equal(skippingFacts.states.hidden, false);
assert.deepEqual(skippingFacts.rect, { x: 0, y: 0, width: 10, height: 10 });
assert.equal(read.call(skippingBox, 'data-testid', '.secure', false).text, '');
document.defaultView.getComputedStyle = () => ({ display: 'block', visibility: 'hidden', contentVisibility: 'visible', content: 'none' });
assert.equal(read.call(skippingBox, 'data-testid', '.secure', true).author.skipsContent, false);
document.defaultView.getComputedStyle = simpleStyle;
console.log('PASS: content-skipping metadata preserves owner box and direct-read rendering contract');

// Native control properties precede stale ARIA and native AX projection.

for (const type of ['checkbox','radio']) {
  for (const checked of [true,false]) {
    const input=new InputControl(type,checked);
    input.getAttribute=name=>name==='aria-checked'?String(!checked):null;
    assert.deepEqual(read.call(input,'data-testid','.secure',true).controlStates,{checked});
    assert.equal(read.call(input,'data-testid','.secure',true).value,null);
    assert.equal(read.call(input,'data-testid','.secure',false).value,'on');
  }
}
for (const selected of [true,false]) {
  const option=new OptionControl(selected);
  option.getAttribute=name=>name==='aria-selected'?String(!selected):null;
  assert.deepEqual(read.call(option,'data-testid','.secure',true).controlStates,{selected});
}
for (const [value,selected] of [['TRUE',true],['TrUe',true],['FALSE',false]]) {
  const tab=new Element();tab.getAttribute=name=>name==='aria-selected'?value:null;
  assert.deepEqual(read.call(tab,'data-testid','.secure',true).controlStates,{selected});
}
console.log('PASS: exact native control properties override ARIA, with checkable tokens only in direct reads');

// Complete native-button content names correct specific AX omissions without
// growing into another accessible-name reader. Unsupported is not empty.
const nameStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = (node, pseudo) => ({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
function attributes(node, values) {
  node.attributes = Object.entries(values).map(([name, value]) => ({ name, value }));
  node.getAttribute = name => values[name] ?? null;
  node.hasAttribute = name => Object.hasOwn(values, name);
  return node;
}
function wrapper(children = [], attrs = {}) {
  const node = attributes(new Element(), attrs); node.localName = 'span'; node.childNodes = children; return node;
}
const button = new ButtonControl();
const buttonName = (bounded = false, protectedEditor = false, inventory = true) => read.call(button, 'data-testid', '.secure', bounded, protectedEditor, inventory).completeButtonContentName;
button.childNodes = [new Text('Save ', button), wrapper([new Text('draft', button)], { inert: '' })];
assert.equal(buttonName(), 'Save draft');
assert.equal(buttonName(true), 'Save draft');
assert.equal(buttonName(false, false, false), null);
assert.equal(buttonName(false, true), null);
const svg = attributes(new EmptySvg(), { width: '10', height: '10' });
const titled = wrapper([svg], { title: 'Child tooltip' });
button.childNodes = [titled];
assert.equal(buttonName(), 'Child tooltip');
// Flex blockifies its SVG; raw boundary spaces prevent the wrapper title.
titled.nameDisplay = 'flex'; svg.nameDisplay = 'block';
assert.equal(buttonName(), '');
attributes(button, { title: ' Own  tooltip ' });
assert.equal(buttonName(), 'Own  tooltip');
attributes(button, {}); delete titled.nameDisplay; delete svg.nameDisplay;
titled.childNodes = [new Text(' \t', titled)];
assert.equal(buttonName(), '');
titled.childNodes = [];
assert.equal(buttonName(), 'Child tooltip');
titled.childNodes = [new Text('Actual', titled)];
assert.equal(buttonName(), 'Actual');
for (const display of ['block', 'inline-block', 'inline-flex', 'inline-grid', 'contents']) {
  const child = wrapper([new Text('B', button)]); child.nameDisplay = display;
  button.childNodes = [new Text('A', button), child]; assert.equal(buttonName(), 'A B');
}
const br = wrapper(); br.localName = 'br';
button.childNodes = [new Text('A', button), br, new Text('B', button)];
assert.equal(buttonName(), 'A B');
for (const hidden of ['aria', 'display', 'visibility']) {
  const child = wrapper([new Text('Hidden', button)]);
  if (hidden === 'aria') attributes(child, { 'aria-hidden': 'TrUe' });
  if (hidden === 'display') child.nameDisplay = 'none';
  if (hidden === 'visibility') child.nameVisibility = 'hidden';
  button.childNodes = [child, new Text(' Visible', button)]; assert.equal(buttonName(), 'Visible');
}
button.childNodes = [new Text('Child', button)];
for (const attrs of [{ role: 'link' }, { role: 'none' }, { 'aria-label': '' }, { 'aria-labelledby': 'name' }, { alt: '' }, { contenteditable: 'false' }]) {
  attributes(button, attrs); assert.equal(buttonName(), null);
}
attributes(button, { role: 'button' }); assert.equal(buttonName(), 'Child');
attributes(button, {});
button.labels = [wrapper()]; assert.equal(buttonName(), null); button.labels = [];
button.secure = true; assert.equal(buttonName(), null); button.secure = false;
button.shadowRoot = {}; assert.equal(buttonName(), null); delete button.shadowRoot;
button.generated = '"before"'; assert.equal(buttonName(), null); delete button.generated;
button.isContentEditable = true; assert.equal(buttonName(), null); button.isContentEditable = false;
const fakeButton = new Element(); fakeButton.localName = 'button'; fakeButton.childNodes = button.childNodes;
assert.equal(read.call(fakeButton, 'data-testid', '.secure', false, false, true).completeButtonContentName, null);
for (const tag of ['img', 'input', 'textarea', 'select', 'button', 'slot', 'canvas', 'math', 'custom-icon']) {
  const rich = wrapper(); rich.localName = tag; button.childNodes = [rich]; assert.equal(buttonName(), null);
}
for (const attrs of [{ title: 'SVG title' }, { alt: '' }, { 'aria-label': '' }, { 'aria-labelledby': '' }, { 'aria-describedby': 'desc' }, { role: 'img' }, { tabindex: '0' }]) {
  attributes(svg, attrs); button.childNodes = [wrapper([svg], { title: 'Must not guess' })]; assert.equal(buttonName(), null);
}
attributes(svg, { width: '10', height: '10' });
svg.childNodes = [new Text('', svg)]; assert.equal(buttonName(), null); svg.childNodes = [];
svg.generated = '"icon"'; assert.equal(buttonName(), null); delete svg.generated;
const sensitive = wrapper(); sensitive.secure = true;
Object.defineProperty(sensitive, 'childNodes', { get() { throw Error('Secure name content acquired'); } });
button.childNodes = [sensitive]; assert.equal(buttonName(), null);
for (const chars of [513, 100000]) {
  button.childNodes = [new Text('x'.repeat(chars), button)]; assert.equal(buttonName(), null);
}
button.childNodes = Array.from({ length: 513 }, () => new Text('', button)); assert.equal(buttonName(), null);
let nested = wrapper(); for (let i = 0; i < 65; i++) nested = wrapper([nested]);
button.childNodes = [nested]; assert.equal(buttonName(), null);
document.defaultView.getComputedStyle = nameStyle;
console.log('PASS: native button name proofs preserve inert/title/raw-space precedence and reject unsupported, secure, shadow, and oversized content');

// Original public 11-href fixture, exercised through actual shared METADATA.
// These are scalar inputs, not a second observation/DOM reader or a decoder.
const hrefDocument = document;
hrefDocument.baseURI = 'http://app.test/dashboard/';
const projectPath = '/dashboard/e2e-dc3cf837/projects/404b2532-9fab-44dc-b3d0-f0a1b2c3d4e5/runs/7d0c3b52-2f7e-4c55-9a51-6f1e0c9b8a77';
const publicHrefs = [
  [projectPath, `http://app.test${projectPath}`],
  ['https://user:pass@docs.example.test/guides/setup', 'https://docs.example.test/guides/setup'],
  ['search?q=token&page=2', 'http://app.test/dashboard/search?…'],
  ['settings#billing', 'http://app.test/dashboard/settings#…'],
  ['mailto:team@example.test?subject=hi', 'mailto:team@example.test?…'],
  ['tel:+48123456789', 'tel:+48123456789'],
  [`data:text/csv,${'id,name%0A1,Ada%0A'.repeat(200)}`, 'data:…'],
  ["javascript:void(document.body.dataset.clicked = 'yes')", 'javascript:…'],
  ['blob:http://app.test/0b7c4c1e-8d9a-4f2e-9c1b-2a3d4e5f6a7b', 'blob:http://app.test/0b7c4c1e-8d9a-4f2e-9c1b-2a3d4e5f6a7b'],
  ['blob:https://user:pass@files.example.test/0b7c4c1e?token=abc', 'blob:https://files.example.test/0b7c4c1e?…'],
  ['blob:null/0b7c4c1e', 'blob:…'],
];
function hrefNode(value) {
  const node = attributes(new Element(), { href: value }); node.localName = 'a'; return node;
}
function checkHref(raw, expected, forbidden = []) {
  const node = hrefNode(raw);
  const protectedMetadata = read.call(node, 'data-testid', '.secure', true);
  assert.equal(protectedMetadata.attributes.href, expected);
  assert.equal(read.call(node, 'data-testid', '.secure', false).attributes.href, raw);
  for (const token of forbidden) assert.equal(JSON.stringify(protectedMetadata).includes(token), false);
  return node;
}
for (const [raw, expected] of publicHrefs) checkHref(raw, expected);
console.log('PASS: actual METADATA matches all 11 original protected href fixtures and preserves exact raw reads');

// Full paths survive; credentials and nonempty query/fragment payloads do not.
const longPath = `/${'404b2532-9fab-44dc-b3d0-f0a1b2c3d4e5/'.repeat(100)}end`;
for (const [raw, expected, forbidden] of [
  [`https://synthetic-user:synthetic-password@files.test${longPath}?synthetic-query#synthetic-fragment`, `https://files.test${longPath}?…#…`, ['synthetic-user', 'synthetic-password', 'synthetic-query', 'synthetic-fragment']],
  ['blob:https://blob-user:blob-password@files.test/item?blob-query#blob-fragment', 'blob:https://files.test/item?…#…', ['blob-user', 'blob-password', 'blob-query', 'blob-fragment']],
  ['mailto:team@example.test?mail-query#mail-fragment', 'mailto:team@example.test?…#…', ['mail-query', 'mail-fragment']],
  ['tel:+48123456789?call-query#call-fragment', 'tel:+48123456789?…#…', ['call-query', 'call-fragment']],
  ['blob:null/blob-payload?blob-query#blob-fragment', 'blob:…', ['blob-payload', 'blob-query', 'blob-fragment']],
  ['blob:not-a-url-payload', 'blob:…', ['not-a-url-payload']],
  ['blob:mailto:private@example.test', 'blob:…', ['private@example.test']],
  ['data:text/plain,opaque-payload?opaque-query#opaque-fragment', 'data:…', ['opaque-payload', 'opaque-query', 'opaque-fragment']],
  ['javascript:script-payload?script-query#script-fragment', 'javascript:…', ['script-payload', 'script-query', 'script-fragment']],
  ['custom:opaque-payload', 'custom:…', ['opaque-payload']],
  ['file:///private/path?file-query#file-fragment', 'file:…', ['private/path', 'file-query', 'file-fragment']],
]) checkHref(raw, expected, forbidden);
for (const [suffix, tail] of [['?', ''], ['#', ''], ['?#', ''], ['?q#', '?…'], ['?#f', '#…'], ['??##', '?…#…']]) {
  checkHref(`https://files.test/path${suffix}`, `https://files.test/path${tail}`);
  checkHref(`blob:https://files.test/path${suffix}`, `blob:https://files.test/path${tail}`);
  // Deliberately retain the original malformed-target fallback, not a new policy.
  checkHref(`http://[invalid${suffix}`, `http://[invalid${tail}`);
}
checkHref('http://[invalid?fallback-query#fallback-fragment', 'http://[invalid?…#…', ['fallback-query', 'fallback-fragment']);
checkHref('https://files.test/a/../b/…?query#fragment', 'https://files.test/b/%E2%80%A6?…#…', ['query', 'fragment']);
console.log('PASS: protected hrefs preserve full paths and exact empty-tail/invalid/opaque rules without payload leakage');

// Resolution must use the receiver's live document base, not page location,
// stale navigation state, a sibling frame, or the top document.
const relativeNode = hrefNode('../target?base-query#base-fragment');
for (const [base, expected] of [
  ['https://one.test/a/b/', 'https://one.test/a/target?…#…'],
  ['https://two.test/changed/', 'https://two.test/target?…#…'],
]) {
  hrefDocument.baseURI = base;
  assert.equal(read.call(relativeNode, 'data-testid', '.secure', true).attributes.href, expected);
  assert.equal(read.call(relativeNode, 'data-testid', '.secure', false).attributes.href, '../target?base-query#base-fragment');
}
checkHref('/root/path', 'https://two.test/root/path');
checkHref('//network.test/path?private', 'https://network.test/path?…', ['private']);
const originalOwner = Object.getOwnPropertyDescriptor(Node.prototype, 'ownerDocument');
Object.defineProperty(Node.prototype, 'ownerDocument', { configurable: true, get() { return this.fixtureDocument || document; } });
const frameDocument = { ...hrefDocument, baseURI: 'https://frame.test/frame/base/', URL: 'about:blank' };
const frameLink = hrefNode('asset?frame-token'); frameLink.fixtureDocument = frameDocument;
// A frame receiver in the wrong isolated document must still fail identity validation.
assert.equal(read.call(frameLink, 'data-testid', '.secure', true).__nativeStatus, 'stale-reference');
document = global.document = frameDocument;
assert.equal(read.call(frameLink, 'data-testid', '.secure', true).attributes.href, 'https://frame.test/frame/base/asset?…');
// about:blank/srcdoc can inherit an effective base without changing document URL.
frameDocument.baseURI = 'https://inherited.test/parent/';
assert.equal(read.call(frameLink, 'data-testid', '.secure', true).attributes.href, 'https://inherited.test/parent/asset?…');
frameDocument.baseURI = 'about:blank';
assert.equal(read.call(frameLink, 'data-testid', '.secure', true).attributes.href, 'asset?…');
Object.defineProperty(frameDocument, 'baseURI', { get() { throw Error('Direct read must not resolve href'); } });
assert.equal(read.call(frameLink, 'data-testid', '.secure', false).attributes.href, 'asset?frame-token');
document = global.document = hrefDocument;
Object.defineProperty(Node.prototype, 'ownerDocument', originalOwner);
hrefDocument.baseURI = 'http://app.test/dashboard/';
console.log('PASS: live base changes, frame isolation, inherited bases, and raw-read nonresolution remain distinct');

const secureLink = hrefNode('https://secure-user:secure-password@files.test/path?secure-query#secure-fragment');
secureLink.secure = true; secureLink.value = 'secure-value';
attributes(secureLink, { href: secureLink.getAttribute('href'), value: 'secure-value' });
const secureHref = read.call(secureLink, 'data-testid', '.secure', true);
assert.equal(secureHref.attributes.href, 'https://files.test/path?…#…');
assert.equal(secureHref.states.secure, true);
assert.equal(secureHref.value, null);
assert.equal(secureHref.attributes.value, undefined);
for (const token of ['secure-user', 'secure-password', 'secure-query', 'secure-fragment', 'secure-value']) {
  assert.equal(JSON.stringify(secureHref).includes(token), false);
}
const secureRaw = read.call(secureLink, 'data-testid', '.secure', false);
assert.equal(secureRaw.attributes.href, secureLink.getAttribute('href'));
assert.equal(secureRaw.value, null);
assert.equal(secureRaw.attributes.value, undefined);
assert.equal(read.call(new Element(), 'data-testid', '.secure', true).attributes.href, undefined);
console.log('PASS: href reduction preserves secure-value exclusion and absence without changing direct attribute access');

// Option listing is an observation graph exception, never a raw metadata or
// locator visibility rewrite, even when the exact option has a hidden owner.
const hiddenSelect = new Element(); hiddenSelect.localName = 'select';
hiddenSelect.getBoundingClientRect = () => ({ x: 0, y: 0, width: 0, height: 0 });
const directOption = new OptionControl(true); directOption.parentElement = hiddenSelect;
directOption.checkVisibility = () => false;
directOption.matches = selector => selector === 'option';
for (const bounded of [false, true]) {
  const optionFacts = read.call(directOption, 'data-testid', '.secure', bounded);
  assert.equal(optionFacts.states.hidden, true);
  assert.equal(optionFacts.author.visible, false);
  assert.equal(optionFacts.value, 'Poland');
  assert.equal(optionFacts.controlStates.selected, true);
}
assert.equal(read.call(hiddenSelect, 'data-testid', '.secure', false).states.hidden, true);
const rawOptionFacts = read.call(directOption, 'data-testid', '.secure', false);
const queryOptionFacts = [{ ...rawOptionFacts, role: 'option', name: 'Poland' }];
assert.deepEqual(matchQuery({ kind: 'selector', selector: 'option' }, queryOptionFacts, [[]], [null], '.secure', [false], directOption).indices, [0]);
assert.deepEqual(matchQuery({ kind: 'query', query: { kind: 'role', value: { kind: 'string', value: 'option', exact: true } } }, queryOptionFacts, [[]], [null], '.secure', [false], directOption).indices, []);
console.log('PASS: hidden select/option exact metadata, raw value, and selector-versus-role query contracts stay unchanged');

// Public landmark naming is attribute presence, not resolved-name computation.
for (const bounded of [false, true]) {
  for (const name of ['aria-label', 'aria-labelledby', 'title']) {
    for (const [value, expected] of [[null, false], ['', false], [' \t\n', false], ['\u00a0\ufeff', false], ['missing-reference', true], ['\u0085', true]]) {
      const form = new Element(); form.localName = 'form'; form.innerText = '';
      form.getAttribute = key => key === name ? value : null;
      assert.equal(read.call(form, 'data-testid', '.secure', bounded).formOwnName, expected, `${bounded}/${name}/${expected}`);
    }
  }
  assert.equal(read.call(new Element(), 'data-testid', '.secure', bounded).formOwnName, null);
  for (const scope of [null, '', 'auto', 'invalid', 'ROW', 'rowgroup', 'Col', 'colgroup', ' row ']) {
    for (const rows of [0, 1, 2]) {
      for (const sibling of [false, true]) {
        const table = { rows: Array(rows) };
        const th = new Element(); th.localName = 'th'; th.innerText = 'Item';
        th.parentElement = new Element(); th.parentElement.localName = 'tr'; th.parentElement.closest = () => table;
        th.previousElementSibling = sibling ? new Element() : null; th.nextElementSibling = null;
        th.getAttribute = name => name === 'scope' ? scope : null;
        const scoped = ['row', 'rowgroup', 'col', 'colgroup'].includes((scope || '').toLowerCase());
        assert.equal(read.call(th, 'data-testid', '.secure', bounded).singleCellHeader, !scoped && !sibling && rows <= 1, `${bounded}/${scope}/${rows}/${sibling}`);
      }
    }
  }
  const detachedHeader = new Element(); detachedHeader.localName = 'th'; detachedHeader.innerText = 'Item';
  detachedHeader.previousElementSibling = null; detachedHeader.nextElementSibling = null;
  assert.equal(read.call(detachedHeader, 'data-testid', '.secure', bounded).singleCellHeader, false);
  const nonRow = new Element(); nonRow.localName = 'div'; detachedHeader.parentElement = nonRow;
  assert.equal(read.call(detachedHeader, 'data-testid', '.secure', bounded).singleCellHeader, false);
}
console.log('PASS: original form own-name presence and sole-cell header facts preserve whitespace, scope and multirow boundaries');
