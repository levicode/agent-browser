// Run without a browser to check bounded metadata and shadow-root redaction.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// The current metadata producer reads CSS interactivity through the standard
// property accessor. Keep every scripted style explicit and reject new reads.
function css(values) {
  return { ...values, getPropertyValue(name) {
    assert.equal(name, 'interactivity');
    return values.interactivity ?? 'auto';
  } };
}
assert.equal(css({}).getPropertyValue('interactivity'), 'auto');
assert.equal(css({ interactivity: 'inert' }).getPropertyValue('interactivity'), 'inert');
assert.throws(() => css({}).getPropertyValue('unexpected-property'), assert.AssertionError);
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
  defaultView: { getComputedStyle: () => css({ visibility: 'visible', display: 'block' }) },
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
document.defaultView.getComputedStyle = () => css({ visibility: 'hidden', display: 'contents' });
assert.equal(read.call(slot, 'data-testid', '.secure', true).author.lineVisible, false);
document.defaultView.getComputedStyle = originalStyle;
console.log('PASS: slot line-flow visibility stays distinct from raw node visibility');

// MAIN-world property reads are a separate side-effect-restricted CDP hint.
// Isolated metadata never invokes a page handler getter or the handler itself.
document.defaultView.getComputedStyle = () => css({ visibility: 'visible', display: 'inline' });
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
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: 'none' });
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
document.defaultView.getComputedStyle = (_node, pseudo) => css({ display: 'inline', visibility: 'visible', content: pseudo ? '"icon"' : 'none' });
assert.equal(completeName(), null);
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: 'none' });
simpleLabel.childNodes = [new Text('x'.repeat(513), simpleLabel)]; assert.equal(completeName(), null);
simpleLabel.childNodes = [new Text('Name', simpleLabel)]; simpleLabel.secure = true; assert.equal(completeName(), null);
document.defaultView.getComputedStyle = simpleStyle;
console.log('PASS: complete simple label facts require native inventory and reject rich/secure/overflow content');

// Accessible-name boundaries are not line-text inline-flow boundaries.
simpleLabel.secure = false;
document.defaultView.getComputedStyle = node => css({ display: node.nameDisplay || 'inline', visibility: 'visible', content: 'none' });
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
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: 'none' });
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
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: '"generated"' });
assert.equal(emptyReference(), false);
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;
console.log('PASS: complete-empty IDREF facts require exact native-gated whitespace-only complete targets');

// A document ID with the same spelling cannot complete another tree's IDREF.
document.getElementById = id => id === 'reference' ? referenceTarget : null;
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: 'none' });
referenceControl.nativeRoot = { host: new Element(), getElementById: () => referenceTarget };
assert.equal(emptyReference(), false); delete referenceControl.nativeRoot;
referenceTarget.hasAttribute = name => name === 'role'; assert.equal(emptyReference(), false);
referenceTarget.hasAttribute = () => false;
referenceTarget.localName = 'textarea'; assert.equal(emptyReference(), false); referenceTarget.localName = 'span';
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;

// Chained authored references remain outside this intentionally simple proof.
document.getElementById = id => id === 'reference' ? referenceTarget : null;
document.defaultView.getComputedStyle = () => css({ display: 'inline', visibility: 'visible', content: 'none' });
referenceTarget.hasAttribute = name => name === 'aria-labelledby';
referenceTarget.getAttribute = name => name === 'aria-labelledby' ? 'another-name' : null;
assert.equal(emptyReference(), false);
referenceTarget.hasAttribute = () => false; referenceTarget.getAttribute = () => null;
document.defaultView.getComputedStyle = simpleStyle;
document.getElementById = savedLookup;

const skippingBox = new Element(); skippingBox.innerText = '';
document.defaultView.getComputedStyle = () => css({ display: 'block', visibility: 'visible', contentVisibility: 'hidden', content: 'none' });
const skippingFacts = read.call(skippingBox, 'data-testid', '.secure', true);
assert.equal(skippingFacts.author.skipsContent, true);
assert.equal(skippingFacts.states.hidden, false);
assert.deepEqual(skippingFacts.rect, { x: 0, y: 0, width: 10, height: 10 });
assert.equal(read.call(skippingBox, 'data-testid', '.secure', false).text, '');
document.defaultView.getComputedStyle = () => css({ display: 'block', visibility: 'hidden', contentVisibility: 'visible', content: 'none' });
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
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
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

// First direct caption names its parent before title/content fallback. These
// exercise the actual shared metadata, not a replacement naming algorithm.
const captionStyle = document.defaultView.getComputedStyle;
const captionMatches = Element.prototype.matches;
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
Element.prototype.matches = function(selector) {
  return selector.split(',').includes(this.localName) || captionMatches.call(this, selector);
};
function namingElement(tag, children = [], attrs = {}) {
  const node = attributes(new Element(), attrs);
  node.localName = tag; node.childNodes = children; node.innerText = ''; node.textContent = '';
  for (const child of children) child.parentElement = node;
  return node;
}
const captionFacts = (node, bounded = false, protectedEditor = false, inventory = true) => read.call(node, 'data-testid', '.secure', bounded, protectedEditor, inventory).directCaptionName;
for (const [tag, source, name] of [['fieldset', 'legend', 'Notifications'], ['figure', 'figcaption', 'Figure one'], ['table', 'caption', 'Scores']]) {
  const first = namingElement(source, [new Text(`  ${name}\n`, null)]);
  const second = namingElement(source, [new Text('Never selected', null)]);
  const parent = namingElement(tag, [new Text('Body ignored', null), first, second], { title: 'Lower priority' });
  for (const bounded of [false, true]) assert.deepEqual(captionFacts(parent, bounded), { source, name });
  first.childNodes = [new Text(' \t\ufeff', first)];
  assert.deepEqual(captionFacts(parent), { source, name: '' });
  first.childNodes = [namingElement('span', [new Text('Nested plain', null)])];
  assert.deepEqual(captionFacts(parent), { source, name: 'Nested plain' });
  for (const attr of ['aria-label', 'aria-labelledby']) {
    attributes(parent, { [attr]: 'Higher priority' }); assert.equal(captionFacts(parent), null);
    attributes(parent, { [attr]: ' \t' }); assert.equal(captionFacts(parent).name, 'Nested plain');
  }
  attributes(parent, {});
  parent.labels = [namingElement('label')]; assert.equal(captionFacts(parent), null); parent.labels = [];
  assert.equal(captionFacts(parent, false, false, false), null);
  assert.equal(captionFacts(parent, false, true), null);
  parent.secure = true; assert.equal(captionFacts(parent), null); parent.secure = false;
  parent.shadowRoot = {}; assert.equal(captionFacts(parent), null); delete parent.shadowRoot;
  parent.checkVisibility = () => false; assert.equal(captionFacts(parent), null); parent.checkVisibility = () => true;
  first.nameDisplay = 'none'; assert.deepEqual(captionFacts(parent), { source, name: '' }); delete first.nameDisplay;
  first.nameVisibility = 'hidden'; assert.deepEqual(captionFacts(parent), { source, name: '' }); delete first.nameVisibility;
  attributes(first, { 'aria-hidden': 'true' }); assert.deepEqual(captionFacts(parent), { source, name: '' }); attributes(first, {});
  for (const attrs of [{ title: 'Rich' }, { 'aria-label': 'Rich' }, { 'aria-labelledby': 'other' }, { role: 'button' }, { contenteditable: 'true' }]) {
    attributes(first, attrs); assert.equal(captionFacts(parent), null);
  }
  attributes(first, {}); first.generated = '"generated"'; assert.equal(captionFacts(parent), null); delete first.generated;
  for (const rich of ['input', 'svg', 'img', 'button', 'canvas', 'slot']) {
    first.childNodes = [namingElement(rich)]; assert.equal(captionFacts(parent), null);
  }
  first.childNodes = [new Text('x'.repeat(513), first)]; assert.equal(captionFacts(parent), null);
  first.childNodes = Array.from({ length: 513 }, () => new Text('', first)); assert.equal(captionFacts(parent), null);
  let deep = namingElement('span'); for (let i = 0; i < 65; i++) deep = namingElement('span', [deep]);
  first.childNodes = [deep]; assert.equal(captionFacts(parent), null);
  first.secure = true;
  Object.defineProperty(first, 'childNodes', { get() { throw Error('Secure caption content acquired'); } });
  assert.equal(captionFacts(parent), null);
  const nestedOnly = namingElement(tag, [namingElement('div', [second])]); assert.equal(captionFacts(nestedOnly), null);
  const tooMany = namingElement(tag, Array.from({ length: 513 }, () => namingElement('span'))); assert.equal(captionFacts(tooMany), null);
}
assert.equal(captionFacts(namingElement('div', [namingElement('figcaption', [new Text('Not a figure', null)])])), null);
document.defaultView.getComputedStyle = captionStyle;
Element.prototype.matches = captionMatches;
console.log('PASS: first direct-caption source facts preserve priority, empty fallthrough, native inventory, security, complexity and resource bounds');

// Editing-host hint provenance keeps host and first empty descendant separate.
// Empty testing reads only bounded, proven public text nodes, never block values.
const editorHintStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'block', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
function hintHost(children = [], attrs = {}) {
  const node = namingElement('div', children, attrs); node.isContentEditable = true; return node;
}
const hintBlock = (name, children = []) => namingElement('p', children, { 'data-placeholder': name });
const editorHint = (node, bounded = false, protectedEditor = false, inventory = true) => read.call(node, 'data-testid', '.secure', bounded, protectedEditor, inventory).editorPlaceholder;
const emptyHint = hintBlock('  Write something  ', [namingElement('br')]);
const tiptap = hintHost([emptyHint]);
for (const bounded of [false, true]) assert.deepEqual(editorHint(tiptap, bounded), { source: 'empty-descendant', name: 'Write something' });
emptyHint.childNodes = [new Text('Hello', emptyHint)];
assert.deepEqual(editorHint(tiptap), { source: 'none', name: '' });
emptyHint.childNodes = [new Text(' \t\ufeff', emptyHint)];
assert.equal(editorHint(tiptap).name, 'Write something');
tiptap.childNodes = [];
assert.deepEqual(editorHint(tiptap), { source: 'none', name: '' });
const quill = hintHost([hintBlock('Child hint')], { 'data-placeholder': '  Compose  a message  ' });
for (const text of ['', 'Hello', 'x'.repeat(1000)]) {
  quill.textContent = text; quill.innerText = text;
  quill.childNodes = [new Text(text, quill)];
  assert.deepEqual(editorHint(quill), { source: 'host', name: 'Compose  a message' });
  assert.deepEqual(editorHint(quill, true), { source: 'host', name: 'Compose  a message' });
}
quill.childNodes = [hintBlock('Child hint')];
assert.equal(editorHint(quill).name, 'Compose  a message');
const later = hintBlock('Later hint');
const order = hintHost([hintBlock('  '), hintBlock('Typed first', [new Text('Content', null)]), later, hintBlock('Last')]);
assert.equal(editorHint(order).name, 'Later hint');
const nestedHint = hintHost([namingElement('div', [hintBlock('Nested')])]);
assert.equal(editorHint(nestedHint).name, 'Nested');
const parentHint = hintBlock('Parent', [hintBlock('Nested')]);
assert.equal(editorHint(hintHost([parentHint])).name, 'Parent');
assert.equal(editorHint(order, false, false, false), null);
assert.equal(editorHint(order, false, true), null);
for (const attr of ['aria-label', 'aria-labelledby', 'title', 'placeholder', 'aria-placeholder']) {
  attributes(order, { [attr]: 'Higher priority' }); assert.equal(editorHint(order), null);
  attributes(order, { [attr]: ' \t\ufeff' }); assert.equal(editorHint(order).name, 'Later hint');
}
attributes(order, {});
for (const role of ['textbox', 'searchbox', '', ' textbox ']) {
  attributes(order, { role }); assert.equal(editorHint(order).name, 'Later hint');
}
for (const role of ['button', 'link', 'none', 'unknown textbox']) {
  attributes(order, { role }); assert.equal(editorHint(order), null);
}
attributes(order, {});
for (const tag of ['button', 'input', 'textarea', 'canvas', 'svg', 'iframe', 'a']) {
  order.localName = tag; assert.equal(editorHint(order), null);
}
order.localName = 'div'; order.isContentEditable = false; assert.equal(editorHint(order), null); order.isContentEditable = true;
order.parentElement = hintHost(); assert.equal(editorHint(order), null); order.parentElement = null;
order.labels = [namingElement('label')]; assert.equal(editorHint(order), null); order.labels = [];
order.secure = true; assert.equal(editorHint(order), null); order.secure = false;
order.shadowRoot = {}; assert.equal(editorHint(order), null); delete order.shadowRoot;
order.checkVisibility = () => false; assert.equal(editorHint(order), null); order.checkVisibility = () => true;
for (const hidden of ['display', 'visibility', 'aria']) {
  const block = hintBlock('Hidden hint');
  if (hidden === 'display') block.nameDisplay = 'none';
  if (hidden === 'visibility') block.nameVisibility = 'hidden';
  if (hidden === 'aria') attributes(block, { 'data-placeholder': 'Hidden hint', 'aria-hidden': 'true' });
  Object.defineProperty(block, 'childNodes', { get() { throw Error('Hidden hint content acquired'); } });
  assert.equal(editorHint(hintHost([block, later])), null);
}
for (const tag of ['input', 'svg', 'canvas', 'slot', 'button', 'custom-editor']) {
  const unsupported = namingElement(tag);
  Object.defineProperty(unsupported, 'childNodes', { get() { throw Error('Unsupported hint content acquired'); } });
  assert.equal(editorHint(hintHost([unsupported, later])), null);
}
for (const attrs of [{ contenteditable: 'false' }, { role: 'button' }, { 'aria-label': 'Named' }, { 'aria-labelledby': 'label' }, { alt: 'Alternative' }]) {
  const block = hintBlock('Unsupported'); attributes(block, { 'data-placeholder': 'Unsupported', ...attrs });
  assert.equal(editorHint(hintHost([block])), null);
}
const generatedHint = hintBlock('Generated'); generatedHint.generated = '"extra"';
assert.equal(editorHint(hintHost([generatedHint])), null);
const secureHint = hintBlock('Never expose hint'); secureHint.secure = true;
Object.defineProperty(secureHint, 'childNodes', { get() { throw Error('Secure hint content acquired'); } });
const secretHost = hintHost([secureHint]);
const hintQuerySelector = Element.prototype.querySelector;
Element.prototype.querySelector = function(selector) { return this === secretHost ? secureHint : hintQuerySelector.call(this, selector); };
Object.defineProperty(secretHost, 'innerText', { get() { throw Error('Secure editor value acquired for hint'); } });
Object.defineProperty(secretHost, 'textContent', { get() { throw Error('Secure editor text acquired for hint'); } });
for (const bounded of [false, true]) {
  const result = read.call(secretHost, 'data-testid', '.secure', bounded, false, true);
  assert.equal(result.editorPlaceholder, null); assert.equal(result.value, null);
  assert.equal(JSON.stringify(result).includes('Never expose hint'), false);
}
Element.prototype.querySelector = hintQuerySelector;
const nativeSecretHost = hintHost([hintBlock('Native protected hint')]);
Object.defineProperty(nativeSecretHost, 'innerText', { get() { throw Error('Native protected editor value acquired'); } });
Object.defineProperty(nativeSecretHost, 'textContent', { get() { throw Error('Native protected editor text acquired'); } });
for (const bounded of [false, true]) assert.equal(editorHint(nativeSecretHost, bounded, true), null);
for (const oversized of [hintHost([], { 'data-placeholder': 'x'.repeat(513) }), hintHost([hintBlock('x'.repeat(513))]), hintHost([hintBlock('Long content', [new Text('x'.repeat(513), null)])]), hintHost(Array.from({ length: 513 }, () => namingElement('br')))]) {
  assert.equal(editorHint(oversized), null);
}
let deepHint = hintBlock('Too deep'); for (let i = 0; i < 65; i++) deepHint = namingElement('div', [deepHint]);
assert.equal(editorHint(hintHost([deepHint])), null);
// Candidate emptiness must not call textContent, innerText, or value getters.
const scalarTrap = hintBlock('Public hint', [namingElement('br')]);
for (const field of ['textContent', 'innerText', 'value']) Object.defineProperty(scalarTrap, field, { get() { throw Error(`Hint proof read ${field}`); } });
assert.equal(editorHint(hintHost([scalarTrap])).name, 'Public hint');
document.defaultView.getComputedStyle = editorHintStyle;
console.log('PASS: editor hints preserve host persistence, first empty descendant order, priority and role gates without acquiring hidden or secret emptiness/value data');

// The SVG exception is one closed link-content shape, not removal of any
// existing SVG rejection or permission to name an SVG's independent role.
class PlainSvgTitle extends Element { constructor() { super(); this.localName = 'title'; } }
global.SVGTitleElement = PlainSvgTitle;
const restrictedSvgStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
function svgTitleLink(svgAttrs = { width: '10', height: '10', role: 'none' }, linkAttrs = { href: '/home', 'data-testid': 'home' }) {
  const title = attributes(new PlainSvgTitle(), {}); title.childNodes = [new Text('  Home\n', title)];
  const svg = attributes(new EmptySvg(), svgAttrs); svg.childNodes = [title]; title.parentElement = svg;
  const link = namingElement('a', [svg], linkAttrs); return { link, svg, title };
}
const svgLinkFact = (node, bounded = false, protectedEditor = false, inventory = true) => read.call(node, 'data-testid', '.secure', bounded, protectedEditor, inventory).restrictedSvgLinkName;
for (const role of [null, 'none', 'presentation']) {
  const { link, svg, title } = svgTitleLink(role === null ? {} : { role });
  for (const bounded of [false, true]) assert.deepEqual(svgLinkFact(link, bounded), { source: 'svg-title', name: 'Home' });
  assert.equal(svgLinkFact(svg), null); assert.equal(svgLinkFact(title), null);
  link.childNodes = [new Text('\n ', link), svg, new Text('\t', link)];
  svg.childNodes = [new Text(' ', svg), title, new Text('\n', svg)];
  assert.equal(svgLinkFact(link).name, 'Home');
  attributes(link, { href: '/home', title: 'Lower priority', role: 'link' }); assert.equal(svgLinkFact(link).name, 'Home');
}
const originalSvgShape = svgTitleLink();
assert.equal(svgLinkFact(originalSvgShape.link, false, false, false), null);
assert.equal(svgLinkFact(originalSvgShape.link, false, true), null);
for (const attrs of [{ 'aria-label': '' }, { 'aria-label': 'Own name' }, { 'aria-labelledby': 'label' }, { role: 'button' }, { role: 'none' }, { 'aria-hidden': 'true' }, { 'aria-describedby': 'description' }, { onclick: '' }]) {
  const { link } = svgTitleLink(undefined, { href: '/home', ...attrs }); assert.equal(svgLinkFact(link), null);
}
const noHref = svgTitleLink(undefined, {}); assert.equal(svgLinkFact(noHref.link), null);
for (const attr of ['title', 'alt', 'aria-label', 'aria-labelledby', 'aria-describedby', 'tabindex', 'unknown']) {
  const { link, svg } = svgTitleLink(); attributes(svg, { [attr]: 'Unsupported' }); assert.equal(svgLinkFact(link), null);
}
for (const role of ['img', 'button', 'none presentation']) {
  const { link } = svgTitleLink({ role }); assert.equal(svgLinkFact(link), null);
}
for (const target of ['link', 'svg']) {
  for (const flag of ['secure', 'shadow', 'display', 'visibility', 'generated', 'aria']) {
    const shape = svgTitleLink(); const node = shape[target];
    if (flag === 'secure') node.secure = true;
    if (flag === 'shadow') node.shadowRoot = {};
    if (flag === 'display') node.nameDisplay = 'none';
    if (flag === 'visibility') node.nameVisibility = 'hidden';
    if (flag === 'generated') node.generated = '"extra"';
    if (flag === 'aria') attributes(node, { ...(target === 'link' ? { href: '/home' } : {}), 'aria-hidden': 'true' });
    assert.equal(svgLinkFact(shape.link), null);
  }
}
const secureTitleShape = svgTitleLink(); secureTitleShape.title.secure = true;
Object.defineProperty(secureTitleShape.title, 'childNodes', { get() { throw Error('Secure SVG title acquired'); } });
assert.equal(svgLinkFact(secureTitleShape.link), null);
for (const target of ['link', 'svg']) {
  const shape = svgTitleLink(); shape[target].childNodes.push(namingElement('path')); assert.equal(svgLinkFact(shape.link), null);
  const mixed = svgTitleLink(); mixed[target].childNodes.unshift(new Text('Extra', mixed[target])); assert.equal(svgLinkFact(mixed.link), null);
  const overflow = svgTitleLink(); overflow[target].childNodes = Array.from({ length: 33 }, () => new Text(' ', overflow[target])); assert.equal(svgLinkFact(overflow.link), null);
}
const nestedTitleShape = svgTitleLink(); nestedTitleShape.svg.childNodes = [namingElement('g', [nestedTitleShape.title])];
assert.equal(svgLinkFact(nestedTitleShape.link), null);
const nestedTitleText = svgTitleLink(); nestedTitleText.title.childNodes = [namingElement('span', [new Text('Home', null)])];
assert.equal(svgLinkFact(nestedTitleText.link), null);
for (const text of ['', ' \t', 'x'.repeat(513)]) {
  const shape = svgTitleLink(); shape.title.childNodes = [new Text(text, shape.title)]; assert.equal(svgLinkFact(shape.link), null);
}
for (const attrs of [{ style: 'display:none' }, { 'aria-label': 'Alternative' }, { role: 'none' }]) {
  const shape = svgTitleLink(); attributes(shape.title, attrs); assert.equal(svgLinkFact(shape.link), null);
}
const hugeAttrs = svgTitleLink(); attributes(hugeAttrs.svg, Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`attr${i}`, ''])));
assert.equal(svgLinkFact(hugeAttrs.link), null);
const oversizedAttribute = svgTitleLink({ width: 'x'.repeat(513) }); assert.equal(svgLinkFact(oversizedAttribute.link), null);
const noContentRead = svgTitleLink();
for (const node of [noContentRead.svg, noContentRead.title]) for (const field of ['textContent', 'innerText']) Object.defineProperty(node, field, { get() { throw Error(`SVG proof read ${field}`); } });
assert.equal(svgLinkFact(noContentRead.link).name, 'Home');
document.defaultView.getComputedStyle = restrictedSvgStyle;
console.log('PASS: restricted SVG-title link facts accept only the whitelisted complete shape and preserve label, security, hidden, shadow, geometry and budget exclusions');


// Original name-content traversal preserves block/BR separators even when the
// child's content is hidden. Caption completion must not misprove A + C as AC.
const hiddenCaptionStyle = document.defaultView.getComputedStyle;
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: 'none' });
for (const [tag, source] of [['fieldset', 'legend'], ['figure', 'figcaption'], ['table', 'caption']]) {
  for (const hiddenTag of ['div', 'br', 'span']) {
    for (const hidden of ['aria', 'display', 'visibility']) {
      const skipped = namingElement(hiddenTag); skipped.nameDisplay = hiddenTag === 'div' ? 'block' : 'inline';
      if (hidden === 'aria') attributes(skipped, { 'aria-hidden': 'true' });
      if (hidden === 'display') skipped.nameDisplay = 'none';
      if (hidden === 'visibility') skipped.nameVisibility = 'hidden';
      Object.defineProperty(skipped, 'childNodes', { get() { throw Error('Hidden caption descendant acquired'); } });
      const caption = namingElement(source, [new Text('A', null), skipped, new Text('C', null)]);
      const parent = namingElement(tag, [caption]);
      for (const bounded of [false, true]) assert.equal(captionFacts(parent, bounded), null, `${tag}/${hiddenTag}/${hidden}`);
      // Root-hidden is a different, complete empty contribution and still
      // falls through without traversing any of these hidden descendants.
      caption.nameDisplay = 'none';
      assert.deepEqual(captionFacts(parent), { source, name: '' });
    }
  }
}
document.defaultView.getComputedStyle = hiddenCaptionStyle;
console.log('PASS: caption-only hidden descendants are unavailable, not false AC/empty proofs; hidden roots remain proven empty without content acquisition');

// Execute the production acquisition function, with native-shaped handles.
// The inventory supplies closed roots; the function must not rediscover them
// through author properties or descend into browser implementation roots.
{
  const vm = require('node:vm');
  const inventorySource = source.match(/const SECURITY_INVENTORY: &str = r#"([\s\S]*?)"#;/)[1];
  class NativeNode {
    constructor(doc, root) { this.doc = doc; this.root = root; this.connected = true; this.parentElement = null; this.secureNodes = []; }
    get isConnected() { return this.connected; }
    get ownerDocument() { return this.doc; }
    getRootNode() { return this.root; }
    querySelectorAll() { return this.secureNodes; }
  }
  class NativeDocument extends NativeNode {
    constructor() { super(null, null); this.nodeType = 9; this.root = this; this.active = null; }
    get activeElement() { return this.active; }
  }
  class NativeElement extends NativeNode {
    constructor(doc, root) { super(doc, root); this.nodeType = 1; }
  }
  class NativeShadowRoot extends NativeNode {
    constructor(host, mode) { super(host.doc, null); this.nodeType = 11; this.root = this; this.nativeHost = host; this.mode = mode; this.active = null; }
    get activeElement() { return this.active; }
    get host() { return this.nativeHost; }
  }
  const doc = new NativeDocument();
  const inventory = vm.runInNewContext(`(${inventorySource})`, {
    Node: NativeNode, Document: NativeDocument, ShadowRoot: NativeShadowRoot, document: doc,
  });
  for (const outerMode of ['open', 'closed']) for (const innerMode of ['open', 'closed']) {
    const outerHost = new NativeElement(doc, doc);
    const outerRoot = new NativeShadowRoot(outerHost, outerMode);
    const innerHost = new NativeElement(doc, outerRoot);
    const innerRoot = new NativeShadowRoot(innerHost, innerMode);
    const leaf = new NativeElement(doc, innerRoot);
    const pin = new NativeElement(doc, outerRoot);
    doc.active = outerHost; outerRoot.active = innerHost; innerRoot.active = leaf;
    // Own author getters must not shadow the isolated intrinsic accessors.
    for (const [target, key] of [[doc, 'activeElement'], [outerRoot, 'activeElement'], [innerRoot, 'host'], [outerHost, 'shadowRoot']]) {
      Object.defineProperty(target, key, { configurable: true, get() { throw Error('Author getter executed'); } });
    }
    const roots = [innerRoot, doc, outerRoot];
    let facts = inventory('.secure', roots.map(() => true), ...roots);
    assert.equal(facts.focused, leaf, `${outerMode}/${innerMode}`);
    assert.equal([outerHost, innerHost, pin, leaf].filter(node => node === facts.focused).length, 1);
    outerRoot.active = pin;
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).focused, pin);
    outerRoot.active = null;
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).focused, outerHost);
    outerRoot.active = innerHost; innerRoot.active = leaf;
    leaf.connected = false;
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).__nativeStatus, 'stale-reference');
    leaf.connected = true; innerRoot.connected = false;
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).__nativeStatus, 'stale-reference');
    innerRoot.connected = true; leaf.doc = new NativeDocument();
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).__nativeStatus, 'stale-reference');
    leaf.doc = doc; leaf.root = outerRoot;
    assert.equal(inventory('.secure', roots.map(() => true), ...roots).__nativeStatus, 'stale-reference');
    delete doc.activeElement;
  }
  const control = new NativeElement(doc, doc);
  const internal = new NativeShadowRoot(control, 'user-agent');
  const implementationLeaf = new NativeElement(doc, internal);
  internal.active = implementationLeaf; doc.active = control;
  // Internal roots keep their security contribution, but cannot steal focus.
  internal.secureNodes = [implementationLeaf];
  let facts = inventory('.secure', [true, false], doc, internal);
  assert.equal(facts.focused, control);
  assert.equal(facts.includes(implementationLeaf), true);
  assert.equal(facts.includes(control), true);
  doc.active = null;
  assert.equal(inventory('.secure', [true], doc).focused, null);
  assert.equal(inventory('.secure', [], doc).__nativeStatus, 'invalid-native-metadata');
  assert.equal(inventory('.secure', [true, true], doc, doc).__nativeStatus, 'invalid-native-metadata');
  assert.equal(inventory('.secure', [true], internal).__nativeStatus, 'invalid-native-metadata');
  const duplicateHostRoot = new NativeShadowRoot(control, 'closed');
  assert.equal(inventory('.secure', [true, true, true], doc, internal, duplicateHostRoot).__nativeStatus, 'invalid-native-metadata');
  const foreignRoot = new NativeShadowRoot(new NativeElement(new NativeDocument(), null), 'closed');
  assert.equal(inventory('.secure', [true, true], doc, foreignRoot).__nativeStatus, 'stale-reference');
  assert.equal(inventory('.secure', Array(10001).fill(true), ...Array(10001).fill(doc)).__nativeStatus, 'resource-limit');
  for (const length of [256, 257]) {
    let scope = doc; const roots = [doc]; let leaf;
    for (let index = 0; index < length; index++) {
      leaf = new NativeElement(doc, scope); scope.active = leaf;
      if (index + 1 < length) { scope = new NativeShadowRoot(leaf, 'closed'); roots.push(scope); }
    }
    const facts = inventory('.secure', roots.map(() => true), ...roots);
    if (length === 256) assert.equal(facts.focused, leaf);
    else assert.equal(facts.__nativeStatus, 'resource-limit');
  }
}
console.log('PASS: shared native root acquisition follows one bounded author focus leaf across open/closed roots, excludes UA focus, and refuses invalid native handles');

// Focus flags are supplied by native backend equality for this acquisition.
// Both full reads and bounded observations gate selection on that same flag.
{
  Node.prototype.contains = function (node) { return node === this || this.childNodes.includes(node); };
  const selected = new InputControl('text', false);
  selected.value = 'release approved'; selected.selectionStart = 8; selected.selectionEnd = 16;
  for (const bounded of [false, true]) {
    let facts = read.call(selected, 'data-testid', '.secure', bounded, false, false, true);
    assert.equal(facts.states.focused, true); assert.equal(facts.selection, 'approved');
    facts = read.call(selected, 'data-testid', '.secure', bounded, false, false, false);
    assert.equal(facts.states.focused, false); assert.equal(facts.selection, null);
    selected.selectionEnd = 8;
    assert.equal(read.call(selected, 'data-testid', '.secure', bounded, false, false, true).selection, null);
    selected.selectionEnd = 16; selected.secure = true;
    facts = read.call(selected, 'data-testid', '.secure', bounded, false, false, true);
    assert.equal(facts.states.focused, true); assert.equal(facts.states.secure, true);
    assert.equal(facts.selection, null); assert.equal(facts.value, null);
    selected.secure = false;
  }
  const host = new Element(); host.isContentEditable = true; host.innerText = 'release approved'; host.textContent = host.innerText;
  const inside = new Text('release approved', null); host.childNodes = [inside]; inside.parentElement = host;
  let common = inside; let collapsed = false; let ranges = 1;
  document.getSelection = () => ({ rangeCount: ranges, isCollapsed: collapsed, getRangeAt: () => ({ commonAncestorContainer: common }), toString: () => 'approved' });
  for (const bounded of [false, true]) {
    const facts = () => read.call(host, 'data-testid', '.secure', bounded, false, false, true);
    assert.equal(facts().selection, 'approved');
    common = new Text('unrelated private selection', null);
    assert.equal(facts().selection, null);
    common = inside; collapsed = true;
    assert.equal(facts().selection, null);
    collapsed = false; ranges = 0;
    assert.equal(facts().selection, null);
    ranges = 1;
    assert.equal(read.call(host, 'data-testid', '.secure', bounded, false, false, false).selection, null);
    assert.equal(read.call(host, 'data-testid', '.secure', bounded, true, false, true).selection, null);
    host.secure = true;
    assert.equal(facts().selection, null);
    host.secure = false;
  }
}
console.log('PASS: shared metadata keeps focus and selection aligned, withholding secure, collapsed, unfocused, and outside-editor selections');

// td keeps the enclosing table's authored role as a private scalar; Rust uses
// the same concrete-token parser as the receiver, not substring matching.
for (const role of [null, '', 'grid', 'treegrid', 'unknown grid', 'region grid', 'unknown\u00a0grid']) {
  const cell = new Element(); cell.localName = 'td'; cell.innerText = '';
  cell.closest = selector => { assert.equal(selector, 'table'); return { getAttribute: name => { assert.equal(name, 'role'); return role; } }; };
  for (const bounded of [false, true]) assert.equal(read.call(cell, 'data-testid', '.secure', bounded).cellTableRole, role);
}
const detachedCell = new Element(); detachedCell.localName = 'td'; detachedCell.closest = () => null;
assert.equal(read.call(detachedCell, 'data-testid', '.secure', true).cellTableRole, null);
console.log('PASS: public table-cell role facts preserve first-token source and no-table absence');

// CI18: the same bounded content proof handles the five heading receivers,
// preserving the intentional alert-content exception rather than axe's value.
Node.prototype.contains = function(other) { return this === other || this.childNodes?.some(child => Node.prototype.contains.call(child, other)) || false; };
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
const heading = wrapper(); heading.localName = 'h2';
const input = attributes(new InputControl('text', false), { 'aria-labelledby': 't1label', 'aria-label': 'ARIA Label' }); input.value = 'the value';
const reference = wrapper([new Text('This is a ', null), wrapper([new Text('label', null)])]); reference.localName = 'div';
const priorLookup = document.getElementById;
document.getElementById = id => id === 't1label' ? reference : null;
const headingFact = (inventory = true) => read.call(heading, 'data-testid', '.secure', true, false, inventory).completeContentNameFact;
for (const [content, attrs, suffix] of [[[], { title: 'italics' }, ' italics'], [[], {}, ''], [[new Text('everything', null)], {role:'alert'}, ' everything'], [[new Text('everything', null)], {}, ' everything']]) {
  const child = wrapper(content, attrs); child.localName = 'i';
  heading.childNodes = [new Text('This is ', heading), input, new Text(' of ', heading), child];
  assert.deepEqual(headingFact(), { source: 'heading', name: 'This is This is a label of' + suffix });
}
assert.equal(headingFact(false), null);
attributes(input, {}); input.value = ''; input.labels = [wrapper([new Text('My form input', null)])];
heading.childNodes = [input]; assert.deepEqual(headingFact(), { source: 'heading', name: '' });
for (const type of ['password', 'number', 'file']) { input.type = type; assert.equal(headingFact(), null); }
input.type = 'text'; input.secure = true;
Object.defineProperty(input, 'value', { configurable: true, get() { throw Error('Secure value read'); } });
assert.equal(headingFact(), null); input.secure = false;
Object.defineProperty(input, 'value', { configurable: true, writable: true, value: 'value' });
attributes(input, { 'aria-labelledby': 't1label' }); reference.nameDisplay = 'none';
assert.equal(headingFact(), null); delete reference.nameDisplay;
reference.childNodes.push(Object.assign(wrapper([new Text('Hidden', null)]), { nameDisplay: 'none' }));
assert.equal(headingFact(), null); reference.childNodes.pop();
attributes(input, { 'aria-labelledby': 't1label t1label' }); assert.equal(headingFact(), null);
attributes(input, { 'aria-labelledby': 't1label' }); input.generated = '"generated"'; assert.equal(headingFact(), null); delete input.generated;
attributes(heading, { 'aria-label': 'Explicit' }); assert.equal(headingFact(), null); attributes(heading, {});
heading.childNodes = [new Text('x'.repeat(513), heading)]; assert.equal(headingFact(), null);
document.getElementById = priorLookup;
for (const role of ['alert', 'status']) {
  const notice = wrapper([new Text('Application notice', null)], {role});
  const noticeFact = local => read.call(notice, 'data-testid', '.secure', true, false, false, false, local).completeContentNameFact;
  assert.equal(noticeFact(false), null);
  assert.deepEqual(noticeFact(true), {source: role, name:'Application notice'});
  notice.shadowRoot = {}; assert.equal(noticeFact(true), null); delete notice.shadowRoot;
  attributes(notice, { role, 'aria-label':'Explicit' }); assert.equal(noticeFact(true), null);
}
const announcer = wrapper(); announcer.localName = 'next-route-announcer';
const priorMatches = Element.prototype.matches;
Element.prototype.matches = function(selector) { return selector.split(',').includes(this.localName) || priorMatches.call(this, selector); };
assert.equal(read.call(announcer, 'data-testid', '.secure', true).author.suppress, true);
Element.prototype.matches = priorMatches;
document.defaultView.getComputedStyle = nameStyle;
console.log('PASS: bounded heading names preserve alert content and empty values; local alert/status proof, explicit/security/hidden/budget negatives and announcer suppression');

// Compatibility repairs read the actual shared producer. They do not replace
// AX globally and cannot claim that an unavailable proof was complete/empty.
const publicNameStyle = document.defaultView.getComputedStyle;
const publicNameLookup = document.getElementById;
document.defaultView.getComputedStyle = (node, pseudo) => css({ display: node.nameDisplay || 'inline', visibility: node.nameVisibility || 'visible', contentVisibility: node.nameContentVisibility || 'visible', content: pseudo ? node.generated || 'none' : 'none' });
const publicFact = (node, bounded = false, inventory = true, protectedEditor = false) => read.call(node, 'data-testid', '.secure', bounded, protectedEditor, inventory).completePublicButtonNameFact;
function publicButton(children, attrs = {}) {
  const node = attributes(new ButtonControl(), attrs); node.childNodes = children;
  for (const child of children) child.parentElement = node;
  return node;
}
for (const bounded of [false, true]) {
  const image = namingElement('img', [], { alt: 'Search' });
  const mixed = publicButton([image, new Text('Go', null)]);
  assert.deepEqual(publicFact(mixed, bounded), { source: 'content', name: 'SearchGo' });
  for (const display of ['block', 'inline-block', 'inline-flex', 'contents']) {
    image.nameDisplay = display;
    assert.equal(publicFact(mixed, bounded).name, 'Search Go');
  }
  delete image.nameDisplay;
  // The promised selector algorithm retains non-inline raw boundaries even
  // when a hidden node contributes empty text; hidden inline adds none.
  const hiddenImage = namingElement('img', [], { alt: 'Hidden', 'aria-hidden': 'true' });
  const around = publicButton([namingElement('img', [], { alt: 'A' }), hiddenImage, new Text('B', null)]);
  assert.equal(publicFact(around, bounded).name, 'AB');
  hiddenImage.nameDisplay = 'none'; assert.equal(publicFact(around, bounded).name, 'A B');
  const emptyBlock = namingElement('span'); emptyBlock.nameDisplay = 'block';
  const rawBoundary = publicButton([namingElement('img', [], { alt: 'A' }), emptyBlock, new Text('B', null)]);
  assert.equal(publicFact(rawBoundary, bounded).name, 'A B');
  const title = namingElement('title', [new Text('Close', null)]); title.nameDisplay = 'none';
  const svg = namingElement('svg', [title], { 'aria-labelledby': 'svg-title' });
  document.getElementById = id => id === 'svg-title' ? title : null;
  const icon = publicButton([svg, new Text('Icon', null)]);
  assert.equal(publicFact(icon, bounded).name, 'CloseIcon');
  svg.nameDisplay = 'block'; assert.equal(publicFact(icon, bounded).name, 'Close Icon');
  delete svg.nameDisplay; attributes(svg, {}); assert.equal(publicFact(icon, bounded).name, 'CloseIcon');

  const range = attributes(new InputControl('range', false), {});
  Object.defineProperty(range, 'value', { get() { throw Error('Default range property must not enter a containing name'); } });
  const control = namingElement('div', [new Text('Volume ', null), range, new Text(' end', null)], { role: 'button' });
  assert.equal(publicFact(control, bounded).name, 'Volume end');
  for (const [attrs, name] of [[{ value: '4' }, 'Volume 4 end'], [{ value: '4', 'aria-valuenow': '6' }, 'Volume 6 end'], [{ value: '4', 'aria-valuenow': '6', 'aria-valuetext': 'loud' }, 'Volume loud end'], [{ value: '4', 'aria-valuetext': '' }, 'Volume end']]) {
    attributes(range, attrs); assert.equal(publicFact(control, bounded).name, name);
  }

  const gone = namingElement('i', [new Text('gone', null)]); gone.nameDisplay = 'none';
  const shown = namingElement('span', [new Text('Shown ', null), gone]);
  const receiver = publicButton([new Text('Ignored', null)], { 'aria-labelledby': 'shown', 'aria-label': 'Lower priority' });
  document.getElementById = id => id === 'shown' ? shown : null;
  assert.deepEqual(publicFact(receiver, bounded), { source: 'reference', name: 'Shown' });
  const ancestor = namingElement('div', [shown], { 'aria-hidden': 'TRUE' });
  assert.equal(publicFact(receiver, bounded).name, 'Shown gone');
  attributes(ancestor, {});
  attributes(shown, { 'aria-label': 'Own label' }); assert.equal(publicFact(receiver, bounded).name, 'Own label');

  const a = namingElement('span', [new Text('A', null)], { 'aria-labelledby': 'b' });
  const b = namingElement('span', [new Text('B', null)], { 'aria-labelledby': 'a' });
  document.getElementById = id => id === 'a' ? a : id === 'b' ? b : null;
  assert.equal(publicFact(publicButton([a, b]), bounded).name, 'B');
  const nested = namingElement('span', [new Text('Ref text', null)], { 'aria-labelledby': 'b' });
  const outer = namingElement('span', [nested]);
  document.getElementById = id => id === 'outer' ? outer : id === 'b' ? b : null;
  assert.equal(publicFact(publicButton([], { 'aria-labelledby': 'outer' }), bounded).name, 'Ref text');
  const owner = publicButton([namingElement('span', [new Text('A', null)], { 'aria-labelledby': 'owner' }), new Text('B', null)]);
  document.getElementById = id => id === 'owner' ? owner : null;
  assert.equal(publicFact(owner, bounded).name, 'AB');
}
const available = () => publicButton([namingElement('img', [], { alt: 'Search' }), new Text('Go', null)]);
assert.equal(publicFact(available(), false, false), null);
assert.equal(publicFact(available(), false, true, true), null);
for (const attrs of [{ role: 'link' }, { 'aria-label': 'Higher priority' }, { 'aria-labelledby': 'missing' }, { 'aria-owns': 'other' }, { contenteditable: 'false' }]) {
  const node = available(); attributes(node, attrs); assert.equal(publicFact(node), null);
}
for (const target of ['root', 'child']) {
  for (const state of ['secure', 'shadow', 'generated']) {
    const node = available(), subject = target === 'root' ? node : node.childNodes[0];
    if (state === 'secure') subject.secure = true;
    if (state === 'shadow') subject.shadowRoot = {};
    if (state === 'generated') subject.generated = '"extra"';
    assert.equal(publicFact(node), null);
  }
}
const secret = namingElement('span'); secret.secure = true;
Object.defineProperty(secret, 'childNodes', { get() { throw Error('Secret referenced content must not be acquired'); } });
document.getElementById = () => secret;
assert.equal(publicFact(publicButton([], { 'aria-labelledby': 'secret' })), null);
for (const tag of ['textarea', 'select', 'slot', 'canvas', 'math', 'custom-element']) {
  assert.equal(publicFact(publicButton([namingElement(tag)])), null);
}
assert.equal(publicFact(publicButton([namingElement('img', [], { alt: 'x'.repeat(513) })])), null);
assert.equal(publicFact(publicButton(Array.from({ length: 513 }, () => new Text('', null)))), null);
let nestedPublic = namingElement('img', [], { alt: 'Deep' });
for (let i = 0; i < 65; i++) nestedPublic = namingElement('span', [nestedPublic]);
assert.equal(publicFact(publicButton([nestedPublic])), null);
const foreign = publicButton([], { 'aria-labelledby': 'foreign' }); foreign.nativeRoot = { host: new Element() };
assert.equal(publicFact(foreign), null);
// Zero-area, content skipping and closed details must not be silently treated
// as ordinary visible IDREFs. A visible child may override ancestor visibility.
for (const shape of ['zero-area', 'contents', 'skipped', 'auto-skipped-positive-box', 'closed-details', 'visible-override']) {
  const target = namingElement('span', [new Text('Shown ', null), namingElement('i', [new Text('Hidden', null)])]);
  target.childNodes[1].nameDisplay = 'none';
  const parent = namingElement('div', [target]);
  if (shape === 'zero-area' || shape === 'contents') target.getBoundingClientRect = () => ({ x: 0, y: 0, width: 0, height: 0 });
  if (shape === 'contents') target.nameDisplay = 'contents';
  if (shape === 'skipped') parent.nameContentVisibility = 'hidden';
  if (shape === 'auto-skipped-positive-box') parent.nameContentVisibility = 'auto';
  if (shape === 'closed-details') { parent.localName = 'details'; parent.open = false; }
  if (shape === 'visible-override') parent.nameVisibility = 'hidden';
  document.getElementById = () => target;
  assert.equal(publicFact(publicButton([], { 'aria-labelledby': 'target' })), null, shape);
}
// SVGTitleElement is non-rendered native metadata even when its computed
// style is inline/visible. The prior fixture's forced display:none hid this
// distinction from the real Chromium producer path.
const zeroBox = () => ({ x: 0, y: 0, width: 0, height: 0 });
function nonRenderedSvgTitle(title = attributes(new PlainSvgTitle(), {}), svg = attributes(new EmptySvg(), {})) {
  title.childNodes = [new Text('Close', title)]; title.getBoundingClientRect = zeroBox;
  svg.childNodes = [title]; title.parentElement = svg;
  attributes(svg, { 'aria-labelledby': 'non-rendered-title' });
  document.getElementById = id => id === 'non-rendered-title' ? title : null;
  return { title, svg, button: publicButton([svg, new Text('Icon', null)]) };
}
for (const bounded of [false, true]) {
  const shape = nonRenderedSvgTitle();
  assert.deepEqual(publicFact(shape.button, bounded), { source: 'content', name: 'CloseIcon' });
  shape.svg.nameDisplay = 'block'; assert.equal(publicFact(shape.button, bounded).name, 'Close Icon');
  delete shape.svg.nameDisplay;
  for (const visibility of ['hidden', 'auto']) {
    shape.svg.nameContentVisibility = visibility;
    assert.equal(publicFact(shape.button, bounded), null);
  }
  delete shape.svg.nameContentVisibility;
  shape.title.secure = true;
  Object.defineProperty(shape.title, 'childNodes', { get() { throw Error('Secure SVG title content acquired'); } });
  assert.equal(publicFact(shape.button, bounded), null);
}
// Same localName/zero box is not enough: retain ordinary HTML title, span and
// wrong-parent refusals. Only native SVG element interfaces establish shape.
for (const target of [namingElement('title'), namingElement('span')]) {
  const shape = nonRenderedSvgTitle(target);
  assert.equal(publicFact(shape.button), null);
}
const wrongParent = nonRenderedSvgTitle(attributes(new PlainSvgTitle(), {}), namingElement('div'));
assert.equal(publicFact(wrongParent.button), null);
console.log('PASS: non-rendered native SVG title IDREFs preserve inline/block naming without admitting arbitrary zero-box targets, skipped content or secure text');
console.log('PASS: actual bounded public-name producer preserves inline/block alternatives, authored range priority, visible/hidden references and cycles; refuses unproven inventory, secure, shadow, generated, unsupported and oversized shapes');

for (const bounded of [false, true]) {
  const th = namingElement('th'); th.parentElement = namingElement('tr'); th.parentElement.closest = () => ({ rows: [1] });
  th.previousElementSibling = null; th.nextElementSibling = namingElement('th');
  let metadata = read.call(th, 'data-testid', '.secure', bounded);
  assert.equal(metadata.presentationConflict, false);
  assert.equal(metadata.conflictHeaderRole, 'columnheader');
  th.nextElementSibling = namingElement('td', [new Text('42', null)]); th.nextElementSibling.children = [];
  assert.equal(read.call(th, 'data-testid', '.secure', bounded).conflictHeaderRole, 'rowheader');
  th.nextElementSibling = namingElement('td', [new Text(' \t', null)]); th.nextElementSibling.children = [];
  assert.equal(read.call(th, 'data-testid', '.secure', bounded).conflictHeaderRole, 'columnheader');
  for (const scope of ['row', 'rowgroup', 'col', 'colgroup']) {
    attributes(th, { scope }); assert.equal(read.call(th, 'data-testid', '.secure', bounded).conflictHeaderRole, null);
  }
}
document.defaultView.getComputedStyle = publicNameStyle;
document.getElementById = publicNameLookup;
console.log('PASS: normal th metadata uses bounded immediate neighbors without requiring a presentation conflict, while explicit scope remains authoritative');
