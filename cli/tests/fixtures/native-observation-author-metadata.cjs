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
  assert.deepEqual(matchQuery(expression, projected, [[]], [null], target).indices, [0]);
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
