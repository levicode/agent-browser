import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

// Execute the actual embedded browser functions, not a second implementation.
// Browser integration tests separately verify trusted input and editing behavior.
const source = readFileSync(new URL('../cli/src/native/interaction.rs', import.meta.url), 'utf8');
function embedded(name) {
  const match = source.match(new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`));
  assert.ok(match, `${name} must remain testable`);
  return Function(`return (${match[1]});`)();
}
const prepareFill = embedded('PREPARE_FILL_JS');
const selectOption = embedded('SELECT_OPTION_JS');

function field({ tag = 'input', type = 'text', readonly = false, disabled = false, redirect = false } = {}) {
  const events = [];
  const selection = { removeAllRanges() {}, addRange(range) { this.range = range; } };
  class Input {
    set value(value) {
      this._value = this.type === 'date' && value !== '' && !/^\d{4}-\d{2}-\d{2}$/.test(value) ? '' : value;
    }
    get value() { return this._value; }
  }
  const doc = {
    activeElement: null,
    defaultView: { HTMLInputElement: Input },
    createElement() { return new Input(); },
    createRange() { return { selectNodeContents(node) { this.node = node; } }; },
    getSelection() { return selection; },
  };
  const node = Object.assign(new Input(), {
    localName: tag, type, isConnected: true, readOnly: readonly,
    isContentEditable: tag === 'div', ownerDocument: doc,
    matches: () => disabled, getAttribute: () => null, getClientRects: () => [{}],
    getRootNode: () => doc,
    focus() { doc.activeElement = redirect ? {} : this; },
    select() { this.wasSelected = true; },
    dispatchEvent(event) { events.push(event.type); },
  });
  node.value = 'old';
  return { node, events, selection };
}

test('normal text, textarea and number fill retain browser insertion', () => {
  for (const options of [{}, { tag: 'textarea' }, { type: 'number' }]) {
    const { node, events } = field(options);
    assert.deepEqual(prepareFill.call(node, 'new'), { insertText: true });
    assert.equal(node.value, '');
    assert.equal(node.wasSelected, true);
    assert.deepEqual(events, ['input']);
  }
});

test('contenteditable fill and clear select contents without flattening the DOM', () => {
  for (const value of ['replacement', '']) {
    const { node, events, selection } = field({ tag: 'div' });
    Object.defineProperty(node, 'textContent', { set() { throw Error('DOM overwrite'); } });
    assert.deepEqual(prepareFill.call(node, value), value === '' ? { deleteSelection: true } : { insertText: true });
    assert.equal(selection.range.node, node);
    assert.deepEqual(events, []);
  }
});

test('native-value fill is limited to validated special input types', () => {
  for (const type of ['date', 'datetime-local', 'month', 'time', 'week']) {
    const { node, events } = field({ type });
    const value = type === 'date' ? '2026-10-20' : 'valid-for-fixture';
    assert.deepEqual(prepareFill.call(node, value), { nativeValue: true });
    assert.equal(node.value, value);
    assert.deepEqual(events, ['input', 'change']);
  }
  const { node, events } = field({ type: 'date' });
  node.value = '2026-10-20';
  assert.deepEqual(prepareFill.call(node, 'invalid'), { beforeInput: true });
  assert.equal(node.value, '2026-10-20');
  assert.equal(node.ownerDocument.activeElement, null);
  assert.deepEqual(events, []);
});

test('readonly, disabled and unsupported fill reject before effects; focus loss is uncertain', () => {
  for (const options of [{ readonly: true }, { disabled: true }, { type: 'file' }, { type: 'checkbox' }]) {
    const { node, events } = field(options);
    assert.deepEqual(prepareFill.call(node, 'new'), { beforeInput: true });
    assert.equal(node.ownerDocument.activeElement, null);
    assert.deepEqual(events, []);
  }
  const { node, events } = field({ redirect: true });
  assert.equal(prepareFill.call(node, 'new'), false);
  assert.equal(node.value, 'old');
  assert.deepEqual(events, []);
});

function select(options, multiple = true) {
  const events = [];
  return {
    localName: 'select', isConnected: true, multiple,
    matches: () => false,
    options: options.map(([value, label, disabled = false]) => ({ value, label, textContent: label, disabled, selected: false })),
    dispatchEvent(event) { events.push(event.type); }, events,
  };
}

test('auto select preserves upstream trim, zero-width and whitespace normalization', () => {
  const node = select([['a', 'One\u00a0A'], ['b', 'Zero\u200bWidth'], ['c', '  padded  ']]);
  for (const [query, index] of [['One A', 0], ['ZeroWidth', 1], ['padded', 2]]) {
    assert.deepEqual(selectOption.call(node, [query], 'auto'), { matched: 1 });
    assert.equal(node.options[index].selected, true);
  }
  assert.deepEqual(node.events, ['change', 'change', 'change']);
});

test('explicit select kinds are unique and exact; auto retains upstream direct-match behavior', () => {
  const node = select([['a', 'Same'], ['b', 'Same'], ['c', ' Other ']]);
  assert.deepEqual(selectOption.call(node, ['Same'], 'auto'), { matched: 2 });
  const previous = node.options.map(option => option.selected);
  assert.deepEqual(selectOption.call(node, ['Same'], 'label'), { error: 'e2e_not_actionable', beforeInput: true });
  assert.deepEqual(selectOption.call(node, ['Other'], 'label'), { error: 'e2e_not_actionable', beforeInput: true });
  assert.deepEqual(node.options.map(option => option.selected), previous);
  assert.deepEqual(selectOption.call(node, ['b'], 'value'), { matched: 1 });
  assert.equal(node.options[1].selected, true);
  assert.deepEqual(selectOption.call(node, ['2'], 'index'), { matched: 1 });
  assert.equal(node.options[2].selected, true);
  assert.deepEqual(node.events, ['change', 'input', 'change', 'input', 'change']);
});

test('missing, normalized-ambiguous and disabled exact options never partially mutate', () => {
  const node = select([['a', 'Alpha Beta'], ['b', 'Alpha\u00a0Beta'], ['c', 'Disabled', true]]);
  const initial = node.options.map(option => option.selected);
  assert.match(selectOption.call(node, ['Alpha  Beta'], 'auto').error, /Multiple options matched/);
  assert.match(selectOption.call(node, ['a', 'missing'], 'auto').error, /No option matched/);
  assert.deepEqual(selectOption.call(node, ['c'], 'value'), { error: 'e2e_not_actionable', beforeInput: true });
  assert.deepEqual(node.options.map(option => option.selected), initial);
  assert.deepEqual(node.events, []);
});
