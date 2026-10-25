const assert = require('node:assert/strict');
const { test } = require('node:test');
const { findCurrentTargetDetach } = require('./native-action-detach-witness.cjs');

const expected = { startIndex: 1, targetId: 'same-target', sessionId: 'current-session' };
const detach = (sessionId = 'current-session', targetId = 'same-target') => ({
  direction: 'reply', message: { method: 'Target.detachedFromTarget', params: { targetId, sessionId } },
});

test('accepts a matching current-session detach after the close boundary', () => {
  const current = detach();
  assert.deepEqual(findCurrentTargetDetach([{}, current], expected), { index: 1, entry: current });
});

test('rejects an old detach even for the same target and current session', () => {
  assert.equal(findCurrentTargetDetach([detach()], expected), undefined);
});

test('rejects a post-close detach for the same target on a different session', () => {
  assert.equal(findCurrentTargetDetach([detach(), detach('old-session')], expected), undefined);
});

test('rejects a post-close detach for a different target on the current session', () => {
  assert.equal(findCurrentTargetDetach([{}, detach('current-session', 'other-target')], expected), undefined);
});

test('selects the new exact detach rather than earlier same-target history', () => {
  const current = detach();
  const entries = [detach(), detach('old-session'), current];
  assert.deepEqual(findCurrentTargetDetach(entries, expected), { index: 2, entry: current });
});

test('rejects wrong-direction or wrong-method messages with matching identifiers', () => {
  assert.equal(findCurrentTargetDetach([{}, { ...detach(), direction: 'request' }], expected), undefined);
  assert.equal(findCurrentTargetDetach([{}, { direction: 'reply', message: { method: 'Target.attachedToTarget', params: detach().message.params } }], expected), undefined);
});

test('rejects missing session evidence and empty post-close history', () => {
  assert.equal(findCurrentTargetDetach([{}, { direction: 'reply', message: { method: 'Target.detachedFromTarget', params: { targetId: 'same-target' } } }], expected), undefined);
  assert.equal(findCurrentTargetDetach([detach()], { ...expected, startIndex: 1 }), undefined);
});

test('accepts detach after close dispatch while the independent close ACK is pending', async () => {
  const entries = [detach('old-session')];
  const boundary = Object.freeze({ ...expected, startIndex: entries.length });
  let acknowledge;
  const closeAck = new Promise(resolve => { acknowledge = resolve; });
  const current = detach();
  entries.push(current); // Native observer receives detach before control ACK.
  assert.deepEqual(findCurrentTargetDetach(entries, boundary), { index: 1, entry: current });
  acknowledge({ success: true });
  assert.equal((await closeAck).success, true);
});
