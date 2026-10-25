// Test-only evidence selection. A detach from old history or another session
// cannot witness the page that the closed-page producer just closed.
const assert = require('node:assert/strict');

function findCurrentTargetDetach(entries, { startIndex, targetId, sessionId }) {
  assert(Number.isInteger(startIndex) && startIndex >= 0 && startIndex <= entries.length);
  assert.equal(typeof targetId, 'string');
  assert.equal(typeof sessionId, 'string');
  assert(targetId.length > 0 && sessionId.length > 0);
  for (let index = startIndex; index < entries.length; index++) {
    const entry = entries[index];
    const message = entry.message;
    if (entry.direction === 'reply' && message?.method === 'Target.detachedFromTarget'
      && message.params?.targetId === targetId && message.params?.sessionId === sessionId) return { index, entry };
  }
  return undefined;
}

module.exports = { findCurrentTargetDetach };
