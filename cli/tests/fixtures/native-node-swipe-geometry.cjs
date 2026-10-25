// Scripted DOM for the actual native-emitted preparation functions, not Chrome.
const assert = require('node:assert/strict');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const box = { x: input.offscreen ? 1600 : 0, y: 0, width: 400, height: 300 };
let rectReads = 0;
const document = {};
const node = {
  tagName: 'DIV', isConnected: true, ownerDocument: document,
  getBoundingClientRect() { rectReads++; return { ...box, right: box.x + 400, bottom: 300 }; },
  getClientRects() { return [this.getBoundingClientRect()]; },
  getRootNode() { return document; },
  contains(other) { return other === this; },
  matches(selector) {
    if (selector === ':disabled') return false;
    if (selector === ':hover') return input.initialPointer.x >= box.x && input.initialPointer.x < box.x + 400
      && input.initialPointer.y >= 0 && input.initialPointer.y < 300;
    throw new Error(`unsupported synthetic selector ${selector}`);
  },
};
const style = { visibility: 'visible', display: 'block', pointerEvents: 'auto' };
Object.assign(globalThis, { document, getComputedStyle: () => style });
document.defaultView = globalThis;
document.elementFromPoint = (x, y) => x >= 0 && x < 1280 && y >= 0 && y < 720
  && x >= box.x && x < box.x + 400 && y < 300 ? node : null;
const args = (input.arguments || []).map(argument => argument.value);
if (args.length) assert.deepEqual(args, [200, 150, false], 'native targeting must derive the actual center');
const result = eval('(' + input.functionDeclaration + ')').apply(node, args);
assert(rectReads > 0, 'the native function must execute the supplied DOM geometry');
process.stdout.write(JSON.stringify({ result, box, rectReads, initialPointer: input.initialPointer, offscreen: input.offscreen }));
