// Scripted DOM for the actual native-emitted preparation functions, not Chrome.
const assert = require('node:assert/strict');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const box = { x: input.offscreen ? 1600 : 0, y: 0, width: input.overflowDescendant ? 100 : 400, height: input.overflowDescendant ? 100 : 300 };
let rectReads = 0;
let clientRectReads = 0;
let hoverReads = 0;
const document = {};
const node = {
  tagName: 'DIV', isConnected: true, ownerDocument: document,
  getBoundingClientRect() { rectReads++; return { ...box, right: box.x + box.width, bottom: box.height }; },
  getClientRects() { clientRectReads++; return input.noClientRects ? [] : [this.getBoundingClientRect()]; },
  getRootNode() { return document; },
  contains(other) { return other === this || other === child; },
  matches(selector) {
    if (selector === ':disabled') return false;
    if (selector === ':hover') { hoverReads++; return input.currentPointer !== null
      && this.contains(document.elementFromPoint(input.currentPointer.x, input.currentPointer.y)); }
    throw new Error(`unsupported synthetic selector ${selector}`);
  },
};
const style = { visibility: 'visible', display: 'block', pointerEvents: 'auto' };
Object.assign(globalThis, { document, getComputedStyle: () => style });
globalThis.top = input.iframe ? {} : globalThis;
document.defaultView = globalThis;
const child = { tagName: 'DIV', parentNode: node, getRootNode: () => document };
const cover = { tagName: 'DIV', id: 'pointer-cover', parentNode: null, closest: () => null, getRootNode: () => document };
document.elementFromPoint = (x, y) => {
  if (input.coverPointer && x >= 60 && x < 100 && y >= 40 && y < 100) return cover;
  if (input.overflowDescendant && x >= 100 && x < 150 && y >= 0 && y < 100) return child;
  return x >= 0 && x < 1280 && y >= 0 && y < 720 && x >= box.x && x < box.x + box.width && y < box.height ? node : null;
};
const args = (input.arguments || []).map(argument => argument.value);
if (args.length === 2) assert.deepEqual(args, [input.currentPointer.x, input.currentPointer.y], 'pointer probe must use the actual submitted point');
else if (args.length) assert.deepEqual(args, [200, 150, false], 'center fallback must derive the actual center');
const result = eval('(' + input.functionDeclaration + ')').apply(node, args);
assert(rectReads > 0 || input.iframe || input.noClientRects, 'the native function must execute the supplied DOM geometry or stop at its original frame/rect gate');
process.stdout.write(JSON.stringify({ result, box, rectReads, clientRectReads, hoverReads, initialPointer: input.initialPointer, currentPointer: input.currentPointer, offscreen: input.offscreen, coverPointer: input.coverPointer }));
