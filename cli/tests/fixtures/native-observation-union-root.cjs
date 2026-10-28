// Root-preserving union regression matrix; explicit DOM double, NOT browser/CDP.
// Oracle portions derived from Microsoft Playwright 1.64.1 (Apache-2.0),
// packages/injected/src/{injectedScript,selectorEvaluator,domUtils}.ts.
// The fixture below retains those methods; a pinned installed bundle is required
// to verify their exact source provenance. CSS ID/tag/*/:scope is a declared
// fixture primitive, not the full Playwright CSS evaluator. No browser launches.
// Run PLAYWRIGHT_CORE_DIR=/installed/playwright-core node this-file.cjs [source.rs]
// Browser-free fixture for the bounded `visible=` chain filter.
// Run: node cli/tests/fixtures/native-observation-visible-chain.cjs It executes the
// production MATCH_QUERY realm (same extraction as the other native-observation
// fixtures) against an explicit DOM double. The double supplies the browser
// visibility primitives (computed style, checkVisibility, client rects, text
// range boxes) as fixed per-node facts, so this proves interpreter wiring only:
// body equality, document/Element roots, chain and nth order, open shadow
// traversal and the existing matcher budget. It is not a browser visibility
// proof; Chromium remains the rendering oracle.
const assert = require('node:assert/strict');
const path = require('node:path');

const fs = require('node:fs');
const crypto = require('node:crypto');
const vm = require('node:vm');
const oracleDir = process.env.PLAYWRIGHT_CORE_DIR;
assert.ok(oracleDir, 'Set PLAYWRIGHT_CORE_DIR to installed playwright-core@1.64.1');
assert.equal(JSON.parse(fs.readFileSync(path.join(oracleDir,'package.json'),'utf8')).version,'1.64.1');
const oracleBundle = fs.readFileSync(path.join(oracleDir,'lib/coreBundle.js'),'utf8');
const oracleLiteral = oracleBundle.split('\n').find(line => /^\s*source\d* = '/.test(line) && line.includes('packages/injected/src/injectedScript.ts'));
assert.ok(oracleLiteral, 'Pinned injectedScript source literal is present');
const oracleSource = vm.runInNewContext(oracleLiteral.slice(oracleLiteral.indexOf('=')+1).trim().replace(/;$/, ''), {}, {timeout:1000});
const oracleMarkers = [["function getElementComputedStyle(", "function isElementStyleVisibilityVisible(", "92074ad27da876068ea0fbeb140516fb0a8f3cb69c11a4d49496ab456d4a5686"], ["function isElementStyleVisibilityVisible(", "function isListBoxSelect(", "d2e623755033323f8dee39e40bd74854b28258882fb5c31e36f6ec7abed251e8"], ["function isListBoxSelect(", "function computeBox(", "180f735eca246b9c38179a139de15726a7d4e0c0840a8557b4d3a6c2b4ae11ee"], ["function computeBox(", "function isElementVisible(", "b3893f81a509a024c4933d3ca2d9bfc7b49a7197473b7ae4357523461d6b707d"], ["function isElementVisible(", "var kTextNodeRange", "5c79fdbf6edcf41eab7099dda343642c518069031de51dff020235baff9d8821"], ["function isVisibleTextNode(", "function elementSafeTagName(", "a33097081c01c36e105dde4b44ffa3d4ed53702a05a8a69504230eff6e360416"], ["  _createVisibleEngine() {", "  _createInternalChainEngine() {", "c4b4c079347bcaa6aef053f0fb984897021e77666b645079b25adb4c0c890bc2"], ["  _createHasEngine() {", "  _createHasNotEngine() {", "47cdf2eb44a29b21d8ed6c0c329cedda1c10722f7830aa79013e595d37bae7a9"], ["  querySelectorAll(selector, root) {", "  _queryEngineAll(part, root) {", "3d7f6f003759410bec26c8473968d303de9a36723987a9f4e2bbcf6c7cc745d9"], ["  _queryEngineAll(part, root) {", "  _createAttributeEngine(", "e7cfebe517728e2e04c5dc473c56f0d2467bbd20e487948616c1a17463298b25"], ["  _queryNth(elements, part) {", "  _queryLayoutSelector(", "e96ca011a88b68ef6a4dbba4315bf7a50361803489c2eca3013c69e534c4b0c3"], ["function sortInDOMOrder(elements) {", "// packages/injected/src/selectorGenerator.ts", "8ea80741a2431c51a98d5ce6348dfe4b51e603838c27e09bc37b5ca3083f2e80"], ["function parentElementOrShadowHost(element) {", "\nfunction ", "0787c1381baf0e4b16c8bf575c04194b2e8c6dcf565d3aae8d88f3c3419b9ef8"]];
for(const [start,end,expectedHash] of oracleMarkers){
 const begin=oracleSource.indexOf(start);assert.ok(begin>=0,start);
 const finish=oracleSource.indexOf(end,begin+start.length);assert.ok(finish>begin,end);
 assert.equal(crypto.createHash('sha256').update(oracleSource.slice(begin,finish)).digest('hex'),expectedHash,`Pinned oracle changed: ${start}`);
}

const sourcePath = process.argv[2] || path.join(__dirname, '../../src/native/client_observation.rs');
const script = require('./native-observation-script.cjs')(sourcePath, 'MATCH_QUERY');

class Node {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this._children = [];
    this.parentNode = null;
    this.box = { width: 0, height: 0 };
  }
  get childNodes() { return this._children; }
  get firstChild() { return this._children[0] || null; }
  get nextSibling() {
    const parent = this.parentNode;
    if (!parent) return null;
    const index = parent._children.indexOf(this);
    return parent._children[index + 1] || null;
  }
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
    throw new SyntaxError(`fixture DOM does not implement ${css}`);
  }
}
class Element extends Node {
  constructor(tag = 'div', id = '') {
    super(1);
    this.localName = tag;
    this.nodeName = tag.toUpperCase();
    this.attributes = new Map();
    this.shadowRoot = null;
    this.style = { display: 'block', visibility: 'visible', contentVisibility: 'visible' };
    this.rect = { width: 10, height: 10 };
    this.visibleByBrowser = true;
    this.id = id;
  }
  get id() { return this.attributes.get('id') ?? ''; }
  set id(value) { this.attributes.set('id', String(value)); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  get hasAttribute() { return name => this.attributes.has(name); }
  matches() { return false; }
  getBoundingClientRect() { return this.rect; }
  // `checkVisibility()` with no arguments is what Playwright 1.64.1 calls;
  // the double fails if the interpreter passes flags Playwright never uses.
  checkVisibility(...args) {
    assert.equal(args.length, 0, 'Playwright calls checkVisibility() with no flags');
    return this.visibleByBrowser;
  }
  attachShadow(mode) { const root = new Node(11); root.host = this; if (mode === 'open') this.shadowRoot = root; return root; }
}
class Text extends Node { constructor(value, box) { super(3); this.nodeValue = value; this.box = box || { width: 10, height: 10 }; } }

global.Node = Node; global.Element = Element;
const document = global.document = new Node(9);
document.documentElement = new Element('html');
document.head = new Element('head');
document.append(document.head, document.documentElement);
document.defaultView = { getComputedStyle: node => node.style };
document.createRange = () => ({ selectNode(node) { this.node = node; }, getBoundingClientRect() { return this.node.box; } });
document.evaluate = () => { throw new Error('fixture DOM has no XPath'); };

const elements = [];
function add(parent, tag, id, facts = {}) {
  const element = new Element(tag, id);
  if ('display' in facts || 'visibility' in facts || 'contentVisibility' in facts) {
    element.style = { ...element.style, ...pick(facts, ['display', 'visibility', 'contentVisibility']) };
  }
  if ('rect' in facts) element.rect = facts.rect;
  if ('check' in facts) element.visibleByBrowser = facts.check;
  if ('attributes' in facts) for (const [name, value] of Object.entries(facts.attributes)) element.setAttribute(name, value);
  parent.append(element);
  if (facts.inventory !== false) elements.push(element);
  return element;
}
function pick(object, keys) { const out = {}; for (const key of keys) if (key in object) out[key] = object[key]; return out; }
function text(parent, value, box) { const node = new Text(value, box); parent.append(node); return node; }

const body = add(document.documentElement, 'body', 'body');
const main = add(body, 'main', 'main');
add(main, 'div', 'shown');
add(main, 'div', 'display-none', { display: 'none', check: false, rect: { width: 0, height: 0 } });
add(main, 'div', 'visibility-hidden', { visibility: 'hidden', check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'visibility-collapse', { visibility: 'collapse', check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'zero-area', { rect: { width: 0, height: 0 } });
add(main, 'div', 'content-skipped', { check: true, rect: { width: 10, height: 10 } });
add(main, 'div', 'opacity-zero', { check: true, rect: { width: 10, height: 10 } });
// display:contents has no box; Playwright looks at children and text ranges.
add(main, 'div', 'contents-empty', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
const contentsChild = add(main, 'div', 'contents-child', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
add(contentsChild, 'span', 'contents-visible-child', { rect: { width: 10, height: 10 } });
const contentsHiddenChild = add(main, 'div', 'contents-hidden-child', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
add(contentsHiddenChild, 'span', 'contents-none-child', { display: 'none', check: false, rect: { width: 0, height: 0 } });
const contentsHiddenText = add(main, 'div', 'contents-hidden-text', { display: 'contents', visibility: 'hidden', check: false, rect: { width: 0, height: 0 } });
text(contentsHiddenText, 'invisible text');
const contentsText = add(main, 'div', 'contents-text', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
text(contentsText, 'painted text', { width: 12, height: 10 });
const contentsZeroText = add(main, 'div', 'contents-zero-text', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
text(contentsZeroText, 'clipped text', { width: 0, height: 0 });
// A contents element whose element child overrides a hidden visibility still
// paints, so Playwright reports the parent visible (the child's own style wins).
const contentsOverride = add(main, 'div', 'contents-override', { display: 'contents', visibility: 'hidden', check: false, rect: { width: 0, height: 0 } });
add(contentsOverride, 'span', 'contents-override-child', { visibility: 'visible', rect: { width: 10, height: 10 } });
const openHost = add(main, 'div', 'open-host');
const openRoot = openHost.attachShadow('open');
add(openRoot, 'div', 'open-inner');
add(openRoot, 'div', 'open-shown');
// A display:contents host only inspects light children, never its shadow root.
const contentsHost = add(main, 'div', 'contents-host', { display: 'contents', check: false, rect: { width: 0, height: 0 } });
const contentsShadow = contentsHost.attachShadow('open');
add(contentsShadow, 'span', 'contents-shadow-child');
const closedHost = add(main, 'div', 'closed-host');
const closedRoot = closedHost.attachShadow('closed');
add(closedRoot, 'div', 'closed-inner');
assert.equal(closedHost.shadowRoot, null, 'closed roots are not exposed');
// Ordered rows: visible, hidden, visible, visible. nth runs before a following
// visible step, and after it when the filter comes first.
const rows = add(main, 'ul', 'rows');
add(rows, 'li', 'row-1', { display: 'none', check: false, rect: { width: 0, height: 0 } });
add(rows, 'li', 'row-2');
add(rows, 'li', 'row-3', { visibility: 'hidden', check: true });
add(rows, 'li', 'row-4');

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
const engine = (name, body) => ({ engine: name, body });

let cacheStyle,cacheStyleBefore,cacheStyleAfter,cacheStyleVisibility; const globalOptions={browserNameForWorkarounds:"chromium"}; const kLayoutSelectorNames=[];
function getElementComputedStyle(element, pseudo) {
  const cache = pseudo === "::before" ? cacheStyleBefore : pseudo === "::after" ? cacheStyleAfter : cacheStyle;
  if (cache && cache.has(element))
    return cache.get(element);
  const style = element.ownerDocument && element.ownerDocument.defaultView ? element.ownerDocument.defaultView.getComputedStyle(element, pseudo) : void 0;
  cache == null ? void 0 : cache.set(element, style);
  return style;
}
function isElementStyleVisibilityVisible(element, style) {
  const cached = cacheStyleVisibility == null ? void 0 : cacheStyleVisibility.get(element);
  if (cached !== void 0)
    return cached;
  const result = computeElementStyleVisibilityVisible(element, style);
  cacheStyleVisibility == null ? void 0 : cacheStyleVisibility.set(element, result);
  return result;
}
function computeElementStyleVisibilityVisible(element, style) {
  style = style != null ? style : getElementComputedStyle(element);
  if (!style)
    return true;
  if (!element.checkVisibility() && !isWebKitListBoxOptionVisible(element, style))
    return false;
  if (style.visibility !== "visible")
    return false;
  return true;
}
function isListBoxSelect(select) {
  return select.multiple || select.size > 1;
}
function isWebKitListBoxOptionVisible(element, style) {
  var _a;
  if (globalOptions.browserNameForWorkarounds !== "webkit" || element.nodeName !== "OPTION" || style.display === "none")
    return false;
  const select = element.closest("select");
  if (!select || !isListBoxSelect(select))
    return false;
  for (let e = element.parentElement; e && e !== select; e = e.parentElement) {
    if (((_a = getElementComputedStyle(e)) == null ? void 0 : _a.display) === "none")
      return false;
  }
  return isElementStyleVisibilityVisible(select);
}
function computeBox(element) {
  const style = getElementComputedStyle(element);
  if (!style)
    return { visible: true, inline: false };
  const cursor = style.cursor;
  if (style.display === "contents") {
    for (let child = element.firstChild; child; child = child.nextSibling) {
      if (child.nodeType === 1 && isElementVisible(child))
        return { visible: true, inline: false, cursor };
      if (child.nodeType === 3 && isVisibleTextNode(child))
        return { visible: true, inline: true, cursor };
    }
    return { visible: false, inline: false, cursor };
  }
  if (!isElementStyleVisibilityVisible(element, style))
    return { cursor, visible: false, inline: false };
  const rect = element.getBoundingClientRect();
  return { cursor, visible: rect.width > 0 && rect.height > 0, inline: style.display === "inline" };
}
function isElementVisible(element) {
  return computeBox(element).visible;
}
var kTextNodeRange = /* @__PURE__ */ Symbol("playwrightTextNodeRange");
function isVisibleTextNode(node) {
  var _a;
  const document = node.ownerDocument;
  const range = (_a = document[kTextNodeRange]) != null ? _a : document[kTextNodeRange] = document.createRange();
  range.selectNode(node);
  const rect = range.getBoundingClientRect();
  const result = rect.width > 0 && rect.height > 0;
  range.setStart(document, 0);
  range.collapse(true);
  return result;
}

const pinned={_createVisibleEngine() {
    const queryAll = (root, body) => {
      if (root.nodeType !== 1)
        return [];
      const visible = body === "true";
      return isElementVisible(root) === visible ? [root] : [];
    };
    return { queryAll };
  },
_createHasEngine() {
    const queryAll = (root, body) => {
      if (root.nodeType !== 1)
        return [];
      const has = !!this.querySelector(body.parsed, root, false);
      return has ? [root] : [];
    };
    return { queryAll };
  },
querySelectorAll(selector, root) {
    if (selector.capture !== void 0) {
      if (selector.parts.some((part) => part.name === "nth"))
        throw this.createStacklessError(`Can't query n-th element in a request with the capture.`);
      const withHas = { parts: selector.parts.slice(0, selector.capture + 1) };
      if (selector.capture < selector.parts.length - 1) {
        const parsed = { parts: selector.parts.slice(selector.capture + 1) };
        const has = { name: "internal:has", body: { parsed }, source: stringifySelector(parsed) };
        withHas.parts.push(has);
      }
      return this.querySelectorAll(withHas, root);
    }
    if (!root["querySelectorAll"])
      throw this.createStacklessError("Node is not queryable.");
    if (selector.capture !== void 0) {
      throw this.createStacklessError("Internal error: there should not be a capture in the selector.");
    }
    if (root.nodeType === 11 && selector.parts.length === 1 && selector.parts[0].name === "css" && selector.parts[0].source === ":scope")
      return [root];
    this._evaluator.begin();
    try {
      let roots = /* @__PURE__ */ new Set([root]);
      for (const part of selector.parts) {
        if (part.name === "nth") {
          roots = this._queryNth(roots, part);
        } else if (part.name === "internal:and") {
          const andElements = this.querySelectorAll(part.body.parsed, root);
          roots = new Set(andElements.filter((e) => roots.has(e)));
        } else if (part.name === "internal:or") {
          const orElements = this.querySelectorAll(part.body.parsed, root);
          roots = new Set(sortInDOMOrder(/* @__PURE__ */ new Set([...roots, ...orElements])));
        } else if (kLayoutSelectorNames.includes(part.name)) {
          roots = this._queryLayoutSelector(roots, part, root);
        } else {
          const next = /* @__PURE__ */ new Set();
          for (const root2 of roots) {
            const all = this._queryEngineAll(part, root2);
            for (const one of all)
              next.add(one);
          }
          roots = next;
        }
      }
      return [...roots];
    } finally {
      this._evaluator.end();
    }
  },
_queryEngineAll(part, root) {
    const result = this._engines.get(part.name).queryAll(root, part.body);
    for (const element of result) {
      if (!("nodeName" in element))
        throw this.createStacklessError(`Expected a Node but got ${Object.prototype.toString.call(element)}`);
    }
    return result;
  },
querySelector(selector, root, strict) {
    const result = this.querySelectorAll(selector, root);
    if (strict && result.length > 1)
      throw this.strictModeViolationError(selector, result);
    this.checkDeprecatedSelectorUsage(selector, result);
    return result[0];
  },
_evaluator:{begin(){},end(){}},
checkDeprecatedSelectorUsage(){},
createStacklessError(message){return new Error(message);},
};
pinned._engines = new Map([['visible',pinned._createVisibleEngine()],['internal:has',pinned._createHasEngine()]]);
function sortInDOMOrder(elements) {
  const elementToEntry = /* @__PURE__ */ new Map();
  const roots = [];
  const result = [];
  function append(element) {
    let entry = elementToEntry.get(element);
    if (entry)
      return entry;
    const parent = parentElementOrShadowHost(element);
    if (parent) {
      const parentEntry = append(parent);
      parentEntry.children.push(element);
    } else {
      roots.push(element);
    }
    entry = { children: [], taken: false };
    elementToEntry.set(element, entry);
    return entry;
  }
  for (const e of elements)
    append(e).taken = true;
  function visit(element) {
    const entry = elementToEntry.get(element);
    if (entry.taken)
      result.push(element);
    if (entry.children.length > 1) {
      const set = new Set(entry.children);
      entry.children = [];
      let child = element.firstElementChild;
      while (child && entry.children.length < set.size) {
        if (set.has(child))
          entry.children.push(child);
        child = child.nextElementSibling;
      }
      child = element.shadowRoot ? element.shadowRoot.firstElementChild : null;
      while (child && entry.children.length < set.size) {
        if (set.has(child))
          entry.children.push(child);
        child = child.nextElementSibling;
      }
    }
    entry.children.forEach(visit);
  }
  roots.forEach(visit);
  return result;
}


function parentElementOrShadowHost(element) {
  if (element.parentElement)
    return element.parentElement;
  if (!element.parentNode)
    return;
  if (element.parentNode.nodeType === 11 && element.parentNode.host)
    return element.parentNode.host;
}

pinned._queryNth = ({  _queryNth(elements, part) {
    const list = [...elements];
    let nth = +part.body;
    if (nth === -1)
      nth = list.length - 1;
    return new Set(list.slice(nth, nth + 1));
  }})._queryNth;

// CSS here is deliberately a fixture primitive for simple ID/tag/*/:scope.
// The comparator's union, has, nth, visible and DOM ordering are pinned source.
Object.defineProperties(Node.prototype, {
 firstElementChild:{get(){return this._children.find(n=>n.nodeType===1)||null;}},
 nextElementSibling:{get(){let n=this.nextSibling;while(n&&n.nodeType!==1)n=n.nextSibling;return n;}}
});
pinned._engines.set('css',{queryAll(root,css){
 if(css===':scope')return root.nodeType===1?[root]:[];
 const result=new Set(root.querySelectorAll(css));
 const visit=r=>{if(r.shadowRoot){for(const e of r.shadowRoot.querySelectorAll(css))result.add(e);visit(r.shadowRoot);}for(const e of r.querySelectorAll('*'))if(e.shadowRoot){for(const n of e.shadowRoot.querySelectorAll(css))result.add(n);visit(e.shadowRoot);}};
 visit(root);return sortInDOMOrder(result);
}});
const css=body=>({kind:'selector',nativeParts:[engine('css',body)]});
const vis=body=>({kind:'selector',nativeParts:[engine('visible',body)]});
const union=(left,right)=>({kind:'union',left,right});
const index=(source,i)=>({kind:'index',source,index:i});
const has=(source,inner)=>({kind:'filter',source,has:inner});
function compile(expr){
 switch(expr.kind){
 case 'selector':return {parts:expr.nativeParts.map(p=>({name:p.engine,body:p.body,source:p.body}))};
 case 'union':return {parts:[...compile(expr.left).parts,{name:'internal:or',body:{parsed:compile(expr.right)}}]};
 case 'index':return {parts:[...compile(expr.source).parts,{name:'nth',body:String(expr.index==='first'?0:expr.index==='last'?-1:expr.index)}]};
 case 'filter':return {parts:[...compile(expr.source).parts,{name:'internal:has',body:{parsed:compile(expr.has)}}]};
 default:throw Error('Unsupported fixture expression');
 }
}
const cases=[
 ['terminal shown',has(css('#shown'),vis('true'))],
 ['terminal hidden',has(css('#display-none'),vis('false'))],
 ['root union positive',has(css('#shown'),union(vis('true'),vis('false')))],
 ['root union reverse',has(css('#shown'),union(vis('false'),vis('true')))],
 ['root union duplicate',has(css('#shown'),union(vis('true'),vis('true')))],
 ['root union negative',has(css('#shown'),union(vis('false'),vis('false')))],
 ['root scope union',has(css('#shown'),union(css(':scope'),css('#missing')))],
 ['descendant union reverse ordering',union(css('#row-4'),css('#row-1'))],
 ['descendant union dedup',union(css('#row-2'),css('#row-2'))],
 ['root and child index first',has(css('#contents-child'),index(union(css('span'),vis('true')),'first'))],
 ['root and child index last',has(css('#contents-child'),index(union(vis('true'),css('span')),'last'))],
 ['root duplicate index second must miss',has(css('#shown'),index(union(vis('true'),vis('true')),1))],
 ['nested union',has(css('#shown'),union(css('#missing'),union(vis('false'),vis('true'))))],
 ['nested filter on root',has(css('#shown'),has(union(vis('true'),css('#missing')),vis('true')))],
 ['nested filter on child',has(css('#contents-child'),has(union(css('span'),css('#missing')),vis('true')))],
 ['root-before-child index first observed',has(css('#rows'),has(index(union(css('#row-1'),vis('true')),'first'),vis('true')))],
 ['root-before-child index last observed',has(css('#rows'),has(index(union(vis('true'),css('#row-1')),'last'),vis('false')))],
 ['no self matching ID widening',has(css('#shown'),union(css('#shown'),css('#missing')))],
 ['document never admitted',union(vis('true'),vis('false'))],
 ['closed root excluded',union(css('#closed-inner'),css('#missing'))],
 ['open root reachable',union(css('#open-shown'),css('#open-inner'))],
];
let failed=0;
for(const [name,expr] of cases){
 const expected=pinned.querySelectorAll(compile(expr),document).map(e=>e.id||e.localName);
 const actual=run(expr);const pass=JSON.stringify(actual)===JSON.stringify(expected);
 console.log(JSON.stringify({name,expected,actual,pass}));if(!pass)failed++;
}
let forbiddenReads=0;
Object.defineProperty(Element.prototype,'value',{get(){forbiddenReads++;throw Error('value forbidden');}});
for(const el of elements)Object.defineProperty(el,'textContent',{get(){forbiddenReads++;throw Error('text forbidden');}});
run(has(css('#shown'),union(vis('true'),vis('false'))));assert.equal(forbiddenReads,0);
// White-box entrypoint only: pass a non-issued Element as root with empty
// scope; production selector/union bodies are unchanged. Public filter never
// supplies such a root, so this additionally checks the defensive index gate.
const outside = new Element('div','not-issued');
const originalEvaluation='const indices=hasDeprecatedLightSelector(expression)?evaluatePublicLightExpression(expression):evaluate(expression);';
assert.ok(script.includes(originalEvaluation));
const outsideScript=script.replace(originalEvaluation,'const indices=hasDeprecatedLightSelector(expression)?evaluatePublicLightExpression(expression):evaluate(expression,[],global.__unissuedRoot);');
global.__unissuedRoot=outside;
const outsideResult=eval(`(${outsideScript})`)(union(vis('true'),vis('false')),elements.map(()=>({states:{secure:false,hidden:false}})),elements.map(()=>[]),elements.map(()=>null),'.secure',elements.map(()=>false),...elements);
delete global.__unissuedRoot;
assert.equal(outsideResult.error,undefined);assert.deepEqual(outsideResult.indices,[]);
console.log('UNISSUED_ROOT no admission (white-box entrypoint, unchanged union/selector bodies)');
console.log(JSON.stringify({cases:cases.length,failed,privacyReads:forbiddenReads,kind:'explicit DOM double, not browser or daemon'}));
if(failed)process.exitCode=1;
