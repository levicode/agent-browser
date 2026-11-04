// Same MATCH_QUERY owner, shared budgets, no ARIA provider or metadata fallback.
const rawCssSelectorError = {}, rawCssUnavailable = {};
const rawCssPrograms = new Map();
const rawCssPreparedParts = new WeakSet();
const rawCssExtensionNames = new Set(['text', 'text-is', 'text-matches', 'has-text', 'visible', 'nth-match', 'light', 'left-of', 'right-of', 'above', 'below', 'near']);
const parseOwnedRawCss = createRawCssParser(matcherStep, matcherLimit);
let ownedRawCssEvaluator;
function rawCssProgram(part) {
  if (part.engine !== 'css' && part.engine !== 'css:light') return null;
  if (rawCssPrograms.has(part.body)) return rawCssPrograms.get(part.body);
  let parsed;
  try { parsed = parseOwnedRawCss(part.body); }
  catch (error) { if (error === matcherLimit) throw error; throw rawCssSelectorError; }
  const program = { selector: parsed.selector, extended: parsed.names.some(name => rawCssExtensionNames.has(name)) };
  rawCssPrograms.set(part.body, program);
  return program;
}
function prepareRawCssPrograms(parts, depth = 0) {
  matcherStep();
  if (depth > 64) throw matcherLimit;
  if (rawCssPreparedParts.has(parts)) return;
  for (const part of parts) {
    matcherStep();
    rawCssProgram(part);
    if (part.nestedParts) prepareRawCssPrograms(part.nestedParts, depth + 1);
  }
  // Only a fully syntax-checked immutable compiled chain is cached.
  rawCssPreparedParts.add(parts);
}
function getOwnedRawCssEvaluator() {
  if (ownedRawCssEvaluator) return ownedRawCssEvaluator;
  // Capture native structural interfaces from this already selected isolated
  // realm. Never obtain a window/document/root from a caller's query scope.
  const prototypes = [
    typeof ShadowRoot === 'function' && ShadowRoot.prototype,
    typeof Document === 'function' && Document.prototype,
    typeof DocumentFragment === 'function' && DocumentFragment.prototype,
    Element.prototype, Node.prototype,
  ].filter(Boolean).map(proto => ({ proto, properties: Object.getOwnPropertyDescriptors(proto) }));
  const isNode = node => node !== null && typeof node === 'object' && Node.prototype.isPrototypeOf(node);
  function descriptor(node, key) {
    for (const entry of prototypes) {
      matcherStep();
      if (entry.proto.isPrototypeOf(node) && Object.hasOwn(entry.properties, key)) return entry.properties[key];
    }
    throw rawCssUnavailable;
  }
  function read(node, key) {
    if (!isNode(node)) throw rawCssUnavailable;
    // Upstream probes shadowRoot on Document/ShadowRoot as well as Elements.
    // Its absence on non-Elements is known DOM shape, not an unknown getter.
    if (key === 'shadowRoot' && !Element.prototype.isPrototypeOf(node)) return undefined;
    const entry = descriptor(node, key);
    return entry.get ? Reflect.apply(entry.get, node, []) : entry.value;
  }
  function invoke(node, key, args) {
    const entry = descriptor(node, key);
    if (typeof entry.value !== 'function') throw rawCssUnavailable;
    return Reflect.apply(entry.value, node, args);
  }
  function authorized(node, depth = 0) {
    matcherStep();
    if (depth > 256) throw matcherLimit;
    if (!isNode(node)) return false;
    if (node === document) return true;
    if (read(node, 'ownerDocument') !== document) return false;
    const type = read(node, 'nodeType');
    if (type === 1) return selectorIndex.has(node);
    if (type === 11) {
      if (typeof ShadowRoot !== 'function' || !ShadowRoot.prototype.isPrototypeOf(node)) return false;
      const host = read(node, 'host');
      return read(node, 'mode') === 'open' && authorized(host, depth + 1) && read(host, 'shadowRoot') === node;
    }
    // These are structural identities, never promoted into output candidates.
    if (![3, 4, 7, 8, 10].includes(type)) return false;
    const parent = read(node, 'parentNode');
    return !!parent && authorized(parent, depth + 1);
  }
  const authority = {
    document,
    isAuthorizedNode: authorized,
    isAuthorizedRoot: node => node === document || (authorized(node) && read(node, 'nodeType') === 11),
    isIssued: node => selectorIndex.has(node),
    textFacts: node => rawTextFacts(node),
    textMatch: (node, matcher) => {
      const result = rawElementTextMatch(node, matcher);
      if (result === 'protected') throw rawCssUnavailable;
      return result;
    },
    isVisible: node => elementVisible(node),
    skipText: node => ['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.nodeName) || !!document.head?.contains(node),
  };
  const native = {
    read,
    querySelectorAll: (root, css) => invoke(root, 'querySelectorAll', [css]),
    matches: (node, css) => invoke(node, 'matches', [css]),
    rect: node => invoke(node, 'getBoundingClientRect', []),
  };
  const policy = createRawCssPolicy(authority, native, matcherStep, matcherLimit, rawCssUnavailable);
  ownedRawCssEvaluator = createRawCssEvaluator(policy, matcherStep, matcherLimit, rawCssUnavailable);
  return ownedRawCssEvaluator;
}
function selectOwnedRawCss(root, program, light) {
  try { return getOwnedRawCssEvaluator().query({ scope: root, pierceShadow: !light }, program.selector); }
  catch (error) {
    if (error === matcherLimit || error === rawCssUnavailable || error === rawCssSelectorError) throw error;
    // Private syntax/engine failures never expose selector bodies or DOM text.
    throw rawCssSelectorError;
  }
}
