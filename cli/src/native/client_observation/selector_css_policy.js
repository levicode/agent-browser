// Bounded structural authority adapter for the exact raw CSS evaluator.
// No payload acquisition, query-scope authority promotion, iframe traversal,
// closed-shadow traversal, or substitution of per-element matches for qSA.
function createRawCssPolicy(authority, native, step, limit, unavailable) {
  for (const key of ['isAuthorizedNode', 'isAuthorizedRoot', 'isIssued', 'textFacts', 'textMatch', 'isVisible', 'skipText'])
    if (typeof authority[key] !== 'function') throw unavailable;
  for (const key of ['read', 'querySelectorAll', 'matches', 'rect'])
    if (typeof native[key] !== 'function') throw unavailable;
  const ownerDocument = authority.document;
  let proof = null;
  function fail() { throw unavailable; }
  function allowed(node) {
    step();
    if (!node || authority.isAuthorizedNode(node) !== true) fail();
    return node;
  }
  function structural(node, key) {
    allowed(node);
    step();
    return native.read(node, key);
  }
  function preflight() {
    // All previous context/cache authority is revoked before starting a proof.
    proof = null;
    allowed(ownerDocument);
    if (authority.isAuthorizedRoot(ownerDocument) !== true || structural(ownerDocument, 'nodeType') !== 9) fail();
    const seen = new Set(), pending = [{ node: ownerDocument, depth: 0, parent: null }];
    while (pending.length) {
      step();
      const { node, depth, parent } = pending.pop();
      if (depth > 256 || seen.size >= 100000) throw limit;
      allowed(node);
      if (seen.has(node)) fail();
      if (structural(node, 'parentNode') !== parent) fail();
      if (node !== ownerDocument && structural(node, 'ownerDocument') !== ownerDocument) fail();
      seen.add(node);
      const type = structural(node, 'nodeType');
      // Only DOM child links and OPEN roots: never contentDocument, frame
      // windows, closed roots, attributes, textContent, nodeValue or values.
      if (type === 1) {
        const shadow = structural(node, 'shadowRoot');
        if (shadow) {
          allowed(shadow);
          if (authority.isAuthorizedRoot(shadow) !== true || structural(shadow, 'nodeType') !== 11 || structural(shadow, 'host') !== node || structural(shadow, 'mode') !== 'open') fail();
          pending.push({ node: shadow, depth: depth + 1, parent: null });
        }
      }
      let child = structural(node, 'firstChild');
      const siblings = new Set();
      while (child) {
        step(); allowed(child);
        if (siblings.has(child)) fail();
        siblings.add(child);
        if (pending.length >= 100000) throw limit;
        pending.push({ node: child, depth: depth + 1, parent: node });
        child = structural(child, 'nextSibling');
      }
    }
    // A native CSS atomic operation may consult the owning light root and
    // ancestors. It is permitted only after this complete authorized proof.
    proof = seen;
  }
  function proven(node) {
    step();
    if (!proof || !proof.has(node)) fail();
    allowed(node);
    return node;
  }
  function chargeAtomic(css) {
    if (!proof || typeof css !== 'string') fail();
    let bytes = 0;
    for (let i = 0; i < css.length; i++) {
      step(); const code = css.charCodeAt(i);
      if (code < 128) bytes++;
      else if (code < 2048) bytes += 2;
      else if (code >= 0xd800 && code <= 0xdbff && css.charCodeAt(i + 1) >= 0xdc00 && css.charCodeAt(i + 1) <= 0xdfff) { bytes += 4; i++; step(); }
      else bytes += 3;
      if (bytes > 65536) throw limit;
    }
    // Charge the entire proven structural search space for EVERY native CSS
    // atomic call. This is not a claim to count browser CPU instructions.
    for (let i = 0; i < proof.size; i++) step();
  }
  function elementLink(node, first, direction) {
    let candidate = structural(node, first);
    const visited = new Set();
    while (candidate) {
      step(); proven(candidate);
      if (visited.has(candidate)) fail();
      visited.add(candidate);
      if (structural(candidate, 'nodeType') === 1) return candidate;
      candidate = structural(candidate, direction);
    }
    return null;
  }
  function readable(element) { proven(element); if (authority.isIssued(element) !== true) fail(); }
  const policy = {
    authorizeContext(context) {
      preflight();
      proven(context.scope);
      if (context.originalScope !== undefined) proven(context.originalScope);
      return true;
    },
    finishContext() { proof = null; },
    read(node, key) {
      proven(node);
      if (!['parentElement', 'parentNode', 'host', 'shadowRoot', 'firstElementChild', 'nextElementSibling', 'previousElementSibling', 'documentElement', 'nodeType'].includes(key)) fail();
      if (key === 'firstElementChild' || key === 'documentElement') return elementLink(node, 'firstChild', 'nextSibling');
      if (key === 'nextElementSibling') return elementLink(node, 'nextSibling', 'nextSibling');
      if (key === 'previousElementSibling') return elementLink(node, 'previousSibling', 'previousSibling');
      const value = structural(node, key);
      if (value && typeof value === 'object') proven(value);
      return value;
    },
    queryAtom(root, css) {
      proven(root);
      chargeAtomic(css);
      const result = native.querySelectorAll(root, css);
      if (!result || typeof result[Symbol.iterator] !== 'function') fail();
      const values = [];
      for (const element of result) { step(); proven(element); if (values.length >= 100000) throw limit; values.push(element); }
      return values;
    },
    matchesAtom(element, css) {
      proven(element);
      chargeAtomic(css);
      return native.matches(element, css);
    },
    rect(element) { readable(element); step(); return native.rect(element); },
    isVisible(element) { readable(element); step(); return authority.isVisible(element); },
    textFacts(element) { readable(element); step(); return authority.textFacts(element); },
    textMatch(element, matcher) { readable(element); step(); return authority.textMatch(element, matcher); },
    skipText(element) { readable(element); step(); return authority.skipText(element); },
    isIssued(element) { proven(element); step(); return authority.isIssued(element); },
  };
  return policy;
}
