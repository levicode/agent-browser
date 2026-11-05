// Selector chain execution stays inside the existing isolated query realm.
// The parser has validated engines and positions before CDP; the entry point
// applies the pinned capture rewrite before this chain runs.
const invalidSelector = {};
// Native XPath syntax DOMExceptions are engine errors on the original public route.
const rawXPathSelectorError = {};
const nativeDOMExceptionName = typeof DOMException === "function" ? Object.getOwnPropertyDescriptor(DOMException.prototype, "name")?.get : undefined;
function isNativeXPathSyntaxError(error) {
  if (!nativeDOMExceptionName) return false;
  try { return Reflect.apply(nativeDOMExceptionName, error, []) === "SyntaxError"; } catch { return false; }
}
const selectorIndex = new Map(elements.map((element, index) => [element, index]));
// Playwright 1.64.1 attribute engines build `[<attribute>=${JSON.stringify(body)}]`
// and query it with browser CSS. The authored body is data, never a selector.
const attributeEngines = new Set([
  'id', 'id:light',
  'data-testid', 'data-testid:light',
  'data-test-id', 'data-test-id:light',
  'data-test', 'data-test:light',
]);
function attributeSelector(part) {
  const attribute = part.engine.endsWith(':light') ? part.engine.slice(0, -6) : part.engine;
  return `[${attribute}=${JSON.stringify(part.body)}]`;
}
// Playwright 1.64.1 `_createVisibleEngine` compares the authored body to the
// exact string "true" and filters the root with `isElementVisible`, which is
// `computeBox(element).visible`. That is rendering visibility, not the E2E
// reader's semantic `hidden` state. Port it as-is: display:contents inspects
// light-tree element children and text ranges; every other element needs
// checkVisibility() and a non-empty client rect. Opacity is not consulted.
function visibleStyle(node) {
  const view = node.ownerDocument && node.ownerDocument.defaultView;
  return view ? view.getComputedStyle(node) : null;
}
function visibleTextNode(node) {
  const range = node.ownerDocument.createRange();
  range.selectNode(node);
  const box = range.getBoundingClientRect();
  return box.width > 0 && box.height > 0;
}
function elementVisible(element, depth = 0) {
  matcherStep();
  if (depth > 256) throw matcherLimit;
  const style = visibleStyle(element);
  if (!style) return true;
  if (style.display === 'contents') {
    // No box exists for the element itself; Playwright asks its light-tree
    // children and direct text nodes instead, never its shadow root.
    for (let child = element.firstChild; child; child = child.nextSibling) {
      matcherStep();
      if (child.nodeType === 1 && elementVisible(child, depth + 1)) return true;
      if (child.nodeType === 3 && visibleTextNode(child)) return true;
    }
    return false;
  }
  // Playwright calls checkVisibility() with no arguments, then requires an
  // explicitly visible computed visibility value.
  if (!element.checkVisibility() || style.visibility !== 'visible') return false;
  const box = element.getBoundingClientRect();
  return box.width > 0 && box.height > 0;
}
function visibleRoot(root, body) {
  if (root.nodeType !== 1) return false;
  return elementVisible(root) === (body === 'true');
}
function selectChain(parts, scope, root, depth = 0) {
  parts = compileRawInternalParts(parts, depth);
  // Complete AST classification before traversal, not fallback after failure.
  prepareRawCssPrograms(parts);
  const allowed = new Set(scope);
  // A chain can legitimately produce the very root it was given: the visible
  // engine returns the root itself when it matches, and CSS `:scope` already
  // does the same. Playwright's `has` engine evaluates the inner selector with
  // the candidate element as scope and accepts that match, but the candidate
  // is not in its own descendant scope, so admit the root explicitly. `allowed`
  // holds inventory indices, so add the root's index rather than the element.
  // The root is always a document or one of the issued elements, so this can
  // never widen the candidate inventory or reach a node outside it.
  const rootIndex = root.nodeType === 1 ? selectorIndex.get(root) : undefined;
  if (rootIndex !== undefined) allowed.add(rootIndex);
  let roots = [root];
  for (const part of parts) {
    matcherStep();
    if (rawInternalEngines.has(part.engine)) {
      roots = evaluateRawInternalPart(part, roots, scope, root, depth);
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    if (part.engine === 'nth') {
      const index = Number(part.body);
      const start = index === -1 ? roots.length - 1 : index;
      roots = roots.slice(start, start + 1);
      continue;
    }
    // Playwright's visible engine has only `queryAll`: it keeps or drops each
    // current root in place. It is not a descendant search, so it neither
    // widens the chain nor pierces again.
    if (part.engine === 'visible') {
      roots = roots.filter(root => { matcherStep(); return visibleRoot(root, part.body); });
      continue;
    }
    // Playwright's role engine is a descendant query over the current root:
    // it never returns the root itself, descends through open shadow roots in
    // document order, and filters by ARIA role, states, hidden and name. The
    // internal projection of the same engine lowercases a non-exact `=` name
    // to a substring match.
    if (part.engine === 'role' || part.engine === 'internal:role') {
      const found = new Set();
      for (const current of roots) {
        matcherStep();
        for (const element of roleQueryAll(current, part.body, part.engine === 'internal:role')) found.add(element);
      }
      roots = [...found];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    // Playwright's internal:text engine is the text engine with shadow search
    // and the internal JSON-unquoted matcher: only an element whose own
    // normalized text matches is returned, never one matched by a descendant.
    if (part.engine === 'internal:text') {
      const found = new Set();
      for (const current of roots) {
        matcherStep();
        for (const element of selectRawText(current, part.body, false, allowed, true)) found.add(element);
      }
      roots = [...found];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    // Playwright's has-text/has-not-text are root predicates over the current
    // element's full normalized text: the root is kept or dropped in place.
    if (part.engine === 'internal:has-text' || part.engine === 'internal:has-not-text') {
      let matcher;
      try { ({ matcher } = compileSelectorTextMatcher(part.body, true)); }
      catch (error) { if (error === matcherLimit) throw error; throw rawTextSelectorError; }
      const keepWhenMatched = part.engine === 'internal:has-text';
      roots = roots.filter(root => {
        matcherStep();
        if (root.nodeType !== 1) return false;
        const facts = rawTextFacts(root);
        // Protected/unknown text is neither a proven match nor a proven
        // absence, so neither the positive nor the negated engine admits it.
        if (facts === null) return false;
        return matcher(facts) === keepWhenMatched;
      });
      continue;
    }
    // Playwright's internal:label is a descendant query filtering each element
    // by its associated label texts (aria-labelledby, aria-label, <label>).
    if (part.engine === 'internal:label') {
      let matcher;
      try { ({ matcher } = compileSelectorTextMatcher(part.body, true)); }
      catch (error) { if (error === matcherLimit) throw error; throw rawTextSelectorError; }
      const found = new Set();
      for (const current of roots) {
        matcherStep();
        for (const index of selectChain([{ engine: 'css', body: '*' }], [...allowed], current)) {
          const element = elements[index];
          matcherStep();
          if (rawElementLabels(element).some(facts => facts !== null && matcher(facts))) found.add(element);
        }
      }
      roots = [...found];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    // Playwright's internal:attr is a named attribute selector over the typed
    // body: query `[name]` across this root's open shadow tree, then filter by
    // the parsed operator/value. The body is data, never interpolated code.
    if (part.engine === 'internal:attr') {
      const parsed = roleParseAttributeSelector(part.body);
      if (parsed.name || parsed.attributes.length !== 1) throw invalidSelector;
      const attribute = parsed.attributes[0];
      const matcher = rawAttributeMatcher(attribute, invalidSelector);
      const found = new Set();
      for (const current of roots) {
        matcherStep();
        for (const index of selectChain([{ engine: 'css', body: '[' + attribute.name + ']' }], [...allowed], current)) {
          const element = elements[index];
          matcherStep();
          if (matcher(element.getAttribute(attribute.name))) found.add(element);
        }
      }
      roots = [...found];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    // Playwright's internal:testid splits a comma-joined attribute name list,
    // queries every named attribute and keeps an element when any value matches.
    if (part.engine === 'internal:testid') {
      const parsed = roleParseAttributeSelector(part.body);
      if (parsed.name || parsed.attributes.length !== 1) throw invalidSelector;
      const attribute = parsed.attributes[0];
      const names = attribute.name.split(',');
      const matcher = rawAttributeMatcher(attribute, invalidSelector);
      const css = names.map(name => '[' + name + ']').join(',');
      const found = new Set();
      for (const current of roots) {
        matcherStep();
        for (const index of selectChain([{ engine: 'css', body: css }], [...allowed], current)) {
          const element = elements[index];
          matcherStep();
          if (names.some(name => {
            const actual = element.getAttribute(name);
            return actual !== null && matcher(actual);
          })) found.add(element);
        }
      }
      roots = [...found];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    if (part.engine === 'text' || part.engine === 'text:light') {
      const textMatches = new Set();
      for (const current of roots) {
        matcherStep();
        for (const element of selectRawText(current, part.body, part.engine === 'text:light', allowed)) textMatches.add(element);
      }
      roots = [...textMatches];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    const cssProgram = rawCssProgram(part);
    if (cssProgram && cssProgram.extended) {
      const matches = new Set();
      for (const current of roots) {
        matcherStep();
        for (const element of selectOwnedRawCss(current, cssProgram, part.engine === 'css:light')) matches.add(element);
      }
      roots = [...matches];
      if (roots.length > 100000) throw matcherLimit;
      continue;
    }
    const found = new Set();
    for (const current of roots) {
      matcherStep();
      if (part.engine === 'xpath' || part.engine === 'xpath:light') {
        // Playwright makes an absolute XPath relative when chaining from an
        // element; XPath does not pierce either open or closed shadow roots.
        const xpath = part.body.startsWith('/') && current.nodeType !== 9 ? '.' + part.body : part.body;
        let matches;
        try {
          matches = document.evaluate(xpath, current, null, XPathResult.ORDERED_NODE_ITERATOR_TYPE, null);
        } catch (error) {
          if (error === matcherLimit) throw error;
          if (isNativeXPathSyntaxError(error)) throw rawXPathSelectorError;
          throw invalidSelector;
        }
        for (let element = matches.iterateNext(); element; element = matches.iterateNext()) {
          matcherStep();
          if (element.nodeType === 1) found.add(element);
        }
      } else {
        // Anything the parser did not classify is never reinterpreted as CSS.
        if (part.engine !== 'css' && part.engine !== 'css:light' && !attributeEngines.has(part.engine)) throw invalidSelector;
        const attribute = attributeEngines.has(part.engine);
        const css = attribute ? attributeSelector(part) : part.body;
        const pierce = attribute ? !part.engine.endsWith(':light') : part.engine !== 'css:light';
        const pending = [[current, 0]];
        while (pending.length) {
          const [searchRoot, depth] = pending.pop();
          matcherStep();
          if (depth > 256) throw matcherLimit;
          let matches;
          try { matches = searchRoot.querySelectorAll(css); } catch { throw invalidSelector; }
          for (const element of matches) { matcherStep(); found.add(element); }
          // querySelectorAll cannot return its root for :scope alone.
          if (!attribute && part.body.trim() === ':scope' && searchRoot.nodeType === 1) found.add(searchRoot);
          if (!pierce) continue;
          const shadows = [];
          if (searchRoot.shadowRoot) shadows.push(searchRoot.shadowRoot);
          for (const element of searchRoot.querySelectorAll('*')) {
            matcherStep();
            if (element.shadowRoot) shadows.push(element.shadowRoot);
          }
          for (let index = shadows.length - 1; index >= 0; index--) pending.push([shadows[index], depth + 1]);
          if (pending.length > 100000) throw matcherLimit;
        }
      }
    }
    roots = [...found];
    if (roots.length > 100000) throw matcherLimit;
  }
  return roots.map(element => selectorIndex.get(element)).filter(index => index !== undefined && allowed.has(index));
}
