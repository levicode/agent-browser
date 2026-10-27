// CSS/XPath chain execution stays inside the existing isolated query realm.
// The parser has validated engines, positions and capture placement before CDP.
const invalidSelector = {};
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
function selectChain(parts, scope, root) {
  const allowed = new Set(scope);
  let roots = [root];
  for (const part of parts) {
    matcherStep();
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
        } catch { throw invalidSelector; }
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
