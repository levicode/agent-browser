// CSS/XPath chain execution stays inside the existing isolated query realm.
// The parser has validated engines, positions and capture placement before CDP.
const invalidSelector = {};
const selectorIndex = new Map(elements.map((element, index) => [element, index]));
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
        const pending = [[current, 0]];
        while (pending.length) {
          const [searchRoot, depth] = pending.pop();
          matcherStep();
          if (depth > 256) throw matcherLimit;
          let matches;
          try { matches = searchRoot.querySelectorAll(part.body); } catch { throw invalidSelector; }
          for (const element of matches) { matcherStep(); found.add(element); }
          // querySelectorAll cannot return its root for :scope alone.
          if (part.body.trim() === ':scope' && searchRoot.nodeType === 1) found.add(searchRoot);
          if (part.engine === 'css:light') continue;
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
