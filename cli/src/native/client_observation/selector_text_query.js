// Copyright (c) Microsoft Corporation. Licensed under the Apache License, Version 2.0.
// Raw text query semantics derived from Playwright 1.64.1 injectedScript.ts.
// Full text acquisition remains the existing bounded/private matcherText policy.
const rawTextFactsCache = new Map();
const rawTextSelectorError = {};
function rawTextFacts(root) {
  if (rawTextFactsCache.has(root)) return rawTextFactsCache.get(root);
  const full = matcherText(root);
  if (full === null) { rawTextFactsCache.set(root, null); return null; }
  const normalize = value => value.replace(/[\u200b\u00ad]/g, '').trim().replace(/\s+/g, ' ');
  const facts = { full, normalized: normalize(full), immediate: [] };
  if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(root.nodeName) || document.head?.contains(root)) {
    rawTextFactsCache.set(root, facts); return facts;
  }
  // matcherText has already read the only allowed non-editable input value.
  // Never read the value property again or read any editable/secure value.
  if (root instanceof HTMLInputElement && ['submit', 'button', 'reset'].includes(root.type)) {
    facts.immediate.push(full);
  } else {
    let current = '', length = 0;
    for (let child = root.firstChild; child; child = child.nextSibling) {
      matcherStep();
      if (child.nodeType === 3) {
        const text = child.nodeValue || '';
        length += text.length; matcherChars += text.length;
        if (length > 1048576 || matcherChars > 8388608) throw matcherLimit;
        current += text;
      } else if (child.nodeType !== 8) {
        if (current) facts.immediate.push(current);
        current = '';
      }
    }
    if (current) facts.immediate.push(current);
  }
  rawTextFactsCache.set(root, facts);
  return facts;
}
function rawElementTextMatch(element, matcher) {
  matcherStep();
  if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(element.nodeName) || document.head?.contains(element)) return 'none';
  const facts = rawTextFacts(element);
  // Redacted/unknown text is not evidence that every descendant fails. In
  // particular a secure sibling must not prune ordinary sibling candidates.
  if (facts === null) return 'protected';
  if (!matcher(facts)) return 'none';
  for (let child = element.firstChild; child; child = child.nextSibling) {
    matcherStep();
    if (child.nodeType !== 1) continue;
    const childFacts = rawTextFacts(child);
    if (childFacts !== null && matcher(childFacts)) return 'selfAndChildren';
  }
  if (element.shadowRoot) {
    const shadowFacts = rawTextFacts(element.shadowRoot);
    if (shadowFacts !== null && matcher(shadowFacts)) return 'selfAndChildren';
  }
  return 'self';
}
function selectRawText(root, body, light, allowed) {
  let compiled;
  try { compiled = compileSelectorTextMatcher(body, false); } catch { throw rawTextSelectorError; }
  const { matcher, kind } = compiled;
  const result = [];
  let lastDidNotMatchSelf = null;
  const append = element => {
    matcherStep();
    if (kind === 'lax' && lastDidNotMatchSelf && lastDidNotMatchSelf.contains(element)) return;
    const matches = rawElementTextMatch(element, matcher);
    if (matches === 'none') lastDidNotMatchSelf = element;
    if (matches === 'self' || (matches === 'selfAndChildren' && kind === 'strict')) result.push(element);
  };
  const rootIndex = root.nodeType === 1 ? selectorIndex.get(root) : undefined;
  if (rootIndex !== undefined && allowed.has(rootIndex)) append(root);
  // Reuse existing inventory/closed-root/search/depth/pending-work boundaries.
  const descendants = selectChain([{ engine: light ? 'css:light' : 'css', body: '*' }], [...allowed], root);
  for (const index of descendants) append(elements[index]);
  return result;
}
