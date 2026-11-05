// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License, Version 2.0.
// Derived from Playwright 1.64.1 selectorParser.ts and injectedScript.ts.
// Private nested raw-selector helpers; no global registry or acquisition changes.
const rawInternalSelectorError = {};
const rawInternalSelectorUnsupported = {};
const rawInternalEngines = new Set(['internal:has', 'internal:has-not', 'internal:and', 'internal:or', 'internal:chain']);
const rawInternalCompiledParts = new WeakSet();
const rawInternalCompiledCache = new WeakMap();
const rawInternalPlainEngines = new Set(['css', 'css:light', 'xpath', 'xpath:light', 'nth', 'visible', 'text', 'text:light', 'role', 'internal:text', 'internal:has-text', 'internal:has-not-text', 'internal:label', 'internal:attr', 'internal:testid', 'internal:role', 'id', 'id:light', 'data-testid', 'data-testid:light', 'data-test-id', 'data-test-id:light', 'data-test', 'data-test:light']);
function rawInternalCharge(source) {
  if (typeof source !== 'string') throw rawInternalSelectorError;
  let bytes = 0;
  for (let i = 0; i < source.length; i++) {
    matcherStep();
    const code = source.charCodeAt(i);
    if (code < 0x80) bytes++;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && source.charCodeAt(i + 1) >= 0xdc00 && source.charCodeAt(i + 1) <= 0xdfff) {
      bytes += 4; i++; matcherStep();
    } else bytes += 3;
    if (bytes > 65536) throw matcherLimit;
  }
}
function decodeRawInternalBody(body) {
  try {
    const values = JSON.parse('[' + body + ']');
    if (!Array.isArray(values) || values.length !== 1 || typeof values[0] !== 'string') throw rawInternalSelectorError;
    return values[0];
  } catch { throw rawInternalSelectorError; }
}
function rawInternalLex(selector) {
  let index = 0;
  let quote5;
  let start3 = 0;
  const result2 = { parts: [] };
  const append = () => {
    const part = selector.substring(start3, index).trim();
    const eqIndex = part.indexOf("=");
    let name;
    let body;
    if (eqIndex !== -1 && part.substring(0, eqIndex).trim().match(/^[a-zA-Z_0-9-+:*]+$/)) {
      name = part.substring(0, eqIndex).trim();
      body = part.substring(eqIndex + 1);
    } else if (part.length > 1 && part[0] === '"' && part[part.length - 1] === '"') {
      name = "text";
      body = part;
    } else if (part.length > 1 && part[0] === "'" && part[part.length - 1] === "'") {
      name = "text";
      body = part;
    } else if (/^\(*\/\//.test(part) || part.startsWith("..")) {
      name = "xpath";
      body = part;
    } else {
      name = "css";
      body = part;
    }
    let capture = false;
    if (name[0] === "*") {
      capture = true;
      name = name.substring(1);
    }
    result2.parts.push({ name, body });
    if (capture) {
      if (result2.capture !== void 0)
        throw rawInternalSelectorError;
      result2.capture = result2.parts.length - 1;
    }
  };
  if (!selector.includes(">>")) {
    index = selector.length;
    append();
    return result2;
  }
  const shouldIgnoreTextSelectorQuote = () => {
    const prefix = selector.substring(start3, index);
    const match = prefix.match(/^\s*text\s*=(.*)$/);
    return !!match && !!match[1];
  };
  while (index < selector.length) {
    const c = selector[index];
    if (c === "\\" && index + 1 < selector.length) {
      index += 2;
    } else if (c === quote5) {
      quote5 = void 0;
      index++;
    } else if (!quote5 && (c === '"' || c === "'" || c === "`") && !shouldIgnoreTextSelectorQuote()) {
      quote5 = c;
      index++;
    } else if (!quote5 && c === ">" && selector[index + 1] === ">") {
      append();
      index += 2;
      start3 = index;
    } else {
      index++;
    }
  }
  append();
  return result2;
}
function parseRawInternalSelector(source, depth = 0, state = { parts: 0 }) {
  if (depth > 64) throw matcherLimit;
  rawInternalCharge(source);
  const parsed = rawInternalLex(source);
  // Capture/frame-prefix normalization is not implemented here: never flatten
  // it or change ownership. The integrator must expose this finite boundary.
  if (parsed.capture !== undefined) throw rawInternalSelectorUnsupported;
  return compileRawInternalParts(parsed.parts.map(part => ({ engine: part.name, body: part.body })), depth, state);
}
function compileRawInternalParts(parts, depth = 0, state = { parts: 0 }) {
  if (depth > 64) throw matcherLimit;
  if (!Array.isArray(parts) || !parts.length) throw rawInternalSelectorError;
  if (rawInternalCompiledParts.has(parts)) return parts;
  const cached = rawInternalCompiledCache.get(parts);
  if (cached) return cached;
  if (rawInternalEngines.has(parts[0].engine)) throw rawInternalSelectorError;
  const compiled = parts.map(part => {
    matcherStep();
    if (++state.parts > 256) throw matcherLimit;
    if (typeof part.engine !== 'string' || typeof part.body !== 'string') throw rawInternalSelectorError;
    rawInternalCharge(part.body);
    if (rawInternalEngines.has(part.engine)) {
      const source = decodeRawInternalBody(part.body);
      return Object.freeze({ engine: part.engine, body: part.body, nestedParts: parseRawInternalSelector(source, depth + 1, state) });
    }
    // Known unsupported and unknown engines are both explicit finite capability
    // boundaries here, never CSS. The outer/native parser retains its policy.
    if (!rawInternalPlainEngines.has(part.engine)) throw rawInternalSelectorUnsupported;
    return Object.freeze({ engine: part.engine, body: part.body });
  });
  Object.freeze(compiled);
  rawInternalCompiledParts.add(compiled);
  rawInternalCompiledCache.set(parts, compiled);
  return compiled;
}
function rawInternalNested(part, scope, root, depth, checked) {
  if (depth > 64) throw matcherLimit;
  if (!Array.isArray(part.nestedParts)) throw rawInternalSelectorError;
  const indices = selectChain(part.nestedParts, scope, root, depth);
  // querySelector (has/has-not) checks only this nested selector's top-level
  // engine list. querySelectorAll (and/or/chain) deliberately does not.
  if (checked && indices.length && part.nestedParts.some(p => deprecatedLightEngines.has(p.engine))) throw deprecatedLightSelector;
  return indices.map(index => { matcherStep(); return elements[index]; });
}
// Exact pinned DOM ordering, with existing matcher work/depth guards added.
// Ancestors are visited only to order issued matches, never added to results.
function rawInternalParent(element) {
  matcherStep();
  if (element.parentElement) return element.parentElement;
  if (!element.parentNode) return;
  if (element.parentNode.nodeType === 11 && element.parentNode.host) return element.parentNode.host;
}
function rawInternalSort(elementsToSort) {
  const elementToEntry = new Map(), roots = [], result = [];
  function append(element, depth = 0) {
    matcherStep();
    if (depth > 256) throw matcherLimit;
    let entry = elementToEntry.get(element);
    if (entry) return entry;
    const parent = rawInternalParent(element);
    if (parent) append(parent, depth + 1).children.push(element);
    else roots.push(element);
    entry = { children: [], taken: false };
    elementToEntry.set(element, entry);
    return entry;
  }
  for (const element of elementsToSort) { matcherStep(); append(element).taken = true; }
  function visit(element, depth = 0) {
    matcherStep();
    if (depth > 256) throw matcherLimit;
    const entry = elementToEntry.get(element);
    if (entry.taken) result.push(element);
    if (entry.children.length > 1) {
      const set = new Set(entry.children);
      entry.children = [];
      let child = element.firstElementChild;
      while (child && entry.children.length < set.size) {
        matcherStep();
        if (set.has(child)) entry.children.push(child);
        child = child.nextElementSibling;
      }
      child = element.shadowRoot ? element.shadowRoot.firstElementChild : null;
      while (child && entry.children.length < set.size) {
        matcherStep();
        if (set.has(child)) entry.children.push(child);
        child = child.nextElementSibling;
      }
    }
    for (const child of entry.children) visit(child, depth + 1);
  }
  for (const root of roots) visit(root);
  return result;
}
function rawInternalOrderedUnion(roots, rhs) {
  const matches = new Set();
  for (const element of [...roots, ...rhs]) {
    matcherStep();
    if (selectorIndex.has(element)) matches.add(element);
  }
  return rawInternalSort(matches);
}
// Call only for one of rawInternalEngines while iterating a compiled chain.
// roots contains Elements, scope contains issued indices, originalRoot is the
// unchanged root supplied to this chain (not the latest matched Element).
function evaluateRawInternalPart(part, roots, scope, originalRoot, depth = 0) {
  matcherStep();
  if (depth > 64) throw matcherLimit;
  if (!rawInternalEngines.has(part.engine)) throw rawInternalSelectorUnsupported;
  if (part.engine === 'internal:and' || part.engine === 'internal:or') {
    const rhs = rawInternalNested(part, scope, originalRoot, depth + 1, false);
    if (part.engine === 'internal:or') return rawInternalOrderedUnion(roots, rhs);
    const left = new Set(roots);
    return rhs.filter(element => { matcherStep(); return left.has(element); });
  }
  const found = new Set();
  for (const root of roots) {
    matcherStep();
    if (root.nodeType !== 1 || !selectorIndex.has(root)) continue;
    const matches = rawInternalNested(part, scope, root, depth + 1, part.engine !== 'internal:chain');
    if (part.engine === 'internal:chain') {
      for (const element of matches) { matcherStep(); found.add(element); }
    } else if (Boolean(matches.length) === (part.engine === 'internal:has')) found.add(root);
  }
  return [...found];
}

// Playwright 1.64.1 InjectedScript.querySelectorAll capture branch. A capture
// that is not the last part is not a separate engine: the captured part ends
// the prefix and the authored tail becomes an internal:has body, exactly as
// the pinned rewrite does. The nested body is serialized back to authored
// source because the adapter's has compiler reads JSON source, not a parsed
// AST; every part keeps its engine name and authored body.
function rawSelectorEntryParts(x) {
  const parts = x.nativeParts;
  const capture = x.nativeCapture;
  if (capture === undefined || capture === null) return parts;
  const tail = parts.slice(capture + 1);
  if (!tail.length) return parts.slice(0, capture + 1);
  let source = '';
  for (const part of tail) source += (source ? ' >> ' : '') + part.engine + '=' + part.body;
  return [...parts.slice(0, capture + 1), { engine: 'internal:has', body: JSON.stringify(source) }];
}

// Playwright 1.64.1 createAttributeMatcher: a regexp tests the value, an exact
// case-sensitive part compares it, and every other part is a case-insensitive
// substring test. Reached only after the CSS name/attribute lookup, so the
// value is always a string.
function rawAttributeMatcher(attribute, refusal) {
  const { value, caseSensitive } = attribute;
  if (value instanceof RegExp) {
    return actual => { value.lastIndex = 0; return !!actual.match(value); };
  }
  if (caseSensitive) return actual => actual === value;
  if (typeof value !== 'string') throw refusal;
  const lowerCaseValue = value.toLowerCase();
  return actual => actual.toLowerCase().includes(lowerCaseValue);
}

// Playwright 1.64.1 getElementLabels without the optional skipRefsInsideElement
// mode the label engine does not pass: aria-labelledby, then a non-empty
// aria-label, then the native labels list for labelable controls. Text facts
// reuse the bounded raw text acquisition, so a protected label is unavailable
// instead of being invented.
function rawElementLabels(element) {
  matcherStep();
  const labelledBy = roleGetAriaLabelledByElements(element);
  if (labelledBy) {
    const facts = [];
    for (const label of labelledBy) {
      const value = rawTextFacts(label);
      if (value !== null) facts.push(value);
    }
    return facts;
  }
  const ariaLabel = element.getAttribute('aria-label');
  if (ariaLabel !== null && !!ariaLabel.trim()) {
    return [{ full: ariaLabel, normalized: roleNormalizeWhiteSpace(ariaLabel), immediate: [ariaLabel] }];
  }
  const isNonHiddenInput = element.nodeName === 'INPUT' && element.type !== 'hidden';
  if (['BUTTON', 'METER', 'OUTPUT', 'PROGRESS', 'SELECT', 'TEXTAREA'].includes(element.nodeName) || isNonHiddenInput) {
    const labels = element.labels;
    if (labels) {
      const facts = [];
      for (const label of labels) {
        const value = rawTextFacts(label);
        if (value !== null) facts.push(value);
      }
      return facts;
    }
  }
  return [];
}
