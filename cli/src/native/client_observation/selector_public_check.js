// Original E2E/Playwright public-query checks are not selector-engine rules.
// Attribute/XPath/text :light engines remain usable in unchecked nested projections.
// This path covers the supported deprecated engines, never css:light.
const deprecatedLightSelector = {};
const deprecatedLightEngines = new Set([
  'id:light', 'data-testid:light', 'data-test-id:light', 'data-test:light', 'xpath:light', 'text:light',
]);
function hasDeprecatedLightSelector(x) {
  // validate_expression already bounds depth/nodes; do not charge ordinary queries.
  if (x.kind === 'selector' && x.nativeParts.some(p => deprecatedLightEngines.has(p.engine))) return true;
  return ['source', 'scope', 'has', 'left', 'right'].some(key => x[key] && hasDeprecatedLightSelector(x[key]));
}
// Only the left/outer chain contributes to Playwright's nonrecursive check.
// A has target is checked separately; a union's right branch is not.
function deprecatedLightInProjection(x) {
  if (x.kind === 'selector') return x.nativeParts.some(p => deprecatedLightEngines.has(p.engine));
  if (x.kind === 'query') return x.scope ? deprecatedLightInProjection(x.scope) : false;
  if (x.kind === 'union') return deprecatedLightInProjection(x.left);
  return x.source ? deprecatedLightInProjection(x.source) : false;
}
function checkedPublicProjection(x, scope, root) {
  const indices = evaluatePublicProjection(x, scope, root);
  if (indices.length && deprecatedLightInProjection(x)) throw deprecatedLightSelector;
  return indices;
}
function plainPublicProjection(locator) {
  return { locator, composable: null, predicate: null, steps: [] };
}
// Mirror only e557 locators.ts project/requireComposable. All selector leaves,
// semantic predicates, scope membership and engine execution remain native.
function compilePublicProjection(x) {
  matcherStep();
  const composable = p => p.composable || p.locator;
  switch (x.kind) {
    case 'selector': return plainPublicProjection(x);
    case 'query': {
      const exactLabel = x.query.kind === 'label' && x.query.value.kind === 'string' && x.query.value.exact;
      const value = x.query.kind === 'displayValue';
      const locator = { ...x, scope: x.scope ? composable(compilePublicProjection(x.scope)) : undefined, publicValueCandidates: value };
      return { locator, composable: exactLabel ? locator : null, predicate: value || exactLabel ? x.query : null, steps: [] };
    }
    case 'union':
      return plainPublicProjection({ ...x, left: composable(compilePublicProjection(x.left)), right: composable(compilePublicProjection(x.right)) });
    case 'filter': {
      const source = compilePublicProjection(x.source);
      const options = { hasText: x.hasText, has: x.has ? composable(compilePublicProjection(x.has)) : undefined };
      if (source.steps.length) return { ...source, steps: [...source.steps, { kind: 'filter', ...options }] };
      const filtered = locator => ({ kind: 'filter', source: locator, ...options });
      return { ...source, locator: filtered(source.locator), composable: source.composable ? filtered(source.composable) : null };
    }
    case 'index': {
      const source = compilePublicProjection(x.source);
      const positioned = locator => ({ kind: 'index', source: locator, index: x.index });
      if (source.predicate) return { ...source, composable: source.composable ? positioned(source.composable) : null, steps: [...source.steps, { kind: 'index', index: x.index }] };
      return plainPublicProjection(positioned(source.locator));
    }
    default: throw new Error('Frame expression must be resolved by native frame scope');
  }
}
// This private projection evaluator differs from evaluate only at public
// boundaries and at the display-value candidate stage. It is not a new parser.
function evaluatePublicProjection(x, scope = all, root = document) {
  matcherStep();
  switch (x.kind) {
    case 'selector': return selectChain(x.nativeParts, scope, root);
    case 'query': {
      const roots = x.scope ? evaluatePublicProjection(x.scope, scope, root) : null;
      const candidates = roots ? scope.filter(i => roots.some(parent => contains(parent, i))) : scope;
      return candidates.filter(i => x.publicValueCandidates
        ? (!x.query.visible || !data[i].states.hidden) && elements[i].matches('input:not([type="checkbox" i]):not([type="radio" i]),textarea,select')
        : semantic(x.query, i));
    }
    case 'union': {
      const matches = new Set([...evaluatePublicProjection(x.left, scope, root), ...evaluatePublicProjection(x.right, scope, root)]);
      return scope.filter(i => matches.has(i));
    }
    case 'filter':
      return evaluatePublicProjection(x.source, scope, root).filter(i =>
        (!x.hasText || matchFilterText(x.hasText, elements[i])) &&
        (!x.has || checkedPublicProjection(x.has, scope.filter(j => contains(i, j)), elements[i]).length > 0));
    case 'index': {
      const matches = evaluatePublicProjection(x.source, scope, root);
      const index = x.index === 'first' ? 0 : x.index === 'last' ? matches.length - 1 : x.index;
      return index >= 0 && index < matches.length ? [matches[index]] : [];
    }
    default: throw new Error('Unknown public projection');
  }
}
function evaluatePublicLightExpression(expression) {
  const projected = compilePublicProjection(expression);
  const raw = checkedPublicProjection(projected.locator, all, document);
  let selected = raw.map((index, position) => ({ index, position }));
  if (projected.predicate) selected = selected.filter(({ index }) => semantic(projected.predicate, index));
  for (const step of projected.steps) {
    matcherStep();
    if (step.kind === 'index') {
      const index = step.index === 'first' ? 0 : step.index === 'last' ? selected.length - 1 : step.index;
      selected = index >= 0 && index < selected.length ? [selected[index]] : [];
    } else {
      // The old surface counts rawLocator.nth(rawPosition).filter(options).
      // It runs only for matches surviving the predicate and preceding steps.
      selected = selected.filter(({ position }) => checkedPublicProjection({
        kind: 'filter', source: { kind: 'index', source: projected.locator, index: position },
        hasText: step.hasText, has: step.has,
      }, all, document).length > 0);
    }
  }
  return selected.map(({ index }) => index);
}
