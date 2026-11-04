// Copyright (c) Microsoft Corporation. Licensed under the Apache License, Version 2.0.
// Adapted from Playwright 1.64.1 injectedScript.ts createTextMatcher/cssUnquote.
// Candidate primitive only: not wired into the production selector dispatcher.
// Caller supplies bounded, policy-approved text facts {full, normalized, immediate};
// this helper never reads DOM/value/attributes or widens issued query scope.
function compileSelectorTextMatcher(body, internal) {
  if (body[0] === '/' && body.lastIndexOf('/') > 0) {
    const lastSlash = body.lastIndexOf('/');
    const re = new RegExp(body.substring(1, lastSlash), body.substring(lastSlash + 1));
    return { kind: 'regex', matcher: text => { re.lastIndex = 0; return re.test(text.full); } };
  }
  function rawUnquote(value) {
    value = value.substring(1, value.length - 1);
    if (!value.includes('\\')) return value;
    const out = [];
    for (let index = 0; index < value.length; index++) {
      if (value[index] === '\\' && index + 1 < value.length) index++;
      out.push(value[index]);
    }
    return out.join('');
  }
  const unquote = internal ? JSON.parse.bind(JSON) : rawUnquote;
  let strict = false;
  if (body.length > 1 && body[0] === '"' && body[body.length - 1] === '"') {
    body = unquote(body); strict = true;
  } else if (internal && body.length > 1 && body[0] === '"' && body[body.length - 2] === '"' && body[body.length - 1] === 'i') {
    body = unquote(body.substring(0, body.length - 1));
  } else if (internal && body.length > 1 && body[0] === '"' && body[body.length - 2] === '"' && body[body.length - 1] === 's') {
    body = unquote(body.substring(0, body.length - 1)); strict = true;
  } else if (body.length > 1 && body[0] === "'" && body[body.length - 1] === "'") {
    body = unquote(body); strict = true;
  }
  const normalize = value => value.replace(/[\u200b\u00ad]/g, '').trim().replace(/\s+/g, ' ');
  body = normalize(body);
  if (strict) {
    if (internal) return { kind: 'strict', matcher: text => text.normalized === body };
    return { kind: 'strict', matcher: text => (!body && !text.immediate.length) || text.immediate.some(value => normalize(value) === body) };
  }
  body = body.toLowerCase();
  return { kind: 'lax', matcher: text => text.normalized.toLowerCase().includes(body) };
}
