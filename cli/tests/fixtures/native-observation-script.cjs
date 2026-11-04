// Read the exact production Rust string, including compile-time JS fragments.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
module.exports = function productionScript(filename, name) {
  const source = fs.readFileSync(filename, 'utf8');
  const start = source.indexOf(`const ${name}: &str = `);
  assert.notEqual(start, -1, `${name} production script is present`);
  const rest = source.slice(start);
  const declaration = rest.match(/^const \w+: &str = (?:r#"[\s\S]*?"#;|concat!\([\s\S]*?\n\);)/);
  assert.ok(declaration, `${name} has a supported Rust string initializer`);
  return [...declaration[0].matchAll(/r#"([\s\S]*?)"#|include_str!\("([^"]+)"\)/g)]
    .map(part => part[1] ?? fs.readFileSync(path.join(path.dirname(filename), part[2]), 'utf8')).join('');
};
