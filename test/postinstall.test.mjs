import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync, readlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

// Exercise the real lifecycle script in an isolated package. No actual binary,
// network, npm-global modification, or platform emulation is executed.
function fixture(t, platform, arch, global = false) {
  const root = mkdtempSync(join(tmpdir(), 'fork-postinstall-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, 'scripts'));
  mkdirSync(join(root, 'bin'));
  mkdirSync(join(root, 'global', 'bin'), {recursive: true});
  writeFileSync(join(root, 'package.json'), '{"type":"module","version":"0.39.1"}');
  copyFileSync(fileURLToPath(new URL('../scripts/postinstall.js', import.meta.url)), join(root, 'scripts/postinstall.js'));
  writeFileSync(join(root, 'guard.mjs'), `
    import https from 'node:https';
    import http from 'node:http';
    import os from 'node:os';
    import cp from 'node:child_process';
    import {writeFileSync} from 'node:fs';
    import {syncBuiltinESMExports} from 'node:module';
    const network = () => {writeFileSync(${JSON.stringify(join(root, 'network-called'))}, 'yes'); throw new Error('network forbidden');};
    https.get = https.request = http.get = http.request = network;
    globalThis.fetch = network;
    os.platform = () => ${JSON.stringify(platform)};
    os.arch = () => ${JSON.stringify(arch)};
    cp.execSync = (command) => {
      if (command === 'npm prefix -g') {
        writeFileSync(${JSON.stringify(join(root, 'global-probed'))}, 'yes');
        return ${JSON.stringify(join(root, 'global'))};
      }
      throw new Error('system commands disabled in synthetic fixture');
    };
    syncBuiltinESMExports();
  `);
  return {root, run() {
    return spawnSync(process.execPath, ['--import', join(root, 'guard.mjs'), join(root, 'scripts/postinstall.js')], {
      cwd: root, env: {...process.env, npm_config_user_agent: 'npm/11.0.0', npm_config_global: String(global)}, encoding: 'utf8', timeout: 5000,
    });
  }};
}

for (const arch of ['arm64', 'x64']) {
  test(`darwin ${arch} missing fork binary fails without upstream download or success marker`, (t) => {
    const {root, run} = fixture(t, 'darwin', arch);
    const result = run();
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, new RegExp(`No bundled fork native binary supplied for darwin-${arch}`));
    assert.match(result.stderr, /Upstream download is disabled/);
    assert.match(result.stderr, /pnpm install --frozen-lockfile --ignore-scripts, then pnpm run build:native/);
    assert.doesNotMatch(result.stdout, /ready|Downloaded|Optimized/);
    assert.equal(existsSync(join(root, 'network-called')), false);
    assert.equal(existsSync(join(root, 'bin', '.install-method')), false);
  });
  test(`darwin ${arch} bundled binary is retained without network or execution`, (t) => {
    const {root, run} = fixture(t, 'darwin', arch);
    const binary = join(root, 'bin', `agent-browser-darwin-${arch}`);
    writeFileSync(binary, 'synthetic bytes, not executable code');
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Native binary ready/);
    assert.equal(readFileSync(binary, 'utf8'), 'synthetic bytes, not executable code');
    assert.equal(readFileSync(join(root, 'bin', '.install-method'), 'utf8'), 'npm');
    assert.equal(existsSync(join(root, 'network-called')), false);
  });
}

test('other-architecture bundled bytes never satisfy the requested platform', (t) => {
  const {root, run} = fixture(t, 'darwin', 'arm64');
  writeFileSync(join(root, 'bin', 'agent-browser-darwin-x64'), 'wrong architecture fixture');
  assert.equal(run().status, 1);
  assert.equal(existsSync(join(root, 'network-called')), false);
  assert.equal(existsSync(join(root, 'bin', '.install-method')), false);
});

for (const global of [false, true]) {
  test(`${global ? 'global' : 'local'} install preserves a foreign global symlink`, (t) => {
    const {root, run} = fixture(t, 'darwin', 'arm64', global);
    writeFileSync(join(root, 'bin', 'agent-browser-darwin-arm64'), 'synthetic native');
    const foreign = join(root, 'foreign-wrapper.js');
    writeFileSync(foreign, 'foreign fixture');
    const shim = join(root, 'global', 'bin', 'agent-browser');
    symlinkSync(foreign, shim);
    assert.equal(run().status, 0);
    assert.equal(readlinkSync(shim), foreign);
    assert.equal(readFileSync(foreign, 'utf8'), 'foreign fixture');
    assert.equal(existsSync(join(root, 'global-probed')), global);
  });
}

test('explicit global install optimizes only its own existing wrapper symlink', (t) => {
  const {root, run} = fixture(t, 'darwin', 'arm64', true);
  const binary = join(root, 'bin', 'agent-browser-darwin-arm64');
  writeFileSync(binary, 'synthetic native');
  const wrapper = join(root, 'bin', 'agent-browser.js');
  writeFileSync(wrapper, 'synthetic wrapper');
  const shim = join(root, 'global', 'bin', 'agent-browser');
  symlinkSync(wrapper, shim);
  assert.equal(run().status, 0);
  assert.equal(readlinkSync(shim), binary);
  assert.equal(run().status, 0);
  assert.equal(readlinkSync(shim), binary);
});

test('global install preserves unknown regular shim files', (t) => {
  const {root, run} = fixture(t, 'darwin', 'arm64', true);
  writeFileSync(join(root, 'bin', 'agent-browser-darwin-arm64'), 'synthetic native');
  const shim = join(root, 'global', 'bin', 'agent-browser');
  writeFileSync(shim, 'unknown wrapper');
  assert.equal(run().status, 0);
  assert.equal(readFileSync(shim, 'utf8'), 'unknown wrapper');
});

for (const global of [false, true]) {
  test(`Windows ${global ? 'global' : 'local'} install preserves package-manager and foreign shims`, (t) => {
    const {root, run} = fixture(t, 'win32', 'x64', global);
    writeFileSync(join(root, 'bin', 'agent-browser-win32-x64.exe'), 'synthetic native');
    const paths = ['agent-browser.cmd', 'agent-browser.ps1'].map((name) => join(root, 'global', name));
    for (const path of paths) writeFileSync(path, 'existing shim content');
    assert.equal(run().status, 0);
    for (const path of paths) assert.equal(readFileSync(path, 'utf8'), 'existing shim content');
    assert.equal(existsSync(join(root, 'global-probed')), false);
  });
}
