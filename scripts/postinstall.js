#!/usr/bin/env node

/**
 * Postinstall script for agent-browser
 * 
 * Requires a bundled platform-native binary for this fork; never downloads upstream bytes.
 * On global installs, patches npm's bin entry to use the native binary directly:
 * - Windows: Preserves package-manager shims and the existing Node launcher
 * - Mac/Linux: Optimizes only an explicitly global, package-owned symlink
 */

import { existsSync, chmodSync, unlinkSync, writeFileSync, symlinkSync, lstatSync, realpathSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { platform, arch } from 'os';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, '..');
const binDir = join(projectRoot, 'bin');

// Detect if the system uses musl libc (e.g. Alpine Linux)
function isMusl() {
  if (platform() !== 'linux') return false;
  try {
    const result = execSync('ldd --version 2>&1 || true', { encoding: 'utf8' });
    return result.toLowerCase().includes('musl');
  } catch {
    return existsSync('/lib/ld-musl-x86_64.so.1') || existsSync('/lib/ld-musl-aarch64.so.1');
  }
}

// Platform detection
const osKey = platform() === 'linux' && isMusl() ? 'linux-musl' : platform();
// Windows ARM64 falls back to x64 binary (no native ARM64 build available).
// x64 binaries run via Windows' built-in emulation on ARM64.
const effectiveArch = platform() === 'win32' && arch() === 'arm64' ? 'x64' : arch();
const platformKey = `${osKey}-${effectiveArch}`;
const ext = platform() === 'win32' ? '.exe' : '';
const binaryName = `agent-browser-${platformKey}${ext}`;
const binaryPath = join(binDir, binaryName);

/**
 * Detect which package manager ran this postinstall and write a marker file
 * next to the binary so `agent-browser upgrade` can use the correct one
 * without fragile path heuristics or slow subprocess probing.
 *
 * npm_config_user_agent is set by npm/pnpm/yarn/bun during lifecycle scripts,
 * e.g. "pnpm/8.10.0 node/v20.10.0 linux x64"
 */
function writeInstallMethod() {
  const ua = process.env.npm_config_user_agent || '';
  let method = '';
  if (ua.startsWith('pnpm/')) method = 'pnpm';
  else if (ua.startsWith('yarn/')) method = 'yarn';
  else if (ua.startsWith('bun/')) method = 'bun';
  else if (ua.startsWith('npm/')) method = 'npm';

  if (method) {
    try {
      writeFileSync(join(binDir, '.install-method'), method);
    } catch {
      // Non-critical — upgrade will fall back to heuristics
    }
  }
}

async function main() {
  // Check if binary already exists
  if (existsSync(binaryPath)) {
    // Ensure binary is executable (npm doesn't preserve execute bit)
    if (platform() !== 'win32') {
      chmodSync(binaryPath, 0o755);
    }
    console.log(`✓ Native binary ready: ${binaryName}`);

    writeInstallMethod();

    // On global installs, fix npm's bin entry to use native binary directly
    await fixGlobalInstallBin();

    showInstallReminder();
    return;
  }

  // This fork requires native capabilities absent from the upstream release.
  // A matching package version alone cannot establish binary provenance.
  throw new Error(
    `No bundled fork native binary supplied for ${platformKey} (${binaryName}). ` +
    'Upstream download is disabled. Use the source-bound verified e2e candidate bundle, ' +
    'or prepare this exact fork checkout with pnpm install --frozen-lockfile --ignore-scripts, then pnpm run build:native.'
  );
}

function findSystemChrome() {
  const os = platform();
  if (os === 'darwin') {
    const candidates = [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
    ];
    return candidates.find(p => existsSync(p)) || null;
  }
  if (os === 'linux') {
    const names = ['google-chrome', 'google-chrome-stable', 'chromium-browser', 'chromium'];
    for (const name of names) {
      try {
        const result = execSync(`which ${name} 2>/dev/null`, { encoding: 'utf8' }).trim();
        if (result) return result;
      } catch {}
    }
    return null;
  }
  if (os === 'win32') {
    const candidates = [
      `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    ];
    return candidates.find(p => p && existsSync(p)) || null;
  }
  return null;
}

function showInstallReminder() {
  const systemChrome = findSystemChrome();
  if (systemChrome) {
    console.log('');
    console.log(`  ✓ System Chrome found: ${systemChrome}`);
    console.log('    agent-browser will use it automatically.');
    console.log('');
    return;
  }

  console.log('');
  console.log('  ⚠ No Chrome installation detected.');
  console.log('  If you plan to use a local browser, run:');
  console.log('');
  console.log('    agent-browser install');
  if (platform() === 'linux') {
    console.log('');
    console.log('  On Linux, include system dependencies with:');
    console.log('');
    console.log('    agent-browser install --with-deps');
  }
  console.log('');
  console.log('  You can skip this if you use --cdp, --provider, --engine, or --executable-path.');
  console.log('');
}

/**
 * Fix npm's bin entry on global installs to use the native binary directly.
 * This provides zero-overhead CLI execution for global installs.
 */
async function fixGlobalInstallBin() {
  // Local installs must never rewrite a different global installation.
  if (process.env.npm_config_global !== 'true') return;
  // Keep package-manager-owned Windows shims intact. The existing Node launcher
  // selects the same native executable; unknown shim contents are not ownership.
  if (platform() === 'win32') return;
  await fixUnixSymlink();
}

/**
 * Fix npm symlink on Mac/Linux global installs.
 * Replace the symlink to the JS wrapper with a symlink to the native binary.
 */
async function fixUnixSymlink() {
  // Get npm's global bin directory (npm prefix -g + /bin)
  let npmBinDir;
  try {
    const prefix = execSync('npm prefix -g', { encoding: 'utf8' }).trim();
    npmBinDir = join(prefix, 'bin');
  } catch {
    return; // npm not available
  }

  const symlinkPath = join(npmBinDir, 'agent-browser');

  // Check if symlink exists (indicates global install)
  try {
    const stat = lstatSync(symlinkPath);
    if (!stat.isSymbolicLink()) {
      return; // Not a symlink, don't touch it
    }
    const target = realpathSync(symlinkPath);
    const ownedTargets = [binaryPath, join(binDir, 'agent-browser.js')]
      .filter(existsSync).map((path) => realpathSync(path));
    if (!ownedTargets.includes(target)) return;
    if (target === realpathSync(binaryPath)) return; // Already optimized.

  } catch {
    return; // Symlink doesn't exist, not a global install
  }

  // Replace symlink to point directly to native binary
  try {
    unlinkSync(symlinkPath);
    symlinkSync(binaryPath, symlinkPath);
    console.log('✓ Optimized: symlink points to native binary (zero overhead)');
  } catch (err) {
    // Permission error or other issue - not critical, JS wrapper still works
    console.log(`⚠ Could not optimize symlink: ${err.message}`);
    console.log('  CLI will work via Node.js wrapper (slightly slower startup)');
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
