// Mandatory opt-in synthetic-browser producer evidence. This script never loads
// a business URL, profile or model. It preserves each original action budget.
// A successful evidence run is not automatically a successful retirement.
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { findCurrentTargetDetach } = require('./native-action-detach-witness.cjs');

const scenario = process.argv[2];
assert(['noneditable', 'closed-page', 'aim-blocked', 'aim-centre', 'aim-pointer'].includes(scenario));
const runtime = path.resolve(process.env.E2E_RETIREMENT_RUNTIME || '');
const e2eRoot = path.resolve(process.env.E2E_RETIREMENT_E2E_ROOT || '');
const chrome = path.resolve(process.env.E2E_CHROMIUM_EXECUTABLE || '');
const output = path.resolve(process.env.E2E_RETIREMENT_OUTPUT || '');
assert.equal(process.env.E2E_RETIREMENT_TEMP_CONTAINER, '1', 'temporary synthetic container authorization must be explicit');
for (const key of ['E2E_RETIREMENT_RUNTIME', 'E2E_RETIREMENT_E2E_ROOT', 'E2E_CHROMIUM_EXECUTABLE', 'E2E_RETIREMENT_OUTPUT']) assert(process.env[key], `${key} is required`);
const timeoutMs = scenario.startsWith('aim-') ? 7 : 5000;
const operation = (timeout = 5000) => ({ timeoutMs: timeout, signal: AbortSignal.timeout(timeout), runId: 'retirement-synthetic', attemptId: scenario, origin: 'test' });
const record = { scenario, actionTimeoutMs: timeoutMs, oldIdentity: { noneditable: 6, 'closed-page': 7, 'aim-blocked': 21, 'aim-centre': 22, 'aim-pointer': 23 }[scenario], status: 'failed', retirementEligible: false, events: [], protocol: [], cdp: [], controlCdp: [], cleanup: {} };
const sockets = new Set();
let chromeChild, client, control, proxy, server, directory, socketDirectory;
let chromeExited = false;
let cdpComplete = true;

async function bounded(test, ms, label) {
  const until = performance.now() + ms;
  do { const value = await test(); if (value) return value; await new Promise(resolve => setTimeout(resolve, 10)); } while (performance.now() < until);
  throw new Error(`bounded synthetic fixture deadline: ${label}`);
}
function listen(server) { return new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); }); }
function connect(url) { return new Promise((resolve, reject) => { const ws = new WebSocket(url); ws.addEventListener('open', () => resolve(ws), { once: true }); ws.addEventListener('error', reject, { once: true }); }); }
function controller(ws) {
  let id = 0;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const reply = JSON.parse(String(event.data));
    record.controlCdp.push({ direction: 'reply', atMs: performance.now(), message: reply });
    const entry = pending.get(reply.id);
    if (entry) { pending.delete(reply.id); clearTimeout(entry.timer); reply.error ? entry.reject(new Error(JSON.stringify(reply.error))) : entry.resolve(reply.result); }
  });
  return (method, params = {}) => new Promise((resolve, reject) => {
    const current = ++id;
    const timer = setTimeout(() => { pending.delete(current); reject(new Error(`control CDP deadline: ${method}`)); }, 5000);
    pending.set(current, { resolve, reject, timer });
    record.controlCdp.push({ direction: 'request', atMs: performance.now(), message: { id: current, method, params } });
    ws.send(JSON.stringify({ id: current, method, params }));
  });
}

// The proxy forwards every byte unchanged. The independent decoder observes
// complete uncompressed WebSocket JSON messages; incomplete evidence fails.
function observer(direction) {
  let bytes = Buffer.alloc(0), upgraded = false, fragments = [], fragmented = false;
  const observe = chunk => {
    bytes = Buffer.concat([bytes, chunk]);
    assert(bytes.length <= 4 * 1024 * 1024, 'bounded CDP observation buffer');
    if (!upgraded) {
      const end = bytes.indexOf('\r\n\r\n');
      if (end < 0) return;
      bytes = bytes.subarray(end + 4); upgraded = true;
    }
    while (bytes.length >= 2) {
      const fin = (bytes[0] & 128) !== 0, opcode = bytes[0] & 15, masked = (bytes[1] & 128) !== 0;
      assert.equal(bytes[0] & 112, 0, 'compression is not silently decoded or ignored');
      let length = bytes[1] & 127, at = 2;
      if (length === 126) { if (bytes.length < 4) return; length = bytes.readUInt16BE(2); at = 4; }
      else if (length === 127) { if (bytes.length < 10) return; length = Number(bytes.readBigUInt64BE(2)); at = 10; }
      assert(Number.isSafeInteger(length) && length <= 4 * 1024 * 1024);
      if (bytes.length < at + (masked ? 4 : 0) + length) return;
      const mask = masked ? bytes.subarray(at, at + 4) : null;
      if (mask) at += 4;
      const body = Buffer.from(bytes.subarray(at, at + length));
      bytes = bytes.subarray(at + length);
      if (mask) for (let i = 0; i < body.length; i++) body[i] ^= mask[i % 4];
      if (opcode >= 8) continue;
      assert(opcode === 0 || opcode === 1, 'CDP uses text frames');
      if (opcode === 1) { assert(!fragmented); fragments = []; }
      else assert(fragmented);
      fragments.push(body); fragmented = !fin;
      if (fin) {
        const message = JSON.parse(Buffer.concat(fragments).toString());
        record.cdp.push({ direction, atMs: performance.now(), message });
        fragments = [];
      }
    }
  };
  observe.finish = () => { assert.equal(bytes.length, 0, 'no unobserved partial CDP frame'); assert.equal(fragmented, false, 'no unobserved fragmented CDP message'); };
  return observe;
}

(async () => {
  await fs.mkdir(output, { recursive: true });
  directory = await fs.mkdtemp(path.join(output, 'owned-synthetic-'));
  socketDirectory = await fs.mkdtemp('/tmp/ab-retirement-socket-');
  const profile = path.join(directory, 'chromium-profile');
  await fs.mkdir(profile);
  const blocked = scenario === 'aim-blocked';
  const html = `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;width:1280px;height:1500px}#target{position:absolute;left:600px;top:100px}#scroll{position:absolute;left:0;top:0;box-sizing:border-box;width:400px;height:300px;overflow:auto}#scroll>div{width:2000px;height:2000px}${blocked ? '#overlay{position:absolute;left:180px;top:130px;width:40px;height:40px;background:black}' : ''}</style></head><body><div id="noneditable" tabindex="0">Plain noneditable target</div><button id="target">Close target</button><div id="scroll" tabindex="0"><div>Scrollable synthetic content</div></div>${blocked ? '<div id="overlay"></div>' : ''}</body></html>`;
  server = http.createServer((request, response) => {
    if (request.url === '/favicon.ico') { response.writeHead(204); response.end(); return; }
    if (request.url !== '/synthetic') { response.writeHead(404); response.end(); return; }
    response.writeHead(200, { 'content-type': 'text/html' }); response.end(html);
  });
  const port = await listen(server);
  const flags = ['--headless=new', '--no-sandbox', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-dev-shm-usage', '--disable-extensions', '--no-proxy-server', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1', 'about:blank'];
  record.chromium = { executable: chrome, version: execFileSync(chrome, ['--version'], { encoding: 'utf8' }).trim(), flags: flags.map(flag => flag.startsWith('--user-data-dir=') ? '--user-data-dir=<owned temporary profile>' : flag) };
  chromeChild = spawn(chrome, flags, { stdio: ['ignore', 'ignore', 'pipe'] });
  let chromeError = '';
  chromeChild.stderr.on('data', data => { chromeError = (chromeError + data.toString()).slice(-65536); });
  chromeChild.once('exit', () => { chromeExited = true; });
  const active = await bounded(async () => { try { return (await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n'); } catch { if (chromeExited) throw new Error(chromeError); return null; } }, 5000, 'owned Chrome startup');
  const endpoint = `ws://127.0.0.1:${active[0]}${active[1]}`;
  control = await connect(endpoint);
  const cdp = controller(control);
  const originalContexts = (await cdp('Target.getBrowserContexts')).browserContextIds;
  proxy = net.createServer(downstream => {
    const upstream = net.connect(Number(active[0]), '127.0.0.1');
    sockets.add(downstream); sockets.add(upstream);
    for (const socket of [downstream, upstream]) { socket.on('close', () => sockets.delete(socket)); socket.on('error', () => { downstream.destroy(); upstream.destroy(); }); }
    for (const [socket, direction] of [[downstream, 'request'], [upstream, 'reply']]) {
      const observe = observer(direction);
      socket.on('data', chunk => { try { observe(chunk); } catch (error) { cdpComplete = false; record.observerFailure = String(error); downstream.destroy(); upstream.destroy(); } });
      socket.on('close', () => { try { observe.finish(); } catch (error) { cdpComplete = false; record.observerFailure = String(error); } });
    }
    downstream.pipe(upstream); upstream.pipe(downstream);
  });
  const proxyPort = await listen(proxy);
  const { connectNativeProcess } = await import(pathToFileURL(path.join(e2eRoot, 'packages/web/dist/native/process.js')));
  const { EngineChannel } = await import(pathToFileURL(path.join(e2eRoot, 'packages/web/dist/native/engine-channel.js')));
  const { BrowserChannel } = await import(pathToFileURL(path.join(e2eRoot, 'packages/web/dist/native/browser-channel.js')));
  client = await connectNativeProcess({ executable: runtime, cwd: directory, env: { PATH: process.env.PATH, TMPDIR: directory, AGENT_BROWSER_SOCKET_DIR: socketDirectory }, capabilities: [] }, operation(), async event => {
    record.events.push(event);
    if (event.event === 'network.request') {
      assert.equal(event.payload.version, 1);
      assert.deepEqual(event.payload.registrationIds, []);
      const url = new URL(event.payload.request.url);
      assert.equal(url.origin, `http://127.0.0.1:${port}`);
      assert(['/synthetic', '/favicon.ico'].includes(url.pathname));
      assert(event.decision, 'normal empty-registry requests still require their native token');
      await client.decide(event.decision.token, { kind: 'continue', overrides: {} }, operation(Math.min(5000, event.decision.timeoutMs)));
    } else assert.equal(event.decision, undefined, 'no other decision source belongs to these synthetic pages');
  });
  const originalRequest = client.request.bind(client);
  client.request = async (command, args, context, ...rest) => {
    const entry = { command, args: structuredClone(args), timeoutMs: context.timeoutMs };
    record.protocol.push(entry);
    try { entry.result = await originalRequest(command, args, context, ...rest); return entry.result; }
    catch (error) { entry.rejected = { code: error.code, retryable: error.retryable, message: error.message }; throw error; }
  };
  const engine = new EngineChannel(client);
  const opened = await engine.command('scope.open', { source: 'connect', context: 'isolated', endpoint: `ws://127.0.0.1:${proxyPort}${active[1]}`, viewport: { width: 1280, height: 720 }, media: {}, initScripts: [] }, operation());
  const identityScope = opened.identityScope;
  record.identityScope = identityScope;
  await engine.command('scope.configure', { identityScope, testIdAttribute: 'data-testid', secureFieldSelector: 'input[type="password" i]', requestPolicy: {}, downloads: { source: 'local' } }, operation());
  const browser = new BrowserChannel(client, { identityScope: () => identityScope, operation });
  await browser.command('network.routes.replace', { version: 1, registrationIds: [] }, operation());
  await browser.command('page.navigate', { url: `http://127.0.0.1:${port}/synthetic`, waitUntil: 'load' }, operation());
  const selector = scenario.startsWith('aim-') ? '#scroll' : scenario === 'noneditable' ? '#noneditable' : '#target';
  const query = await engine.command('browser.query', { identityScope, expression: { kind: 'selector', selector }, testIdAttribute: 'data-testid', secureFieldSelector: 'input[type="password" i]' }, operation());
  assert.equal(query.nodes.length, 1);
  record.reference = query.nodes[0].ref;
  assert.match(record.reference.id, /^@e[1-9]\d*$/);
  const bounds = await browser.command('page.evaluate', { source: `(selector)=>{const n=document.querySelector(selector);const r=n.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,editable:n.isContentEditable,tag:n.tagName};}`, argument: selector }, operation());
  record.originalTarget = bounds.value;
  if (scenario.startsWith('aim-')) {
    assert.deepEqual(bounds.value, { x: 0, y: 0, width: 400, height: 300, editable: false, tag: 'DIV' });
    const point = scenario === 'aim-pointer' ? { x: 200, y: 150 } : { x: 800, y: 600 };
    await engine.command('browser.pointer', { identityScope, point, action: { kind: 'hover' } }, operation());
    record.initialPointer = point;
  }
  if (scenario === 'closed-page') {
    const controlStart = record.cdp.length;
    await engine.command('browser.perform', { identityScope, ref: record.reference, action: { kind: 'tap' } }, operation());
    const input = record.cdp.slice(controlStart).filter(entry => entry.direction === 'request' && entry.message.method.startsWith('Input.'));
    assert(input.some(entry => entry.message.params.type === 'mousePressed'));
    assert(input.some(entry => entry.message.params.type === 'mouseReleased'));
    const currentSession = input.find(entry => entry.message.params.type === 'mousePressed').message.sessionId;
    assert.equal(typeof currentSession, 'string');
    assert(input.every(entry => entry.message.sessionId === currentSession));
    record.openPageTapControl = { sameReference: record.reference, currentSession, succeeded: true, cdpStart: controlStart, cdpEnd: record.cdp.length };
    const target = (await cdp('Target.getTargets')).targetInfos.find(target => target.url === `http://127.0.0.1:${port}/synthetic`);
    assert(target, 'actual page target is discovered independently');
    // Freeze immediately before sending close, on this same synchronous turn.
    // The independent control/observer sockets provide no ACK/detach ordering.
    record.closeBoundary = Object.freeze({ startIndex: record.cdp.length, targetId: target.targetId, sessionId: currentSession });
    assert.equal((await cdp('Target.closeTarget', { targetId: target.targetId })).success, true);
    await bounded(async () => !(await cdp('Target.getTargets')).targetInfos.some(current => current.targetId === target.targetId), 1000, 'actual target closure');
    record.detachWitness = await bounded(() => findCurrentTargetDetach(record.cdp, record.closeBoundary), 1000, 'current native session detaches after actual target closure');
    record.closedTarget = target.targetId;
    assert.equal((await cdp('Browser.getVersion')).product.startsWith('Chrome/'), true, 'browser connection remains live after only the page closes');
  }
  const before = record.cdp.length;
  record.actionProtocolIndex = record.protocol.length;
  record.action = scenario === 'noneditable' ? { kind: 'fill', value: 'synthetic plain value', sensitive: false } : scenario === 'closed-page' ? { kind: 'tap' } : { kind: 'swipe', direction: 'down' };
  const started = performance.now();
  try { record.actionValue = await engine.command('browser.perform', { identityScope, ref: record.reference, action: record.action }, operation(timeoutMs)); record.actionSucceeded = true; }
  catch (error) { record.publicFailure = { code: error.code, retryable: error.retryable, message: error.message }; record.actionSucceeded = false; }
  record.elapsedMs = performance.now() - started;
  record.actionCdpStart = before;
  record.actionCdpEnd = record.cdp.length;
  assert(cdpComplete, 'all observed CDP messages must be readable');
  if (scenario === 'closed-page') {
    const request = record.protocol[record.actionProtocolIndex];
    assert.equal(request.command, 'browser.perform');
    assert.deepEqual(request.args, { identityScope, ref: record.reference, action: { kind: 'tap' } });
    assert.equal(request.result.error.code, 'browser-failure');
    assert.equal(request.result.effects, 'not-dispatched');
    assert.equal(request.result.scopeState, 'usable');
    assert.equal(record.cdp.slice(before).filter(entry => entry.direction === 'request' && entry.message.method.startsWith('Input.')).length, 0);
    assert.deepEqual(record.publicFailure, { code: 'ENGINE_FAILURE', retryable: false, message: 'The native browser operation failed (browser-failure)' });
  }
  if (scenario.startsWith('aim-')) assert.equal(record.actionSucceeded, false, 'current stable-center action cannot establish original7ms success');
  if (scenario === 'noneditable') assert.equal(record.actionSucceeded, false);
  record.status = 'evidence-complete';
  try { await engine.command('scope.end', { identityScope }, operation(1000)); record.cleanup.scopeEnd = 'acknowledged'; }
  catch (error) { record.cleanup.scopeEnd = { code: error.code }; }
  try { await client.close(operation(1000)); record.cleanup.clientClose = 'acknowledged'; }
  catch (error) { record.cleanup.clientClose = { code: error.code }; }
  await bounded(async () => { const contexts = (await cdp('Target.getBrowserContexts')).browserContextIds; record.cleanup.remainingContexts = contexts; return contexts.length === originalContexts.length && contexts.every(id => originalContexts.includes(id)); }, 3000, 'borrowed test context cleanup');
  record.cleanup.contextsRestored = true;
  if (scenario === 'closed-page') {
    assert.equal(record.cleanup.scopeEnd, 'acknowledged');
    assert.equal(record.cleanup.clientClose, 'acknowledged');
    assert.equal(record.protocol.filter(entry => entry.command === 'browser.perform').length, 2, 'one positive control and one closed-page tap; no action retry');
    assert.equal(record.cdp.slice(before).filter(entry => entry.direction === 'request' && entry.message.method.startsWith('Input.')).length, 0, 'no late input during cleanup');
  }
})().catch(error => { record.status = 'failed'; record.failure = { message: error.message, stack: error.stack }; process.exitCode = 1; }).finally(async () => {
  if (client) { try { await client.close(operation(1000)); } catch {} }
  if (control) control.close();
  for (const socket of sockets) socket.destroy();
  if (proxy) await new Promise(resolve => proxy.close(resolve));
  if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  if (chromeChild && !chromeExited) { chromeChild.kill('SIGTERM'); try { await bounded(() => chromeExited, 3000, 'owned Chrome exit'); } catch { chromeChild.kill('SIGKILL'); await bounded(() => chromeExited, 1000, 'owned Chrome reap'); } }
  record.cleanup.chromeExited = chromeExited;
  if (directory) { await fs.rm(directory, { recursive: true, force: true }); record.cleanup.profileRemoved = true; }
  if (socketDirectory) { await fs.rm(socketDirectory, { recursive: true, force: true }); record.cleanup.socketDirectoryRemoved = true; }
  record.observerComplete = cdpComplete;
  if (!cdpComplete) { record.status = 'failed'; process.exitCode = 1; }
  record.retirementEligible = scenario === 'closed-page' && record.status === 'evidence-complete' && cdpComplete && record.cleanup.contextsRestored && chromeExited && record.cleanup.profileRemoved && record.cleanup.socketDirectoryRemoved;
  record.runtimeSha256 = createHash('sha256').update(await fs.readFile(runtime)).digest('hex');
  await fs.mkdir(output, { recursive: true });
  await fs.writeFile(path.join(output, `${scenario}.json`), JSON.stringify(record, null, 2) + '\n');
  console.log(JSON.stringify({ scenario, status: record.status, retirementEligible: record.retirementEligible, publicFailure: record.publicFailure, cleanup: record.cleanup, output: path.join(output, `${scenario}.json`) }));
});
