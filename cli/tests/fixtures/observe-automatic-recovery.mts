// Joint real-Chromium test with a cfg(test) inventory scheduling rendezvous.
// One public observe() call uses built, unmodified NativeSurface and native core.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const checkout = process.env['OBSERVE_BRIDGE_E2E_CHECKOUT'];
const evidence = process.env['OBSERVE_AUTOMATIC_EVIDENCE'];
assert.ok(checkout); assert.ok(evidence);
const { web, surfaceOf } = await import(pathToFileURL(path.join(checkout, 'packages/web/dist/index.js')).href);
const { endpoint } = JSON.parse(readFileSync(process.env['OBSERVE_AUTOMATIC_READY']!, 'utf8'));
const server = createServer((_request, response) => {
  response.writeHead(200, { 'content-type': 'text/html' });
  // Fix the synthetic page's resource inventory: URL churn must not schedule
  // implicit favicon requests while the observation authorization is consumed.
  response.end(`<!doctype html><html><head><title>Automatic continuation</title><link rel="icon" href="data:,"></head><body>
    <h1>Automatic observation recovered</h1><label>Customer name<input value="Ada"></label>
    <button onclick="globalThis.clickCount++">Activate once</button><script>globalThis.clickCount = 0;</script>
    </body></html>`);
});
const lifetime = new AbortController();
const expiry = setTimeout(() => lifetime.abort(), 45_000);
const operation = () => ({ timeoutMs: 15_000, signal: lifetime.signal, runId: 'automatic-joint', attemptId: 'one', origin: 'test' as const });
const engine = web({ viewport: { width: 640, height: 480 }, connect: { cdpEndpoint: () => endpoint, reconnectEndpoint: () => endpoint } });
const wire = () => readFileSync(process.env['OBSERVE_AUTOMATIC_WIRE']!, 'utf8').trim().split('\n').map(line => JSON.parse(line));
const flatten = (node: any): any[] => [node, ...(node.children ?? []).flatMap(flatten)];
let primary: unknown;
try {
  server.listen({ port: 0, host: '127.0.0.1', signal: lifetime.signal }); await once(server, 'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  await engine.init!({ runId: 'automatic-joint', targetName: 'web', projectRoot: checkout, app: {}, env: process.env, headed: false, workerSlot: 0, signal: lifetime.signal, log: () => {} });
  await engine.startAttempt!({ attemptId: 'one', artifactsDir: evidence, signal: lifetime.signal, resolveSecret: async () => { throw new Error('No secrets'); }, appLog: () => {}, navigation: () => {}, environment: () => {} });
  await engine.session!.open!(`http://127.0.0.1:${address.port}/`, operation());
  const publicPage = surfaceOf(engine)!.page();
  await publicPage.waitForLoadState('load');
  const deadline = performance.now() + 15_000;
  const observeOperation = { ...operation(), get timeoutMs() { return deadline - performance.now(); } };
  const options = { pixels: false, pixelFallback: false };
  // No manual continuation extraction or request exists in this harness.
  const snapshot = await engine.observe!(observeOperation, options);
  const beforeAction = wire();
  const requests = beforeAction.filter(row => row.direction === 'client' && row.frame.type === 'request').map(row => row.frame);
  const observes = requests.filter(frame => frame.command === 'browser.observe');
  assert.equal(observes.length, 2, 'one public observe must automatically emit exactly one fresh capture');
  assert.equal(requests.filter(frame => frame.command === 'browser.perform').length, 0);
  const original = beforeAction.find(row => row.direction === 'server' && row.frame.type === 'result' && row.frame.id === observes[0].id)!.frame;
  const continued = beforeAction.find(row => row.direction === 'server' && row.frame.type === 'result' && row.frame.id === observes[1].id)!.frame;
  assert.equal(original.ok, false); assert.equal(original.error.code, 'stale-scope');
  assert.equal(original.effects, 'not-dispatched'); assert.equal(original.scopeState, 'usable');
  assert.ok(original.observeContinuation, 'the actual native settlement must issue the grant');
  assert.equal(original.observeContinuation.retiredOperationSeq, observes[0].operationSeq);
  assert.equal(Object.hasOwn(observes[0].args, 'continuation'), false);
  assert.deepEqual(observes[1].args, { ...observes[0].args, continuation: original.observeContinuation });
  assert.ok(observes[1].operationSeq > observes[0].operationSeq);
  assert.ok(observes[1].timeoutMs > 0 && observes[1].timeoutMs <= observes[0].timeoutMs);
  assert.deepEqual(observes[0].args.options, options);
  assert.equal(beforeAction.filter(row => row.direction === 'server' && row.frame.observeContinuation !== undefined).length, 1);
  assert.equal(continued.ok, true); assert.equal(continued.effects, 'completed'); assert.equal(continued.scopeState, 'usable');
  assert.equal(continued.observeContinuation, undefined);
  assert.equal(snapshot.treeUnavailable, undefined);
  assert.equal(snapshot.identityScope, observes[0].args.identityScope);
  assert.equal(snapshot.location, `http://127.0.0.1:${address.port}/?inventory=2`);
  assert.deepEqual(snapshot.viewport, { width: 640, height: 480 });
  const nodes = flatten(snapshot.root);
  assert.ok(nodes.some(node => node.role === 'heading' && node.name === 'Automatic observation recovered'));
  assert.ok(nodes.some(node => node.role === 'textbox' && node.name === 'Customer name'));
  const button = nodes.find(node => node.role === 'button' && node.name === 'Activate once');
  assert.ok(button?.ref?.id, 'complete observation must return an actionable native reference');
  assert.equal(await publicPage.evaluate(() => (globalThis as any).clickCount), 0);
  await engine.perform!(button.ref, { kind: 'tap' }, operation());
  assert.equal(await publicPage.evaluate(() => (globalThis as any).clickCount), 1, 'one explicit action may execute once');
  const actions = wire().filter(row => row.direction === 'client' && row.frame.command === 'browser.perform');
  assert.equal(actions.length, 1);
  assert.equal(Object.hasOwn(actions[0].frame.args, 'continuation'), false);
  const summary = { realChromium: true, fixtureLaunch: { explicitChromeExecutable: true, headless: true, args: ['--no-sandbox'], ciPresent: process.env['CI'] !== undefined }, scheduling: 'cfg(test) rendezvous after actual initial inventory revision snapshot; external real Chromium history events', productionCore: 'unwrapped ClientBrowser, transport, owner/debt/deadline/one-use guards, grant, semantic reader and ref publication', executor: 'ClientBrowser', sdk: 'built NativeSurface', ownership: 'persistent-connect', publicObserveCalls: 1, nativeObserveRequests: 2, nativeGrants: 1, completeSemanticSnapshot: true, nativeReferenceActionSucceeded: true, explicitActions: 1, actionReplays: 0, snapshot, originalRequest: observes[0], continuedRequest: observes[1] };
  writeFileSync(path.join(evidence, 'sdk-summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary));
} catch (cause) { primary = cause; }
finally {
  clearTimeout(expiry);
  try { await engine.dispose!({ timeoutMs: 20_000, signal: new AbortController().signal }); }
  catch (cleanup) { primary = primary === undefined ? cleanup : new AggregateError([primary, cleanup], 'Automatic joint test and cleanup failed'); }
  server.close(); server.closeAllConnections();
}
if (primary !== undefined) throw primary;
