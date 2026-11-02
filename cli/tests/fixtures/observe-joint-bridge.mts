// Deterministic native-authority / SDK-wire control. Not real-browser acceptance.
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { Writable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
const checkout = process.env['OBSERVE_BRIDGE_E2E_CHECKOUT'];
assert.ok(checkout, 'explicit E2E checkout required');
const { NativeClient } = await import(pathToFileURL(path.join(checkout, 'packages/web/src/native/client.ts')).href);
const { EngineChannel, takeObservationContinuation } = await import(pathToFileURL(path.join(checkout, 'packages/web/src/native/engine-channel.ts')).href);

const socketPath = process.env['OBSERVE_BRIDGE_SOCKET'];
assert.ok(socketPath);
const socket = net.createConnection(socketPath);
await once(socket, 'connect');
const sent: any[] = []; const received: any[] = []; let partial = '';
socket.on('data', chunk => {
  partial += chunk.toString();
  for (;;) { const end = partial.indexOf('\n'); if (end < 0) break;
    received.push(JSON.parse(partial.slice(0, end))); partial = partial.slice(end + 1); }
});
const output = new Writable({ write(chunk, encoding, done) { sent.push(JSON.parse(chunk.toString())); socket.write(chunk, encoding, done); } });
const deadline = performance.now() + 10_000;
const operation = { get timeoutMs() { return deadline - performance.now(); }, signal: new AbortController().signal, runId: 'joint-bridge', attemptId: 'one', origin: 'test' as const };
const client = await NativeClient.connect({ readable: socket, writable: output, dispose: () => socket.destroy() }, ['browser.observe/1', 'browser.observe-continuation/1', 'terminal.close/1'], operation, () => {});
const engine = new EngineChannel(client, scope => () => scope === 'scope');
const args = { identityScope: 'scope', options: {}, testIdAttribute: 'data-testid', secureFieldSelector: 'input[type=password]' };
async function refused(args: any) {
  try { await engine.command('browser.observe', args, operation); }
  catch (error) { assert.equal((error as any).code, 'INVALID_STATE'); assert.equal((error as any).retryable, false); return error; }
  assert.fail('controlled native inventory refusal unexpectedly succeeded');
}
try {
  const original = await refused(args);
  const grant = takeObservationContinuation(original);
  assert.ok(grant, 'must receive actual native-issued grant over real Rust serialization');
  assert.equal(takeObservationContinuation(original), undefined, 'SDK receipt custody is one-use');
  const continued = await refused({ ...args, continuation: grant });
  assert.equal(takeObservationContinuation(continued), undefined, 'no chained grant');
  const replay = await refused({ ...args, continuation: grant });
  assert.equal(takeObservationContinuation(replay), undefined, 'native rejects replayed grant');
  const requests = sent.filter(row => row.type === 'request');
  assert.equal(requests.length, 3);
  assert.deepEqual(requests[1].args, { ...requests[0].args, continuation: grant });
  assert.equal(grant.retiredOperationSeq, requests[0].operationSeq);
  assert.ok(requests[1].operationSeq > requests[0].operationSeq);
  assert.ok(requests[1].timeoutMs <= requests[0].timeoutMs);
  assert.equal(received.filter(row => row.observeContinuation !== undefined).length, 1);
  assert.ok(received.filter(row => row.type === 'result').every(row => row.effects === 'not-dispatched' && row.scopeState === 'usable' && row.error.code === 'stale-scope'));
  await client.close(operation);
  console.log(JSON.stringify({ mode: process.env['OBSERVE_BRIDGE_MODE'], actualNativeGrant: true, sdkParserAccepted: true, freshRequestReturnedToNative: true, noChainedGrant: true, replayRefused: true, scope: 'EngineChannel; NativeSurface automatic wrapper remains separate unit coverage', sent, received }));
} finally { socket.destroy(); }
