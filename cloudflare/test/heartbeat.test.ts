import { describe, expect, it, beforeEach } from 'vitest';
import { webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') (globalThis as any).crypto = webcrypto;

import { handleHeartbeat } from '../src/heartbeat';
import { makeEnv, FakeKV } from './fakeKv';
import { generateTestKeypair, nowIso, signCanonical } from './fixtures';
import type { BoxRecord, HeartbeatBody, RelayRecord } from '../src/types';

function makeRequest(body: HeartbeatBody): Request {
  return new Request('https://discovery.fx.land/heartbeat', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function buildBoxHeartbeat(opts: {
  kp: Awaited<ReturnType<typeof generateTestKeypair>>;
  timestamp?: string;
  reservedOn?: string[];
  libp2pAddrs?: string[];
}): Promise<HeartbeatBody> {
  const ts = opts.timestamp ?? nowIso();
  const data = {
    type: 'box' as const,
    reservedOn: opts.reservedOn ?? ['relay.dev.fx.land'],
    libp2pAddrs: opts.libp2pAddrs ?? ['/dns/.../p2p-circuit/p2p/...'],
  };
  const signature = await signCanonical(opts.kp.privateKey, {
    peerId: opts.kp.peerId,
    timestamp: ts,
    data,
  });
  return {
    type: 'box',
    peerId: opts.kp.peerId,
    timestamp: ts,
    data,
    signature,
  };
}

describe('handleHeartbeat (box)', () => {
  let env: ReturnType<typeof makeEnv>;
  let kp: Awaited<ReturnType<typeof generateTestKeypair>>;

  beforeEach(async () => {
    env = makeEnv();
    kp = await generateTestKeypair();
  });

  it('writes a record for a first-time heartbeat', async () => {
    const body = await buildBoxHeartbeat({ kp });
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(200);
    const stored = await env._BOXES.get<BoxRecord>(`box:${kp.peerId}`, 'json');
    expect(stored).not.toBeNull();
    expect(stored!.peerId).toBe(kp.peerId);
    expect(stored!.lastTs).toBe(Date.parse(body.timestamp));
  });

  it('rejects a replayed identical heartbeat with 409', async () => {
    const body = await buildBoxHeartbeat({ kp });
    await handleHeartbeat(makeRequest(body), env);
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(409);
    const j = await r.json<{ error: string }>();
    expect(j.error).toMatch(/stale heartbeat/);
  });

  it('rejects an out-of-order heartbeat (older signed ts) with 409', async () => {
    const newer = await buildBoxHeartbeat({ kp, timestamp: nowIso() });
    await handleHeartbeat(makeRequest(newer), env);
    // Build an older heartbeat with same state.
    const older = await buildBoxHeartbeat({ kp, timestamp: nowIso(-30_000) });
    const r = await handleHeartbeat(makeRequest(older), env);
    expect(r.status).toBe(409);
  });

  it('write-on-change: same state + fresh lastSeen → no write', async () => {
    const first = await buildBoxHeartbeat({ kp });
    await handleHeartbeat(makeRequest(first), env);
    const firstRaw = env._BOXES._raw(`box:${kp.peerId}`);

    // Send a strictly-newer heartbeat with the same payload state.
    const second = await buildBoxHeartbeat({ kp, timestamp: nowIso(+1) });
    const r = await handleHeartbeat(makeRequest(second), env);
    expect(r.status).toBe(200);
    const secondRaw = env._BOXES._raw(`box:${kp.peerId}`);

    // No write: stored bytes are identical.
    expect(secondRaw).toBe(firstRaw);
  });

  it('writes when reservedOn changes', async () => {
    const first = await buildBoxHeartbeat({ kp, reservedOn: ['r1'] });
    await handleHeartbeat(makeRequest(first), env);
    const second = await buildBoxHeartbeat({ kp, timestamp: nowIso(+1), reservedOn: ['r1', 'r2'] });
    await handleHeartbeat(makeRequest(second), env);
    const stored = await env._BOXES.get<BoxRecord>(`box:${kp.peerId}`, 'json');
    expect(stored!.reservedOn).toEqual(['r1', 'r2']);
  });

  it('writes when libp2pAddrs changes', async () => {
    const first = await buildBoxHeartbeat({ kp, libp2pAddrs: ['m1'] });
    await handleHeartbeat(makeRequest(first), env);
    const second = await buildBoxHeartbeat({ kp, timestamp: nowIso(+1), libp2pAddrs: ['m1', 'm2'] });
    await handleHeartbeat(makeRequest(second), env);
    const stored = await env._BOXES.get<BoxRecord>(`box:${kp.peerId}`, 'json');
    expect(stored!.libp2pAddrs).toEqual(['m1', 'm2']);
  });

  it('reservedOn order does not trigger a write', async () => {
    const first = await buildBoxHeartbeat({ kp, reservedOn: ['a', 'b'] });
    await handleHeartbeat(makeRequest(first), env);
    const firstRaw = env._BOXES._raw(`box:${kp.peerId}`);
    const second = await buildBoxHeartbeat({ kp, timestamp: nowIso(+1), reservedOn: ['b', 'a'] });
    await handleHeartbeat(makeRequest(second), env);
    const secondRaw = env._BOXES._raw(`box:${kp.peerId}`);
    expect(secondRaw).toBe(firstRaw);
  });

  it('rejects bad signature with 401', async () => {
    const body = await buildBoxHeartbeat({ kp });
    body.signature = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(401);
  });

  it('rejects malformed JSON with 400', async () => {
    const r = await handleHeartbeat(
      new Request('https://x/heartbeat', { method: 'POST', body: 'not json' }),
      env,
    );
    expect(r.status).toBe(400);
  });

  it('liveness refresh: stale lastSeen forces a write even when state unchanged', async () => {
    const first = await buildBoxHeartbeat({ kp });
    await handleHeartbeat(makeRequest(first), env);

    // Backdate the stored lastSeen by 4h+1m so the box liveness-stale check
    // (>LIVENESS_REFRESH_MIN, default 240 min) triggers on the next heartbeat.
    const stored = await env._BOXES.get<BoxRecord>(`box:${kp.peerId}`, 'json');
    stored!.lastSeen = new Date(Date.now() - (240 + 1) * 60 * 1000).toISOString();
    env._BOXES._seed(`box:${kp.peerId}`, stored);
    const beforeRaw = env._BOXES._raw(`box:${kp.peerId}`);

    const second = await buildBoxHeartbeat({ kp, timestamp: nowIso(+1) });
    await handleHeartbeat(makeRequest(second), env);
    const afterRaw = env._BOXES._raw(`box:${kp.peerId}`);

    expect(afterRaw).not.toBe(beforeRaw); // record was rewritten
  });
});

describe('handleHeartbeat (relay)', () => {
  let env: ReturnType<typeof makeEnv>;
  let kp: Awaited<ReturnType<typeof generateTestKeypair>>;

  beforeEach(async () => {
    env = makeEnv();
    kp = await generateTestKeypair();
  });

  async function buildRelayHeartbeat(opts: {
    kp: Awaited<ReturnType<typeof generateTestKeypair>>;
    dnsName: string;
    timestamp?: string;
    reservationCount?: number;
    circuitCount?: number;
  }): Promise<HeartbeatBody> {
    const ts = opts.timestamp ?? nowIso();
    const data: any = { type: 'relay', dnsName: opts.dnsName };
    if (opts.reservationCount !== undefined) data.reservationCount = opts.reservationCount;
    if (opts.circuitCount !== undefined) data.circuitCount = opts.circuitCount;
    const sig = await signCanonical(opts.kp.privateKey, {
      peerId: opts.kp.peerId,
      timestamp: ts,
      data,
    });
    return { type: 'relay', peerId: opts.kp.peerId, timestamp: ts, data, signature: sig };
  }

  it('rejects relay heartbeat for unknown dnsName with 404', async () => {
    const body = await buildRelayHeartbeat({ kp, dnsName: 'unknown-relay.fx.land' });
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(404);
  });

  it('rejects relay heartbeat when peerId does not match registered relay', async () => {
    // Seed a relay with a DIFFERENT peer ID.
    const other = await generateTestKeypair();
    env._RELAYS._seed('relay:test.fx.land', {
      dnsName: 'test.fx.land',
      peerId: other.peerId,
      addr: '/dns/test.fx.land/tcp/4001',
      multiaddr: `/dns/test.fx.land/tcp/4001/p2p/${other.peerId}`,
      lastSeen: nowIso(),
      createdAt: nowIso(),
    } satisfies RelayRecord);

    const body = await buildRelayHeartbeat({ kp, dnsName: 'test.fx.land' });
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(403);
  });

  it('accepts heartbeat for a registered relay with matching peerId', async () => {
    env._RELAYS._seed('relay:test.fx.land', {
      dnsName: 'test.fx.land',
      peerId: kp.peerId,
      addr: '/dns/test.fx.land/tcp/4001',
      multiaddr: `/dns/test.fx.land/tcp/4001/p2p/${kp.peerId}`,
      lastSeen: new Date(Date.now() - 10 * 60_000).toISOString(),  // 10m > RELAY_LIVENESS_REFRESH_MIN (5m) → forces a write
      createdAt: nowIso(),
    } satisfies RelayRecord);
    const body = await buildRelayHeartbeat({ kp, dnsName: 'test.fx.land', reservationCount: 5 });
    const r = await handleHeartbeat(makeRequest(body), env);
    expect(r.status).toBe(200);
    const stored = await env._RELAYS.get<RelayRecord>('relay:test.fx.land', 'json');
    expect(stored!.reservationCount).toBe(5);
    expect(stored!.lastTs).toBe(Date.parse(body.timestamp));
  });
});
