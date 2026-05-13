import { describe, expect, it, beforeEach } from 'vitest';
import { handleGetRelays } from '../src/relays';
import { makeEnv } from './fakeKv';
import { nowIso } from './fixtures';
import type { RelayRecord } from '../src/types';

function seedRelay(env: ReturnType<typeof makeEnv>, rec: RelayRecord) {
  env._RELAYS._seed(`relay:${rec.dnsName}`, rec);
}

describe('GET /relays', () => {
  let env: ReturnType<typeof makeEnv>;
  beforeEach(() => {
    env = makeEnv();
  });

  it('returns empty when no relays are registered', async () => {
    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    expect(j).toEqual([]);
  });

  it('includes a freshly-seeded relay without lastTs regardless of lastSeen', async () => {
    seedRelay(env, {
      dnsName: 'relay.dev.fx.land',
      peerId: 'PEER',
      addr: '/dns/relay.dev.fx.land/tcp/4001',
      multiaddr: '/dns/relay.dev.fx.land/tcp/4001/p2p/PEER',
      lastSeen: '2020-01-01T00:00:00.000Z',  // ancient
      createdAt: nowIso(),
      // no lastTs → never heartbeated → freshly seeded
    });
    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    expect(j).toHaveLength(1);
    expect(j[0].dnsName).toBe('relay.dev.fx.land');
  });

  it('includes a heartbeated relay whose lastSeen is fresh', async () => {
    seedRelay(env, {
      dnsName: 'fresh.fx.land',
      peerId: 'P1',
      addr: '/dns/fresh.fx.land/tcp/4001',
      multiaddr: '/dns/fresh.fx.land/tcp/4001/p2p/P1',
      lastSeen: nowIso(),  // very fresh
      lastTs: Date.now(),
    });
    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    expect(j.map(x => x.dnsName)).toContain('fresh.fx.land');
  });

  it('excludes a heartbeated relay whose lastSeen is older than RELAY_STALE_MS', async () => {
    seedRelay(env, {
      dnsName: 'stale.fx.land',
      peerId: 'P2',
      addr: '/dns/stale.fx.land/tcp/4001',
      multiaddr: '/dns/stale.fx.land/tcp/4001/p2p/P2',
      lastSeen: new Date(Date.now() - 10 * 60 * 1000).toISOString(),  // 10 min old
      lastTs: Date.now() - 10 * 60 * 1000,
    });
    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    expect(j.map(x => x.dnsName)).not.toContain('stale.fx.land');
  });

  it('mixed: includes fresh + freshly-seeded; excludes stale', async () => {
    seedRelay(env, { dnsName: 'a.fx.land', peerId: 'PA', addr: '/dns/a.fx.land/tcp/4001', multiaddr: '/dns/a.fx.land/tcp/4001/p2p/PA', lastSeen: nowIso(), lastTs: Date.now() });
    seedRelay(env, { dnsName: 'b.fx.land', peerId: 'PB', addr: '/dns/b.fx.land/tcp/4001', multiaddr: '/dns/b.fx.land/tcp/4001/p2p/PB', lastSeen: '2020-01-01T00:00:00.000Z', createdAt: nowIso() });
    seedRelay(env, { dnsName: 'c.fx.land', peerId: 'PC', addr: '/dns/c.fx.land/tcp/4001', multiaddr: '/dns/c.fx.land/tcp/4001/p2p/PC', lastSeen: new Date(Date.now() - 600_000).toISOString(), lastTs: Date.now() - 600_000 });
    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    const names = j.map(x => x.dnsName).sort();
    expect(names).toEqual(['a.fx.land', 'b.fx.land']);
  });

  it('kill-switch ON: returns only the canonical relay regardless of staleness', async () => {
    // Canonical relay, deeply stale and heartbeated long ago.
    seedRelay(env, {
      dnsName: 'relay.dev.fx.land',
      peerId: 'CANON',
      addr: '/dns/relay.dev.fx.land/tcp/4001',
      multiaddr: '/dns/relay.dev.fx.land/tcp/4001/p2p/CANON',
      lastSeen: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
      lastTs: Date.now() - 24 * 3600 * 1000,
    });
    // Other relay, fresh — should be EXCLUDED in kill-switch mode.
    seedRelay(env, {
      dnsName: 'other.fx.land',
      peerId: 'OTHER',
      addr: '/dns/other.fx.land/tcp/4001',
      multiaddr: '/dns/other.fx.land/tcp/4001/p2p/OTHER',
      lastSeen: nowIso(),
      lastTs: Date.now(),
    });
    env._RELAYS._seed('meta:kill-switch', '1');

    const r = await handleGetRelays(env);
    const j = await r.json<RelayRecord[]>();
    expect(j).toHaveLength(1);
    expect(j[0].dnsName).toBe('relay.dev.fx.land');
  });

  it('kill-switch OFF (after delete): normal behavior resumes', async () => {
    seedRelay(env, { dnsName: 'relay.dev.fx.land', peerId: 'CANON', addr: '/dns/relay.dev.fx.land/tcp/4001', multiaddr: '/dns/relay.dev.fx.land/tcp/4001/p2p/CANON', lastSeen: nowIso(), lastTs: Date.now() });
    seedRelay(env, { dnsName: 'other.fx.land', peerId: 'OTHER', addr: '/dns/other.fx.land/tcp/4001', multiaddr: '/dns/other.fx.land/tcp/4001/p2p/OTHER', lastSeen: nowIso(), lastTs: Date.now() });
    env._RELAYS._seed('meta:kill-switch', '1');
    let r = await handleGetRelays(env);
    expect((await r.json<RelayRecord[]>())).toHaveLength(1);

    // Delete the flag — both relays now visible.
    await env._RELAYS.delete('meta:kill-switch');
    r = await handleGetRelays(env);
    const names = (await r.json<RelayRecord[]>()).map(x => x.dnsName).sort();
    expect(names).toEqual(['other.fx.land', 'relay.dev.fx.land']);
  });
});
