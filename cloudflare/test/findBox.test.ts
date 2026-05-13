import { describe, expect, it, beforeEach } from 'vitest';
import { handleFindBox } from '../src/findBox';
import { makeEnv } from './fakeKv';
import { nowIso } from './fixtures';
import type { BoxRecord, RelayRecord } from '../src/types';

function makeFindBoxRequest(peerId: string): Request {
  return new Request('https://discovery.fx.land/find-box', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ peerId }),
  });
}

describe('POST /find-box', () => {
  let env: ReturnType<typeof makeEnv>;

  beforeEach(() => {
    env = makeEnv();
  });

  it('rejects body without peerId with 400', async () => {
    const r = await handleFindBox(
      new Request('https://x/find-box', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      }),
      env,
    );
    expect(r.status).toBe(400);
  });

  it('rejects malformed JSON body with 400', async () => {
    const r = await handleFindBox(
      new Request('https://x/find-box', { method: 'POST', body: 'not-json' }),
      env,
    );
    expect(r.status).toBe(400);
  });

  it('tier 1: returns box self-reported addrs when heartbeat is fresh', async () => {
    const peerId = '12D3KooWBOX1';
    env._BOXES._seed(`box:${peerId}`, {
      peerId,
      reservedOn: ['relay.dev.fx.land'],
      libp2pAddrs: ['/dns/relay.dev.fx.land/tcp/4001/p2p/REL/p2p-circuit/p2p/BOX'],
      lastSeen: nowIso(),
      lastTs: Date.now(),
    } satisfies BoxRecord);

    const r = await handleFindBox(makeFindBoxRequest(peerId), env);
    const j = await r.json<Array<{ multiaddr: string }>>();
    expect(j).toHaveLength(1);
    expect(j[0].multiaddr).toContain('/p2p-circuit/p2p/BOX');
  });

  it('tier 1: ignores stale heartbeat (>BOX_STALE_MIN) and falls through to tier 2', async () => {
    const peerId = '12D3KooWBOX2';
    env._BOXES._seed(`box:${peerId}`, {
      peerId,
      reservedOn: ['relay.dev.fx.land'],
      libp2pAddrs: ['/old-addrs-not-to-be-used'],
      lastSeen: new Date(Date.now() - 20 * 60_000).toISOString(),  // 20m > BOX_STALE_MIN default 15m
      lastTs: Date.now() - 20 * 60_000,
    } satisfies BoxRecord);
    // Seed a relay so tier-2 has something to construct from.
    env._RELAYS._seed('relay:relay.dev.fx.land', {
      dnsName: 'relay.dev.fx.land',
      peerId: 'RPID',
      addr: '/dns/relay.dev.fx.land/tcp/4001',
      multiaddr: '/dns/relay.dev.fx.land/tcp/4001/p2p/RPID',
      lastSeen: nowIso(),
      lastTs: Date.now(),
    } satisfies RelayRecord);

    const r = await handleFindBox(makeFindBoxRequest(peerId), env);
    const j = await r.json<Array<{ multiaddr: string }>>();
    expect(j).toHaveLength(1);
    expect(j[0].multiaddr).toBe(`/dns/relay.dev.fx.land/tcp/4001/p2p/RPID/p2p-circuit/p2p/${peerId}`);
    expect(j[0].multiaddr).not.toContain('/old-addrs-not-to-be-used');
  });

  it('tier 2: no heartbeat at all + relays exist → constructs addrs per relay', async () => {
    const peerId = '12D3KooWBOX3';
    env._RELAYS._seed('relay:a.fx.land', {
      dnsName: 'a.fx.land',
      peerId: 'PA',
      addr: '/dns/a.fx.land/tcp/4001',
      multiaddr: '/dns/a.fx.land/tcp/4001/p2p/PA',
      lastSeen: nowIso(),
      lastTs: Date.now(),
    } satisfies RelayRecord);
    env._RELAYS._seed('relay:b.fx.land', {
      dnsName: 'b.fx.land',
      peerId: 'PB',
      addr: '/dns/b.fx.land/tcp/4001',
      multiaddr: '/dns/b.fx.land/tcp/4001/p2p/PB',
      lastSeen: nowIso(),
      lastTs: Date.now(),
    } satisfies RelayRecord);

    const r = await handleFindBox(makeFindBoxRequest(peerId), env);
    const j = await r.json<Array<{ multiaddr: string }>>();
    expect(j).toHaveLength(2);
    expect(j.map(x => x.multiaddr).sort()).toEqual([
      `/dns/a.fx.land/tcp/4001/p2p/PA/p2p-circuit/p2p/${peerId}`,
      `/dns/b.fx.land/tcp/4001/p2p/PB/p2p-circuit/p2p/${peerId}`,
    ]);
  });

  it('tier 2: excludes stale relays when constructing', async () => {
    const peerId = '12D3KooWBOX4';
    env._RELAYS._seed('relay:fresh.fx.land', {
      dnsName: 'fresh.fx.land',
      peerId: 'PF',
      addr: '/dns/fresh.fx.land/tcp/4001',
      multiaddr: '/dns/fresh.fx.land/tcp/4001/p2p/PF',
      lastSeen: nowIso(),
      lastTs: Date.now(),
    } satisfies RelayRecord);
    env._RELAYS._seed('relay:stale.fx.land', {
      dnsName: 'stale.fx.land',
      peerId: 'PS',
      addr: '/dns/stale.fx.land/tcp/4001',
      multiaddr: '/dns/stale.fx.land/tcp/4001/p2p/PS',
      lastSeen: new Date(Date.now() - 10 * 60_000).toISOString(),
      lastTs: Date.now() - 10 * 60_000,
    } satisfies RelayRecord);

    const r = await handleFindBox(makeFindBoxRequest(peerId), env);
    const j = await r.json<Array<{ multiaddr: string }>>();
    expect(j.map(x => x.multiaddr)).toEqual([
      `/dns/fresh.fx.land/tcp/4001/p2p/PF/p2p-circuit/p2p/${peerId}`,
    ]);
  });

  it('returns empty array when neither tier yields anything', async () => {
    const r = await handleFindBox(makeFindBoxRequest('12D3KooWGhost'), env);
    const j = await r.json<unknown[]>();
    expect(j).toEqual([]);
  });
});
