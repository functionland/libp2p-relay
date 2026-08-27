import { Env, BoxRecord, RelayRecord, boxStaleMs, relayStaleMs } from './types';

interface FindBoxRequest {
  peerId?: string;
}

/**
 * POST /find-box
 * Body: { peerId }
 *
 * Returns the box's currently-reachable circuit multiaddrs in latency-preference
 * order, derived from heartbeats. Falls back to constructing addresses from the
 * current relay set if no heartbeat has been received recently.
 */
export async function handleFindBox(req: Request, env: Env): Promise<Response> {
  let body: FindBoxRequest;
  try {
    body = await req.json<FindBoxRequest>();
  } catch {
    return Response.json({ error: 'invalid json body' }, { status: 400 });
  }
  if (!body.peerId) {
    return Response.json({ error: 'missing peerId' }, { status: 400 });
  }

  const box = await env.BOXES.get<BoxRecord>(`box:${body.peerId}`, 'json');
  const now = Date.now();
  const BOX_STALE_MS = boxStaleMs(env);
  const RELAY_STALE_MS = relayStaleMs(env);

  // Tier 1: the box itself has reported recent heartbeat data — trust its
  // self-advertised circuit addresses.
  if (box) {
    const lastSeen = Date.parse(box.lastSeen);
    if (!isNaN(lastSeen) && now - lastSeen <= BOX_STALE_MS && box.libp2pAddrs.length > 0) {
      return Response.json(
        box.libp2pAddrs.map(m => ({ multiaddr: m })),
        { headers: { 'access-control-allow-origin': '*' } },
      );
    }
  }

  // Tier 2: no recent heartbeat. Construct best-effort circuit addresses by
  // assuming the box is reachable through every currently-healthy relay.
  // The client will iterate them and discover which ones actually work.
  const relayList = await env.RELAYS.list({ prefix: 'relay:' });
  const relays = await Promise.all(
    relayList.keys.map(k => env.RELAYS.get<RelayRecord>(k.name, 'json'))
  );
  const addrs: { multiaddr: string }[] = [];
  const seen = new Set<string>();
  const push = (relayAddr: string) => {
    const m = `${relayAddr}/p2p-circuit/p2p/${body.peerId}`;
    if (seen.has(m)) return;
    seen.add(m);
    addrs.push({ multiaddr: m });
  };
  for (const r of relays) {
    if (!r) continue;
    const lastSeen = Date.parse(r.lastSeen);
    if (isNaN(lastSeen) || now - lastSeen > RELAY_STALE_MS) continue;
    // One circuit address per public relay address the relay itself reports
    // (only its own /p2p/<relayPeerId> addrs). Browser-dialable WebTransport
    // addrs (with certhash) first, then QUIC/TCP, then the seeded TCP
    // multiaddr as the always-present fallback for native clients.
    const own = (r.addrs ?? []).filter(a => a.endsWith(`/p2p/${r.peerId}`));
    for (const a of own) if (a.includes('/webtransport/certhash/')) push(a);
    for (const a of own) if (!a.includes('/webtransport/certhash/')) push(a);
    push(r.multiaddr);
  }

  return Response.json(addrs, {
    headers: { 'access-control-allow-origin': '*' },
  });
}
