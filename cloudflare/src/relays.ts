import { Env, RelayRecord, relayStaleMs } from './types';

const KILL_SWITCH_KEY = 'meta:kill-switch';

/**
 * GET /relays
 *
 * Returns array of currently-healthy relay records.
 *
 * A relay is considered healthy if EITHER:
 *   - It has never heartbeated (lastTs undefined) — freshly seeded, no
 *     heartbeats have arrived yet. Operator has just registered it, edges
 *     should be able to see it immediately. The first successful heartbeat
 *     starts the stale-filter.
 *   - It has heartbeated AND its lastSeen is within RELAY_STALE_MS.
 *
 * Kill switch: if the KV entry `meta:kill-switch` is set to "1", the
 * endpoint returns ONLY the seeded production relay record, ignoring
 * staleness. This is the emergency rollback path — set the flag and every
 * edge / app falls back to the canonical relay on its next refresh, no
 * code change required.
 */
export async function handleGetRelays(env: Env): Promise<Response> {
  const killSwitch = await env.RELAYS.get(KILL_SWITCH_KEY);
  const now = Date.now();
  const RELAY_STALE_MS = relayStaleMs(env);
  const list = await env.RELAYS.list({ prefix: 'relay:' });
  const records = await Promise.all(
    list.keys.map(k => env.RELAYS.get<RelayRecord>(k.name, 'json')),
  );

  const out: RelayRecord[] = [];
  for (const rec of records) {
    if (!rec) continue;

    // Kill-switch: include only relays explicitly flagged as canonical.
    if (killSwitch === '1') {
      // Convention: kill-switch mode returns relays whose dnsName matches the
      // sentinel relay (relay.dev.fx.land) — the one that's always present
      // and never renamed.
      if (rec.dnsName !== 'relay.dev.fx.land') continue;
      out.push(stripInternal(rec));
      continue;
    }

    // Freshly-seeded relay (no heartbeats yet) — include it. Once it starts
    // heartbeating, lastTs becomes defined and the stale-filter takes over.
    if (rec.lastTs === undefined) {
      out.push(stripInternal(rec));
      continue;
    }

    const lastSeen = Date.parse(rec.lastSeen);
    if (isNaN(lastSeen)) continue;
    if (now - lastSeen > RELAY_STALE_MS) continue;

    out.push(stripInternal(rec));
  }

  return Response.json(out, {
    headers: {
      'cache-control': 'public, max-age=30',  // edges/apps cache 30s
      'access-control-allow-origin': '*',
    },
  });
}

function stripInternal(rec: RelayRecord): RelayRecord {
  // Future-proof: hide any operator-internal fields we don't want public.
  // Currently nothing internal in the record, but kept as a single chokepoint.
  return rec;
}
