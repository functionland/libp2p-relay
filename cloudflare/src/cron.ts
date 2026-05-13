import { Env, BoxRecord } from './types';

/**
 * Scheduled handler — runs hourly per wrangler.toml.
 *
 * Cleanup-only. Relay health comes from relay-VM-side POST /heartbeat (see
 * libp2p-relay/scripts/relay-heartbeat.sh); the Worker does NOT pull from
 * kubo APIs. That avoids the operational nightmare of needing public kubo
 * RPC or Cloudflare Tunnel on every relay.
 *
 * What we clean up:
 *   - `box:*` entries whose lastSeen is older than 7 days. KV already has an
 *     `expirationTtl: 7 * 86400` set on writes, so this is belt-and-suspenders
 *     for entries written before TTL was introduced or in case the TTL
 *     semantics ever drift.
 *
 * Note that we deliberately do NOT remove stale `relay:*` entries. A relay's
 * absence from /relays (via the stale-filter in relays.ts) is enough; the
 * record itself stays so the operator can see "this relay used to be here"
 * and so the next heartbeat from a recovered relay refreshes lastSeen
 * without re-seeding.
 */
export async function scheduled(env: Env, ctx: ExecutionContext): Promise<void> {
  ctx.waitUntil(cleanupExpiredBoxes(env));
}

async function cleanupExpiredBoxes(env: Env): Promise<void> {
  const STALE_AGE_MS = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  let cursor: string | undefined;
  let deleted = 0;
  let inspected = 0;

  do {
    const list = await env.BOXES.list({ prefix: 'box:', cursor });
    cursor = list.list_complete ? undefined : list.cursor;

    // Inspect in parallel; deletions are sequential after to bound concurrent
    // KV operations.
    const records = await Promise.all(
      list.keys.map(k =>
        env.BOXES.get<BoxRecord>(k.name, 'json').then(r => ({ name: k.name, rec: r })),
      ),
    );
    for (const { name, rec } of records) {
      inspected++;
      if (!rec || isNaN(Date.parse(rec.lastSeen))) continue;
      if (now - Date.parse(rec.lastSeen) > STALE_AGE_MS) {
        await env.BOXES.delete(name);
        deleted++;
      }
    }
  } while (cursor);

  if (deleted > 0 || inspected > 0) {
    console.log(`cron: inspected ${inspected} box records, deleted ${deleted} stale entries`);
  }
}
