import { Env, RelayRecord, BoxRecord, relayStaleMs, boxStaleMs } from './types';
import { handleGetRelays } from './relays';
import { handleFindBox } from './findBox';
import { handleHeartbeat } from './heartbeat';
import { scheduled as scheduledHandler } from './cron';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight — the box-app reads from a different origin.
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type',
          'access-control-max-age': '86400',
        },
      });
    }

    if (request.method === 'GET' && url.pathname === '/relays') {
      return handleGetRelays(env);
    }
    if (request.method === 'POST' && url.pathname === '/find-box') {
      return handleFindBox(request, env);
    }
    if (request.method === 'POST' && url.pathname === '/heartbeat') {
      return handleHeartbeat(request, env);
    }
    if (request.method === 'GET' && url.pathname === '/healthz') {
      return handleHealthz(env);
    }

    return Response.json({ error: 'not found' }, { status: 404 });
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    await scheduledHandler(env, ctx);
  },
};

/**
 * GET /healthz — summary fitness for external uptime monitors.
 *
 * Returns relays_healthy + boxes_active counts so a monitoring system can
 * alert on "relays_healthy === 0" instead of just polling for HTTP 200.
 * Capped at 100 box scans per call to bound execution time.
 */
async function handleHealthz(env: Env): Promise<Response> {
  const now = Date.now();
  const RELAY_STALE_MS = relayStaleMs(env);
  const BOX_STALE_MS = boxStaleMs(env);

  // Relays — count those visible per /relays semantics (fresh OR never-heartbeated).
  const relayList = await env.RELAYS.list({ prefix: 'relay:' });
  const relayRecs = await Promise.all(
    relayList.keys.map(k => env.RELAYS.get<RelayRecord>(k.name, 'json')),
  );
  let relaysHealthy = 0;
  for (const r of relayRecs) {
    if (!r) continue;
    if (r.lastTs === undefined) { relaysHealthy++; continue; }
    const lastSeen = Date.parse(r.lastSeen);
    if (!isNaN(lastSeen) && now - lastSeen <= RELAY_STALE_MS) relaysHealthy++;
  }

  // Boxes — sample first 100 to estimate active count. Full scan would
  // exceed CPU time on large fleets; for production, replace with a
  // counter that's incremented in heartbeat.ts.
  const boxList = await env.BOXES.list({ prefix: 'box:', limit: 100 });
  const boxRecs = await Promise.all(
    boxList.keys.map(k => env.BOXES.get<BoxRecord>(k.name, 'json')),
  );
  // Multiple windows so a single endpoint can answer different operational
  // questions. The 5m bucket uses the configurable BOX_STALE_MIN cutoff;
  // 4h/8h/24h are fixed and meaningful relative to LIVENESS_REFRESH_MIN
  // (default 4h), the write-on-change refresh boundary. A box whose state
  // hasn't changed in N hours still gets a KV write at each 4h boundary,
  // so the 4h+ counts approximate "boxes that have heartbeated in the
  // last window" rather than "boxes whose state changed recently".
  const STALE_MS_4H = 4 * 3600_000;
  const STALE_MS_8H = 8 * 3600_000;
  const STALE_MS_24H = 24 * 3600_000;
  let boxesActive = 0;
  let boxesActive4h = 0;
  let boxesActive8h = 0;
  let boxesActive24h = 0;
  for (const b of boxRecs) {
    if (!b) continue;
    const lastSeen = Date.parse(b.lastSeen);
    if (isNaN(lastSeen)) continue;
    const age = now - lastSeen;
    if (age <= BOX_STALE_MS) boxesActive++;
    if (age <= STALE_MS_4H) boxesActive4h++;
    if (age <= STALE_MS_8H) boxesActive8h++;
    if (age <= STALE_MS_24H) boxesActive24h++;
  }
  // If we hit the page limit, the count is approximate.
  const boxesActiveExact = boxList.list_complete;

  return Response.json(
    {
      ok: relaysHealthy > 0,
      relays_healthy: relaysHealthy,
      boxes_active_5m: boxesActive,
      boxes_active_4h: boxesActive4h,
      boxes_active_8h: boxesActive8h,
      boxes_active_24h: boxesActive24h,
      boxes_active_exact: boxesActiveExact,
      timestamp: new Date(now).toISOString(),
    },
    {
      headers: {
        'content-type': 'application/json',
        'access-control-allow-origin': '*',
        'cache-control': 'no-store',
      },
    },
  );
}
