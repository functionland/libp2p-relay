import { Env, HeartbeatBody, BoxRecord, RelayRecord, livenessRefreshMs, relayLivenessRefreshMs } from './types';
import { verifyHeartbeat } from './verify';

/**
 * POST /heartbeat
 *
 * Boxes and relays signal liveness. Three layers of protection:
 *   1. Signature verified against the claimed peer ID (verify.ts)
 *   2. Timestamp drift check (anti-replay window — verify.ts)
 *   3. Monotonic-timestamp check (anti-replay within the drift window —
 *      reject heartbeats whose signed timestamp is not strictly newer than
 *      the last accepted one). Without this, a heartbeat captured in transit
 *      can be replayed within the drift window to overwrite a newer record.
 *
 * Write-on-change: KV.put only fires when state actually changed OR when
 * lastSeen is older than LIVENESS_REFRESH_MS. Steady-state heartbeats from
 * idle peers produce zero writes, keeping us under KV write budgets.
 */
export async function handleHeartbeat(req: Request, env: Env): Promise<Response> {
  let body: HeartbeatBody;
  try {
    body = await req.json<HeartbeatBody>();
  } catch {
    return Response.json({ error: 'invalid json body' }, { status: 400, headers: { 'access-control-allow-origin': '*' } });
  }

  const verifyErr = await verifyHeartbeat(body);
  if (verifyErr) {
    console.warn(`heartbeat rejected from ${body.peerId}: ${verifyErr}`);
    return Response.json({ error: 'invalid heartbeat' }, { status: 401 });
  }

  const signedTsMs = Date.parse(body.timestamp);  // already validated by verifyHeartbeat
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();

  if (body.type === 'box' && body.data.type === 'box') {
    const key = `box:${body.peerId}`;
    const existing = await env.BOXES.get<BoxRecord>(key, 'json');

    // Replay guard: reject any heartbeat whose signed timestamp is not strictly
    // newer than the last accepted one for this peer.
    if (existing?.lastTs !== undefined && signedTsMs <= existing.lastTs) {
      console.warn(`heartbeat replay/out-of-order from ${body.peerId}: signed=${signedTsMs}, stored=${existing.lastTs}`);
      return Response.json({ error: 'stale heartbeat' }, { status: 409 });
    }

    const candidate: BoxRecord = {
      peerId: body.peerId,
      reservedOn: body.data.reservedOn,
      libp2pAddrs: body.data.libp2pAddrs,
      lastSeen: nowIso,
      lastTs: signedTsMs,
      ...(body.data.clusterPeerId ? { clusterPeerId: body.data.clusterPeerId } : {}),
    };

    // Write-on-change: skip the put if nothing meaningful changed and the
    // stored lastSeen is still fresh. Box uses the longer refresh window so
    // 100 idle boxes only generate ~600 writes/day (free-tier-friendly).
    // clusterPeerId is included so a blox that bootstraps its cluster identity
    // for the first time (None → real value) triggers an immediate write.
    const stateChanged =
      !existing ||
      !arraysEqual(existing.reservedOn, candidate.reservedOn) ||
      !arraysEqual(existing.libp2pAddrs, candidate.libp2pAddrs) ||
      (existing.clusterPeerId ?? '') !== (candidate.clusterPeerId ?? '');
    const livenessStale =
      !existing ||
      nowMs - Date.parse(existing.lastSeen) > livenessRefreshMs(env);

    if (stateChanged || livenessStale) {
      await env.BOXES.put(key, JSON.stringify(candidate), {
        expirationTtl: 7 * 86400,
      });
    } else {
      // Still bump lastTs in memory-only? No — without writing, replay guard
      // doesn't tighten. Accept this slack: an attacker who replays an
      // older-but-still-newer-than-stored-lastTs heartbeat within the drift
      // window can only set state to what the legitimate box just set it to.
      // Effectively a no-op.
    }
    return Response.json({ ok: true }, { headers: { 'access-control-allow-origin': '*' } });
  }

  if (body.type === 'relay' && body.data.type === 'relay') {
    const key = `relay:${body.data.dnsName}`;
    const existing = await env.RELAYS.get<RelayRecord>(key, 'json');
    if (!existing) {
      // Operator must seed via wrangler. Auto-registering relays from
      // heartbeats would let any peer claim to be a relay.
      console.warn(`relay heartbeat for unknown dnsName=${body.data.dnsName}; ignoring`);
      return Response.json(
        { error: 'relay not registered; seed entry via wrangler first' },
        { status: 404 },
      );
    }
    if (existing.peerId !== body.peerId) {
      console.warn(`relay heartbeat peerId mismatch: claim=${body.peerId} expected=${existing.peerId}`);
      return Response.json({ error: 'peerId mismatch' }, { status: 403 });
    }
    if (existing.lastTs !== undefined && signedTsMs <= existing.lastTs) {
      console.warn(`relay heartbeat replay/out-of-order from ${body.data.dnsName}`);
      return Response.json({ error: 'stale heartbeat' }, { status: 409 });
    }

    const candidate: RelayRecord = {
      ...existing,
      lastSeen: nowIso,
      lastTs: signedTsMs,
      reservationCount: body.data.reservationCount ?? existing.reservationCount,
      circuitCount: body.data.circuitCount ?? existing.circuitCount,
    };

    const countsChanged =
      existing.reservationCount !== candidate.reservationCount ||
      existing.circuitCount !== candidate.circuitCount;
    // Relays use a SHORTER refresh window than boxes. The `/relays`
    // stale-filter excludes records older than `RELAY_STALE_MIN` (default 7m);
    // if we only wrote every 4h like boxes, the relay would disappear from
    // /relays between writes. 5 min keeps it visible at low cost (1 relay ×
    // 288 writes/day vs 1440 if we wrote every heartbeat).
    const livenessStale =
      nowMs - Date.parse(existing.lastSeen) > relayLivenessRefreshMs(env);

    if (countsChanged || livenessStale) {
      await env.RELAYS.put(key, JSON.stringify(candidate));
    }
    return Response.json({ ok: true }, { headers: { 'access-control-allow-origin': '*' } });
  }

  return Response.json({ error: 'type/data mismatch' }, { status: 400 });
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  // Order-insensitive comparison so a peer that reports the same set in a
  // different order doesn't trigger a write.
  const sa = [...a].sort();
  const sb = [...b].sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}
