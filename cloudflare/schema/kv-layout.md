# KV Schema

Two KV namespaces, both bound to the Worker via `wrangler.toml`.

## `RELAYS` namespace

One entry per relay VM, plus a `meta:kill-switch` flag for emergency rollback. Relay key format: `relay:<dnsName>`.

```json
{
  "dnsName": "relay.dev.fx.land",
  "peerId": "12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835",
  "addr": "/dns/relay.dev.fx.land/tcp/4001",
  "multiaddr": "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835",
  "createdAt": "2026-05-13T00:00:00.000Z",
  "lastSeen": "2026-05-13T05:30:00.000Z",
  "lastTs": 1747200000000,
  "reservationCount": 1234,
  "circuitCount": 45
}
```

Fields:

- `dnsName` — unique key suffix; the relay's hostname.
- `peerId` — relay's libp2p ed25519 peer ID.
- `addr` — base multiaddr (no `/p2p/...` suffix). Used in kubo `Peering.Peers`.
- `multiaddr` — full multiaddr including `/p2p/<peerId>`. Used in kubo `Swarm.RelayClient.StaticRelays`.
- `createdAt` — ISO 8601 when the operator seeded this record. Stable; never overwritten by heartbeats.
- `lastSeen` — ISO 8601 of most recent accepted heartbeat (server clock). Bumped on heartbeat only when state changed OR previous value > 30 min old (write-on-change).
- `lastTs` — epoch ms of the *signed* heartbeat timestamp from the most recent accepted heartbeat. **Replay guard**: incoming heartbeats with `signedTimestamp ≤ lastTs` are rejected with 409.
- `reservationCount`, `circuitCount` — last reported counts from the relay's heartbeat. Informational; not load-bearing.

**Visibility rule in `GET /relays`**:
- A record with `lastTs === undefined` is **always included** (freshly seeded, hasn't heartbeated yet).
- A record with `lastTs` set is included only if `lastSeen` is within `RELAY_STALE_MIN` (default 7 min, tunable via `wrangler.toml [vars]`) of now.

### `meta:kill-switch`

```
"1"
```

A plain `"1"` value flips `GET /relays` into emergency mode, returning only the canonical `relay.dev.fx.land` entry. See `cloudflare/README.md` § "Emergency kill switch".

## `BOXES` namespace

One entry per edge device. Key format: `box:<peerId>`.

```json
{
  "peerId": "12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ",
  "reservedOn": ["relay.dev.fx.land", "relay-eu.fx.land"],
  "libp2pAddrs": [
    "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835/p2p-circuit/p2p/12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"
  ],
  "lastSeen": "2026-05-13T05:30:00.000Z",
  "lastTs": 1747200000000
}
```

Fields:

- `peerId` — box's libp2p peer ID.
- `reservedOn` — dnsNames of relays the box currently holds reservations on (self-reported).
- `libp2pAddrs` — circuit multiaddrs the box advertises. Used directly by `POST /find-box`.
- `lastSeen` — ISO 8601 of last write (server clock).
- `lastTs` — epoch ms of the most recent accepted signed heartbeat timestamp. Replay guard.

`POST /find-box` excludes boxes whose `lastSeen` is older than `BOX_STALE_MIN` (default 15 min, tunable via `wrangler.toml [vars]`) and falls back to "construct addresses from current relay set" in that case.

`expirationTtl: 7 days` is set on every put; the hourly cron also reaps any record whose `lastSeen` is older than 7 days as belt-and-suspenders.

## Replay & write-on-change semantics (summary)

Every accepted heartbeat:

1. Passes signature verification.
2. Has signed timestamp within ±5 min of server clock (drift window).
3. Has signed timestamp strictly greater than the stored `lastTs` for this peer (monotonic replay guard).

A KV write happens only if:
- State changed (different `reservedOn` / `libp2pAddrs` for box; different counts for relay), OR
- Stored `lastSeen` is older than the liveness-refresh window (boxes: `LIVENESS_REFRESH_MIN` default 240 min; relays: `RELAY_LIVENESS_REFRESH_MIN` default 5 min).

Different refresh windows for boxes vs relays because relays need to stay visible in `/relays` (short window) while idle boxes don't need frequent KV writes (long window — saves write budget at scale).

At default settings + idle state: ~6 writes/day per box, ~288 writes/day per relay. 100 boxes + 1 relay ≈ ~900 writes/day, fits the free-tier 1k/day budget.

## Why KV and not D1

D1 (SQLite) would give richer querying but adds a dependency and the access pattern here is purely key-by-known-id. KV's free tier (1 GB storage, 100k reads/day) is far more than enough; write tier is the constraint and is handled by write-on-change. Simpler choice.
