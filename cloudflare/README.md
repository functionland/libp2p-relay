# Fula Discovery Worker

Cloudflare Worker that owns the live Fula relay configuration. Edges and the box-app discover relays through this service instead of hardcoding addresses, so adding/removing a relay becomes a KV update — no edge OTA push and no app release.

Sits next to (not in front of) the libp2p relays in `..`. The data path (libp2p circuit relay v2 over raw TCP/QUIC) does NOT go through Cloudflare; only discovery/health metadata does.

## Architecture (push-only model)

```
   ┌──────────────────────────────┐
   │  Relay VMs (Oracle ARM)      │
   │   - libp2p-relay (kubo)      │
   │   - relay-heartbeat.timer ───┼──► POST /heartbeat (every 60s, signed)
   └──────────────────────────────┘
                                    
   ┌──────────────────────────────┐
   │  Edge devices (fula-ota)     │──► POST /heartbeat (every 60s, signed)
   │   - kubo (circuit reservs)   │
   │   - readiness-check.py       │──► GET /relays (hourly drift check)
   └──────────────────────────────┘
                                    
   ┌──────────────────────────────┐
   │  Box-app (React Native)      │──► POST /find-box (per blox dial)
   │                              │──► GET /relays (on app launch, cache refresh)
   └──────────────────────────────┘
```

The Worker NEVER pulls health from kubo APIs (would require either public kubo RPC — insecure — or Cloudflare Tunnel on every relay — operational overhead). Relays self-report. Hourly cron does cleanup of stale `box:*` entries only.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/relays` | Returns currently-healthy relay records. Includes freshly-seeded relays without heartbeats so initial deploys aren't blocked. |
| POST | `/find-box` | Body `{ peerId }`. Returns target box's currently-reachable circuit multiaddrs. |
| POST | `/heartbeat` | Boxes/relays signal liveness. Body signed with libp2p ed25519 private key; replay-guarded by strict-monotonic signed timestamp + 5min drift window. |
| GET | `/healthz` | Plain-text liveness for external monitors. |
| (cron) | `0 * * * *` | Hourly cleanup of `box:*` records older than 7 days. |

Schema: `schema/kv-layout.md`.

## Cost & plan tier

Cloudflare KV free tier: 100k reads/day, **1k writes/day**, 100k Worker requests/day.

The defaults in `wrangler.toml` are calibrated for **~100 edges on the free tier**:

| Knob (`[vars]` in `wrangler.toml`) | Default | What it controls |
|---|---|---|
| `LIVENESS_REFRESH_MIN` | 240 (4 h) | Box write-on-change refresh window — idle boxes only write every 4 h |
| `RELAY_LIVENESS_REFRESH_MIN` | 5 | Relay refresh window — short so `/relays` keeps the relay visible |
| `BOX_STALE_MIN` | 15 | `/find-box` tier-1 cutoff — boxes older than this fall to tier 2 |
| `RELAY_STALE_MIN` | 7 | `/relays` excludes records older than this (must be > `RELAY_LIVENESS_REFRESH_MIN`) |

Plus on the edge: `HEARTBEAT_INTERVAL_SEC` defaults to **300** (5 min). Override via env var on the readiness-check systemd service.

### Free-tier math at 100 edges + 1 relay

| Metric | Daily volume (defaults above) | Free limit | Status |
|---|---|---|---|
| Worker requests | 100 boxes × 288 + 1 relay × 1440 + ~3k overhead ≈ **~33k/day** | 100k/day | ✓ |
| KV reads | ~33k/day (one get-existing per heartbeat) + overhead | 100k/day | ✓ |
| KV writes | 100 × (24/4) + 1 × (24×60/5) + ~10 state-change ≈ **~900/day** | 1k/day | ✓ (10% headroom) |

**Crossover**: at roughly 120 edges the writes hit 1k/day with state-change variance. Upgrade to **Workers Paid plan ($5/mo flat)** at that point and you can:
- Lower `LIVENESS_REFRESH_MIN` back to 30 (more accurate liveness)
- Lower `HEARTBEAT_INTERVAL_SEC` back to 60 (faster state detection)

Paid plan ceiling: ~20k peers before write costs become meaningful.

### Trade-offs of the free-tier defaults

- **5-min heartbeat instead of 1-min**: edge state changes (new circuit reservations, address changes) take up to 5 min to appear in KV. Fine for stable home boxes.
- **4-h liveness refresh**: an idle box's `lastSeen` can be up to 4 h old. `/find-box` tier 1 falls through to tier 2 (construct from current `/relays`) for idle boxes. App still gets working addresses; just not the box's exact self-reported set.
- **`/find-box` tier 2 always works** because relays heartbeat every 5 min and `RELAY_STALE_MIN=7` keeps them visible.

### Adjusting without redeploying

The four `[vars]` above are reachable from the Cloudflare dashboard:
**Workers & Pages → fula-discovery → Settings → Variables and Secrets**.
Change a value, save, takes effect on the next request — no `wrangler deploy` needed.

## Prerequisites

- Cloudflare account (free signup, no card to enable Workers).
- The `fx.land` zone on Cloudflare DNS. **If your DNS is at another registrar**, change nameservers to Cloudflare first — `wrangler` Custom Domain binding only works for zones on Cloudflare.
- `wrangler` CLI: `npm install -g wrangler`.
- Node.js 20+ locally.

## First-time setup

```bash
cd E:\GitHub\libp2p-relay\cloudflare
npm install
wrangler login                                    # opens browser for OAuth
wrangler kv:namespace create RELAYS               # prints { id = "<32-hex>" }
wrangler kv:namespace create BOXES                # prints { id = "<32-hex>" }
```

**Important**: the output of `wrangler kv:namespace create` looks like:

```
🌀  Creating namespace with title "fula-discovery-RELAYS"
✨  Success!
Add the following to your configuration file:
[[kv_namespaces]]
binding = "RELAYS"
id = "abc123...def"
```

Copy the `id = "..."` line content (just the 32-hex value) and paste over `REPLACE_WITH_RELAYS_NAMESPACE_ID` in `wrangler.toml`. Repeat for BOXES.

Deploy:

```bash
wrangler deploy
```

**Bind a custom domain** (the rest of the stack uses `https://discovery.fx.land`):

1. Cloudflare dashboard → Workers & Pages → `fula-discovery` → Settings → Triggers → Custom Domains.
2. Add `discovery.fx.land`.
3. Cloudflare auto-provisions DNS + TLS.

## Seeding the first relay

Use a JSON file to dodge cross-shell quoting hell (works identically on bash, zsh, PowerShell):

```bash
cat > seed-relay.json <<'EOF'
{
  "dnsName": "relay.dev.fx.land",
  "peerId": "12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835",
  "addr": "/dns/relay.dev.fx.land/tcp/4001",
  "multiaddr": "/dns/relay.dev.fx.land/tcp/4001/p2p/12D3KooWDRrBaAfPwsGJivBoUw5fE7ZpDiyfUjqgiURq2DEcL835",
  "createdAt": "2026-05-13T00:00:00.000Z",
  "lastSeen": "2026-05-13T00:00:00.000Z"
}
EOF

wrangler kv:key put --binding=RELAYS "relay:relay.dev.fx.land" --path=seed-relay.json
```

PowerShell users: same approach. Save `seed-relay.json` with `Set-Content -Encoding utf8 seed-relay.json '...'` or paste the contents into a file with any editor, then run the `wrangler kv:key put` command.

Once seeded, the Worker's `GET /relays` returns this entry immediately even before the first heartbeat (the freshly-seeded path in `relays.ts` — records without `lastTs` are included regardless of `lastSeen`).

**Then provision the heartbeat on the relay VM** (next section). Without this, `lastSeen` never updates and the relay disappears from `/relays` once `lastTs` becomes defined.

## Provisioning the relay-side heartbeat

On each relay VM (Oracle ARM running `libp2p-relay`):

```bash
# Pull the repo
git clone https://github.com/your-org/libp2p-relay.git
cd libp2p-relay
sudo bash scripts/install-heartbeat.sh
```

`install-heartbeat.sh`:

1. Installs `python3-cryptography` (heartbeat signs with the relay's ed25519 key).
2. Copies `relay-heartbeat.py` to `/usr/local/bin/`.
3. Installs systemd units `relay-heartbeat.service` + `relay-heartbeat.timer` (fires every 60s).
4. Runs one heartbeat immediately to verify connectivity.

Verify:

```bash
systemctl status relay-heartbeat.timer    # should show "active (waiting)"
journalctl -u relay-heartbeat.service --since "5 minutes ago"
```

If you see `HTTP 404: relay not registered` — you forgot to seed the KV entry. Run the wrangler put first.

## Adding a new relay (Phase 1 / Phase 2 / Phase N — zero code push)

1. Provision the VM, run `../install.sh --identity <new-key>` on it.
2. Add a Cloudflare DNS record for `relay-<region>.fx.land` pointing at the new VM (DNS must propagate BEFORE the next step or signatures verify against the wrong host).
3. SSH to the new VM, run `sudo bash scripts/install-heartbeat.sh` to start sending heartbeats.
4. Locally, seed the KV entry:

   ```bash
   cat > new-relay.json <<'EOF'
   {
     "dnsName": "relay-eu.fx.land",
     "peerId": "<new-peer-id>",
     "addr": "/dns/relay-eu.fx.land/tcp/4001",
     "multiaddr": "/dns/relay-eu.fx.land/tcp/4001/p2p/<new-peer-id>",
     "createdAt": "<now in ISO8601>",
     "lastSeen": "<now in ISO8601>"
   }
   EOF
   wrangler kv:key put --binding=RELAYS "relay:relay-eu.fx.land" --path=new-relay.json
   ```

That's it. Edges pick up at next kubo restart (Watchtower image refresh, weekly reboot, or readiness-check hourly drift check — whichever first). Apps pick up at next launch.

**No code push, no OTA, no app release.**

## Removing a relay

```bash
wrangler kv:key delete --binding=RELAYS "relay:relay-eu.fx.land"
```

Edges and apps stop seeing it within ~hour (readiness-check drift detection on edges; cache TTL on apps).

## Emergency kill switch

If discovery layer has a bug that breaks production, fall everything back to the canonical relay (`relay.dev.fx.land`) without any code change:

```bash
wrangler kv:key put --binding=RELAYS "meta:kill-switch" "1"
```

Once flipped, `/relays` returns ONLY the canonical relay record regardless of staleness. Edges + apps fall back to single-relay behavior identical to pre-discovery. Disable:

```bash
wrangler kv:key delete --binding=RELAYS "meta:kill-switch"
```

This is your rollback button. Use it.

## Per-device verification (after edge OTA)

**On the device:**

```bash
# 1. Did the discovery API actually get queried?
sudo journalctl -u fula --since "10 minutes ago" | grep -E "discovery|heartbeat"
# Expect: "discovery: fetched N relay(s) from https://discovery.fx.land/relays"

# 2. Is kubo's StaticRelays the Workers list?
jq '.Swarm.RelayClient.StaticRelays' /home/pi/.internal/ipfs_data/config

# 3. Is the box heartbeating successfully?
sudo journalctl -u fula-readiness-check --since "5 minutes ago" | grep heartbeat
# Expect: no "POST returned HTTP" warnings; "skipping (no signing key)" means cryptography missing.
```

**From your laptop:**

```bash
# 1. The device's box record should appear in KV within ~60s of fula boot:
wrangler kv:key get --binding=BOXES "box:12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"
# Expect JSON with reservedOn and libp2pAddrs; lastSeen within last 2 min.

# 2. findBox should return circuit addresses for that device:
curl -sX POST https://discovery.fx.land/find-box \
  -H 'content-type: application/json' \
  -d '{"peerId":"12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ"}'

# 3. Worker logs:
wrangler tail
```

## Monitoring (operational gaps to close before high scale)

The Worker has Cloudflare's default request analytics. For meaningful production telemetry you should add:

- **`/healthz` enrichment** to return `{ relays_healthy: N, boxes_active_15m: M }` for external uptime monitors.
- **External monitor** (BetterStack, Pingdom, or UptimeRobot — all have free tiers) hitting `/healthz` every minute. Page if `/relays` returns `[]` for more than 5 minutes.
- **Heartbeat-rejection alert**: tail `wrangler tail` for "heartbeat rejected" patterns. A spike means either canonical-JSON drift, clock skew, or compromised key.

These are not built in — operator must wire them.

## Failure modes

| Failure | Behavior | Recovery |
|---|---|---|
| Worker down at kubo container boot | `update_kubo_config.py` falls back to template defaults; box-app falls back to cached relay list then hardcoded `FXRelay`. | Auto-heals on Worker restore. |
| Workers down during steady-state | readiness-check drift check silently fails; kubo keeps running with last-fetched config. | None needed. |
| KV corrupted | Init `jq -e 'length > 0'` guards reject empty/invalid response; falls through to defaults. | Restore KV from backup. |
| Worker URL hijacked (DNS / CF account compromise) | Could direct boxes to malicious relays. | Set kill-switch flag immediately; rotate Cloudflare account. Long-term: sign `/relays` responses (Phase 0+ hardening, not yet implemented). |
| Bad rollout | (See kill switch above.) | Flip the KV flag. |

The 3-tier fallback in the box-app (live → cache → hardcoded) means Workers outage gives at-worst current behavior, never worse.

## Tech stack

TypeScript, Web Crypto API (Ed25519) via the `experimental` compatibility flag. Web Standard Fetch. No external crypto libs.
