// Shared types for the discovery Worker.

export interface Env {
  RELAYS: KVNamespace;
  BOXES: KVNamespace;

  // Tunable via wrangler.toml [vars] or Cloudflare dashboard → Variables.
  // These let you trade liveness-freshness for KV-write volume without
  // redeploying the Worker. Increase them to fit a smaller plan;
  // decrease them for paid-plan-grade freshness.
  LIVENESS_REFRESH_MIN?: string;        // boxes: write-on-change liveness refresh (default 240 = 4h)
  RELAY_LIVENESS_REFRESH_MIN?: string;  // relays: same idea, kept short so /relays stays current (default 5)
  BOX_STALE_MIN?: string;               // /find-box tier-1 stale cutoff (default 15)
  RELAY_STALE_MIN?: string;             // /relays excludes records older than this (default 7)
}

export interface RelayRecord {
  dnsName: string;
  peerId: string;
  addr: string;       // base multiaddr without /p2p suffix; used by Peering.Peers
  multiaddr: string;  // full multiaddr including /p2p/<peerId>; used by StaticRelays
  lastSeen: string;   // ISO 8601 — set to server time on accepted heartbeat
  lastTs?: number;    // epoch ms of last accepted SIGNED heartbeat timestamp (replay guard)
  reservationCount?: number;
  circuitCount?: number;
  // `createdAt`: ISO 8601, set by the seeding wrangler put. Used by /relays
  // to keep a freshly-seeded relay visible until its first heartbeat lands.
  createdAt?: string;
}

export interface BoxRecord {
  peerId: string;
  reservedOn: string[];   // dnsNames of relays the box is reserved on
  libp2pAddrs: string[];  // circuit multiaddrs the box advertises
  lastSeen: string;       // ISO 8601 — server time on accepted heartbeat
  lastTs?: number;        // epoch ms of last accepted SIGNED heartbeat timestamp (replay guard)
  // Optional ipfs-cluster libp2p peer ID, distinct from the kubo `peerId`
  // above. Used by operator tooling that cross-references with the
  // StoragePool / RewardEngine contracts (which register cluster identities).
  // Absent for bloxes that haven't bootstrapped their cluster identity yet.
  clusterPeerId?: string;
}

// Heartbeat payload (signed by sender's libp2p ed25519 private key).
export interface HeartbeatBody {
  type: 'box' | 'relay';
  peerId: string;
  // base64 of libp2p protobuf-wrapped ed25519 public key.
  // For identity-multihash peer IDs (always the case for ed25519) the
  // public key is recoverable from peerId alone, so this is optional.
  publicKey?: string;
  timestamp: string;  // ISO 8601 — rejected if more than 5 min from server clock
  data:
    | { type: 'box'; reservedOn: string[]; libp2pAddrs: string[]; clusterPeerId?: string }
    | { type: 'relay'; dnsName: string; reservationCount?: number; circuitCount?: number };
  // base64 ed25519 signature over the canonical JSON of
  // { peerId, timestamp, data } (keys sorted alphabetically).
  signature: string;
}

// Hardcoded default limits. The first three are tunable per-request via
// `env.*_MIN` (see Env interface above); HEARTBEAT_DRIFT_MS is fixed.
//
// Helpers to read env-overridable values:
export function relayStaleMs(env: Env): number {
  return (Number(env.RELAY_STALE_MIN ?? '7')) * 60_000;
}
export function boxStaleMs(env: Env): number {
  return (Number(env.BOX_STALE_MIN ?? '15')) * 60_000;
}
export function livenessRefreshMs(env: Env): number {
  return (Number(env.LIVENESS_REFRESH_MIN ?? '240')) * 60_000;
}
export function relayLivenessRefreshMs(env: Env): number {
  return (Number(env.RELAY_LIVENESS_REFRESH_MIN ?? '5')) * 60_000;
}

export const HEARTBEAT_DRIFT_MS = 300_000;    // reject heartbeats >5 min off from server time
