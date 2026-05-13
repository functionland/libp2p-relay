// Heartbeat signature verification.
//
// libp2p ed25519 peer IDs are identity-multihash-encoded — the public key
// is recoverable from the peer ID alone. We use that to verify signatures
// without requiring callers to send the public key separately.
//
// Encoding (reading left to right when base58-decoded):
//   peer ID bytes = <multihash header><protobuf(PublicKey)>
//   multihash header for identity, len 36 = 0x00 0x24
//   protobuf(PublicKey) for ed25519 = 0x08 0x01 0x12 0x20 <32-byte-key>
// Total: 2 + 4 + 32 = 38 bytes.
//
// References:
//   - libp2p PeerID spec: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
//   - PublicKey protobuf: https://github.com/libp2p/specs/blob/master/keys/keys.md

import { HeartbeatBody, HEARTBEAT_DRIFT_MS } from './types';

// Standard base58btc alphabet (Bitcoin / IPFS).
const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP: Record<string, number> = {};
for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = i;

function base58Decode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array();
  // count leading '1's — they map to leading zero bytes
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;

  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = B58_MAP[s[i]];
    if (c === undefined) throw new Error(`invalid base58 character: ${s[i]}`);
    let carry = c;
    for (let j = 0; j < bytes.length; j++) {
      const v = bytes[j] * 58 + carry;
      bytes[j] = v & 0xff;
      carry = v >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // bytes is little-endian; flip and prepend leading zeros
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}

function base64Decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Extract the raw 32-byte ed25519 public key from a libp2p peer ID string.
 * Throws if the peer ID is not an identity-multihash ed25519 peer ID.
 */
export function peerIdToEd25519PubKey(peerId: string): Uint8Array {
  const bytes = base58Decode(peerId);
  // Expect: 0x00 0x24 0x08 0x01 0x12 0x20 <32 bytes>
  if (bytes.length !== 38) {
    throw new Error(`peer ID has unexpected length ${bytes.length}; expected 38 for identity-multihash ed25519`);
  }
  if (bytes[0] !== 0x00) throw new Error('peer ID is not identity-multihash (got 0x' + bytes[0].toString(16) + ')');
  if (bytes[1] !== 0x24) throw new Error('peer ID multihash length is not 36');
  if (bytes[2] !== 0x08 || bytes[3] !== 0x01) throw new Error('peer ID is not an ed25519 key (KeyType != 1)');
  if (bytes[4] !== 0x12 || bytes[5] !== 0x20) throw new Error('peer ID public-key field is not 32 bytes');
  return bytes.slice(6);
}

/**
 * Canonical JSON serialization with sorted keys, used as the signing input.
 * Both sender and verifier must produce the exact same bytes.
 */
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJSON).join(',') + ']';
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON((value as Record<string, unknown>)[k])).join(',') + '}';
}

/**
 * Verify a heartbeat:
 *   1. Public key is recoverable from peerId (or matches a provided key).
 *   2. Timestamp is within HEARTBEAT_DRIFT_MS of server time (replay protection).
 *   3. Signature is a valid ed25519 sig over canonicalJSON({peerId, timestamp, data}).
 *
 * Returns null on success, or an error message on failure (for logging).
 */
export async function verifyHeartbeat(body: HeartbeatBody): Promise<string | null> {
  if (!body.peerId || !body.timestamp || !body.signature || !body.data) {
    return 'missing required fields';
  }

  // Timestamp drift check (anti-replay).
  const sentAt = Date.parse(body.timestamp);
  if (isNaN(sentAt)) return 'invalid timestamp';
  const drift = Math.abs(Date.now() - sentAt);
  if (drift > HEARTBEAT_DRIFT_MS) return `timestamp drift ${drift}ms exceeds limit ${HEARTBEAT_DRIFT_MS}ms`;

  // Recover ed25519 public key from peer ID.
  let pubkey: Uint8Array;
  try {
    pubkey = peerIdToEd25519PubKey(body.peerId);
  } catch (e) {
    return `peerId decode failed: ${(e as Error).message}`;
  }

  // Build signing input: canonical JSON of (peerId, timestamp, data).
  const signingInput = canonicalJSON({
    peerId: body.peerId,
    timestamp: body.timestamp,
    data: body.data,
  });

  // Decode signature.
  let sig: Uint8Array;
  try {
    sig = base64Decode(body.signature);
  } catch {
    return 'signature is not valid base64';
  }
  if (sig.length !== 64) return `signature length ${sig.length} != 64`;

  // Import public key into Web Crypto.
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('raw', pubkey, { name: 'Ed25519' }, false, ['verify']);
  } catch (e) {
    return `key import failed: ${(e as Error).message}`;
  }

  // Verify.
  const ok = await crypto.subtle.verify(
    'Ed25519',
    key,
    sig,
    new TextEncoder().encode(signingInput),
  );
  return ok ? null : 'signature verification failed';
}
