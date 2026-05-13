import { describe, expect, it, beforeAll } from 'vitest';
import { webcrypto } from 'node:crypto';

// Make Web Crypto globally available before importing the module under test.
if (typeof globalThis.crypto === 'undefined') (globalThis as any).crypto = webcrypto;

import {
  peerIdToEd25519PubKey,
  canonicalJSON,
  verifyHeartbeat,
} from '../src/verify';
import {
  bytesToBase64,
  canonicalJSON as testCanonicalJSON,
  generateTestKeypair,
  nowIso,
  pubKeyToPeerId,
  signCanonical,
} from './fixtures';
import type { HeartbeatBody } from '../src/types';

describe('peerIdToEd25519PubKey', () => {
  it('round-trips a freshly generated ed25519 key', async () => {
    const { publicKeyRaw, peerId } = await generateTestKeypair();
    const recovered = peerIdToEd25519PubKey(peerId);
    expect(recovered).toEqual(publicKeyRaw);
  });

  it('round-trips multiple distinct keys', async () => {
    for (let i = 0; i < 3; i++) {
      const { publicKeyRaw, peerId } = await generateTestKeypair();
      expect(peerIdToEd25519PubKey(peerId)).toEqual(publicKeyRaw);
    }
  });

  it('rejects a peer ID that is too short', () => {
    // Build a too-short multihash (24-byte payload instead of 36).
    const tooShort = new Uint8Array(26);
    tooShort[0] = 0x00; tooShort[1] = 0x18;
    expect(() => peerIdToEd25519PubKey(pubKeyToPeerIdLike(tooShort))).toThrow(/unexpected length/);
  });

  it('rejects a peer ID with non-identity multihash code', () => {
    // 0x12 = sha2-256, length 32 = 0x20
    const bad = new Uint8Array(38);
    bad[0] = 0x12; bad[1] = 0x20;
    expect(() => peerIdToEd25519PubKey(pubKeyToPeerIdLike(bad))).toThrow(/not identity-multihash/);
  });

  it('rejects a non-ed25519 KeyType in the protobuf', async () => {
    const { publicKeyRaw } = await generateTestKeypair();
    // Replace KeyType byte (offset 3 in the peer-id bytes layout) with 0x00 (RSA).
    const bytes = new Uint8Array(38);
    bytes[0] = 0x00; bytes[1] = 0x24;
    bytes[2] = 0x08; bytes[3] = 0x00; // KeyType = RSA (wrong)
    bytes[4] = 0x12; bytes[5] = 0x20;
    bytes.set(publicKeyRaw, 6);
    expect(() => peerIdToEd25519PubKey(pubKeyToPeerIdLike(bytes))).toThrow(/KeyType != 1/);
  });

  it('rejects a malformed base58 peer ID', () => {
    // '0' is not in the base58 alphabet
    expect(() => peerIdToEd25519PubKey('12D3Koo0InvalidChar')).toThrow();
  });

  // Helper inverse of the canonical encoder for negative-test fixtures.
  function pubKeyToPeerIdLike(rawBytes: Uint8Array): string {
    const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let zeros = 0;
    while (zeros < rawBytes.length && rawBytes[zeros] === 0) zeros++;
    const digits: number[] = [];
    for (let i = zeros; i < rawBytes.length; i++) {
      let carry = rawBytes[i];
      for (let j = 0; j < digits.length; j++) {
        const v = digits[j] * 256 + carry;
        digits[j] = v % 58;
        carry = Math.floor(v / 58);
      }
      while (carry > 0) { digits.push(carry % 58); carry = Math.floor(carry / 58); }
    }
    let s = '';
    for (let i = 0; i < zeros; i++) s += '1';
    for (let i = digits.length - 1; i >= 0; i--) s += B58[digits[i]];
    return s;
  }
});

describe('canonicalJSON', () => {
  // Each fixture must produce a byte-identical output across the test impl
  // (in fixtures.ts) and the production impl (in verify.ts). Cross-language
  // (Python ↔ TS) equality is checked in test/canonical-cross-check.md.

  const cases: { name: string; input: unknown; expected: string }[] = [
    { name: 'null', input: null, expected: 'null' },
    { name: 'true', input: true, expected: 'true' },
    { name: 'false', input: false, expected: 'false' },
    { name: 'int 42', input: 42, expected: '42' },
    { name: 'string', input: 'hello', expected: '"hello"' },
    { name: 'empty array', input: [], expected: '[]' },
    { name: 'empty object', input: {}, expected: '{}' },
    { name: 'array of ints', input: [1, 2, 3], expected: '[1,2,3]' },
    { name: 'array of strings', input: ['a', 'b'], expected: '["a","b"]' },
    {
      name: 'object with sorted keys',
      input: { b: 1, a: 2 },
      expected: '{"a":2,"b":1}',
    },
    {
      name: 'nested object with deep key sort',
      input: { z: { y: 1, x: 2 }, a: [3, 4] },
      expected: '{"a":[3,4],"z":{"x":2,"y":1}}',
    },
    {
      name: 'string with quote',
      input: { x: 'a"b' },
      expected: '{"x":"a\\"b"}',
    },
    {
      name: 'string with backslash',
      input: { x: 'a\\b' },
      expected: '{"x":"a\\\\b"}',
    },
    {
      name: 'heartbeat-shaped payload',
      input: {
        peerId: '12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ',
        timestamp: '2026-05-13T05:30:00.000Z',
        data: {
          type: 'box',
          reservedOn: ['relay.dev.fx.land'],
          libp2pAddrs: ['/dns/relay.dev.fx.land/.../p2p-circuit/p2p/..'],
        },
      },
      expected:
        '{"data":{"libp2pAddrs":["/dns/relay.dev.fx.land/.../p2p-circuit/p2p/.."],"reservedOn":["relay.dev.fx.land"],"type":"box"},"peerId":"12D3KooWE6gC66XWxKacdna5LX4ymwnCCMpaddBFkB8At3WedRaZ","timestamp":"2026-05-13T05:30:00.000Z"}',
    },
  ];

  for (const c of cases) {
    it(`production canonicalJSON: ${c.name}`, () => {
      expect(canonicalJSON(c.input)).toBe(c.expected);
    });
    it(`test canonicalJSON (sanity): ${c.name}`, () => {
      expect(testCanonicalJSON(c.input)).toBe(c.expected);
    });
  }

  it('production and test impls agree on a random heartbeat shape', () => {
    const sample = {
      peerId: '12D3KooWX',
      timestamp: '2026-05-13T00:00:00.000Z',
      data: { type: 'box', reservedOn: ['r1', 'r2'], libp2pAddrs: ['m1'] },
    };
    expect(canonicalJSON(sample)).toBe(testCanonicalJSON(sample));
  });
});

describe('verifyHeartbeat', () => {
  let kp: Awaited<ReturnType<typeof generateTestKeypair>>;
  beforeAll(async () => {
    kp = await generateTestKeypair();
  });

  function basePayload(opts: Partial<HeartbeatBody> = {}): HeartbeatBody {
    return {
      type: 'box',
      peerId: kp.peerId,
      timestamp: nowIso(),
      data: { type: 'box', reservedOn: ['r1'], libp2pAddrs: ['m1'] },
      signature: '',
      ...opts,
    };
  }

  it('accepts a freshly signed heartbeat', async () => {
    const body = basePayload();
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: body.data,
    });
    expect(await verifyHeartbeat(body)).toBeNull();
  });

  it('rejects a signature signed over a different payload', async () => {
    const body = basePayload();
    // Sign a *different* data shape, then submit body unchanged.
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: { type: 'box', reservedOn: ['DIFFERENT'], libp2pAddrs: ['m1'] },
    });
    expect(await verifyHeartbeat(body)).toMatch(/signature verification failed/);
  });

  it('rejects when peerId claim does not own the signing key', async () => {
    const other = await generateTestKeypair();
    const body = basePayload({ peerId: other.peerId });
    // Sign with kp (not `other`) — peer ID claims `other.peerId` so verify
    // recovers `other.publicKeyRaw` from peerId, and the sig (made by kp)
    // doesn't verify against that recovered key.
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: body.data,
    });
    expect(await verifyHeartbeat(body)).toMatch(/signature verification failed/);
  });

  it('rejects timestamp drift beyond 5 minutes', async () => {
    const body = basePayload({ timestamp: nowIso(-10 * 60 * 1000) });  // 10 min in past
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: body.data,
    });
    expect(await verifyHeartbeat(body)).toMatch(/timestamp drift/);
  });

  it('rejects future timestamp drift beyond 5 minutes', async () => {
    const body = basePayload({ timestamp: nowIso(10 * 60 * 1000) });   // 10 min in future
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: body.data,
    });
    expect(await verifyHeartbeat(body)).toMatch(/timestamp drift/);
  });

  it('rejects signature with wrong byte length', async () => {
    const body = basePayload({ signature: bytesToBase64(new Uint8Array(32)) }); // 32 bytes, not 64
    expect(await verifyHeartbeat(body)).toMatch(/signature length/);
  });

  it('rejects body with missing required fields', async () => {
    expect(await verifyHeartbeat({ peerId: '', timestamp: '', signature: '', data: {} as any, type: 'box' })).toMatch(
      /missing required fields/,
    );
  });

  it('rejects malformed timestamp', async () => {
    const body = basePayload({ timestamp: 'not-a-date' });
    body.signature = await signCanonical(kp.privateKey, {
      peerId: body.peerId,
      timestamp: body.timestamp,
      data: body.data,
    });
    expect(await verifyHeartbeat(body)).toMatch(/invalid timestamp/);
  });
});
