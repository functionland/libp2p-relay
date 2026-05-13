// Test fixtures: generates a fresh ed25519 keypair + matching libp2p peer ID
// per test, then signs arbitrary canonical-JSON payloads. Used to build
// known-good heartbeats for end-to-end verification tests.

import { webcrypto } from 'node:crypto';

// Make Web Crypto available globally so the imported `verify.ts` works
// identically in the test environment as in the Worker runtime.
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as any).crypto = webcrypto;
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      const v = digits[j] * 256 + carry;
      digits[j] = v % 58;
      carry = Math.floor(v / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let s = '';
  for (let i = 0; i < zeros; i++) s += '1';
  for (let i = digits.length - 1; i >= 0; i--) s += B58_ALPHABET[digits[i]];
  return s;
}

export function pubKeyToPeerId(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) throw new Error('expected 32-byte ed25519 pubkey');
  // protobuf PublicKey { Type=Ed25519, Data=pubkey }
  const protobuf = new Uint8Array(36);
  protobuf[0] = 0x08; protobuf[1] = 0x01;
  protobuf[2] = 0x12; protobuf[3] = 0x20;
  protobuf.set(pubkey, 4);
  // identity multihash: 0x00 (code) + 0x24 (length=36) + protobuf
  const mh = new Uint8Array(38);
  mh[0] = 0x00; mh[1] = 0x24;
  mh.set(protobuf, 2);
  return base58Encode(mh);
}

export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export async function generateTestKeypair(): Promise<{
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
  peerId: string;
}> {
  const pair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = await webcrypto.subtle.exportKey('raw', pair.publicKey);
  const publicKeyRaw = new Uint8Array(raw);
  const peerId = pubKeyToPeerId(publicKeyRaw);
  return { privateKey: pair.privateKey, publicKeyRaw, peerId };
}

// Canonical JSON matching the Worker's verify.ts implementation. Duplicated
// in the test to avoid coupling the test to the verify module (so a buggy
// canonicalJSON in verify.ts can't be masked by the test using the same
// function).
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJSON).join(',') + ']';
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON((value as Record<string, unknown>)[k])).join(',') + '}';
}

export async function signCanonical(
  privateKey: CryptoKey,
  payload: { peerId: string; timestamp: string; data: unknown },
): Promise<string> {
  const input = canonicalJSON(payload);
  const sig = await webcrypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(input));
  return bytesToBase64(new Uint8Array(sig));
}

export function nowIso(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}
