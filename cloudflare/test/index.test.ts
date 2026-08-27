import { describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') (globalThis as any).crypto = webcrypto;

import worker from '../src/index';
import { makeEnv } from './fakeKv';

describe('CORS preflight (browser clients)', () => {
  it('answers OPTIONS with 204 and allows the x-fula-client header', async () => {
    const env = makeEnv();
    const r = await worker.fetch(
      new Request('https://discovery.fula.network/relays', {
        method: 'OPTIONS',
        headers: {
          origin: 'https://blox.fx.land',
          'access-control-request-method': 'GET',
          'access-control-request-headers': 'x-fula-client',
        },
      }),
      env as any,
    );
    expect(r.status).toBe(204);
    expect(r.headers.get('access-control-allow-origin')).toBe('*');
    const allowed = (r.headers.get('access-control-allow-headers') ?? '').toLowerCase();
    expect(allowed).toContain('content-type');
    expect(allowed).toContain('x-fula-client');
    expect(r.headers.get('access-control-allow-methods')).toContain('GET');
  });
});
