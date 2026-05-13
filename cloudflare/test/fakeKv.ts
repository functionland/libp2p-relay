// Hand-rolled in-memory KV that matches the subset of KVNamespace surface
// the Worker actually uses. Faster and lighter than miniflare for unit tests
// that don't exercise scheduled handlers.

import type { Env } from '../src/types';

interface PutOptions {
  expirationTtl?: number;
}

export class FakeKV {
  private store = new Map<string, string>();

  async get(key: string): Promise<string | null>;
  async get<T>(key: string, type: 'json'): Promise<T | null>;
  async get<T>(key: string, type?: 'json'): Promise<T | string | null> {
    const v = this.store.get(key);
    if (v === undefined) return null;
    if (type === 'json') return JSON.parse(v) as T;
    return v;
  }

  async put(key: string, value: string, _opts?: PutOptions): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(opts: { prefix?: string; cursor?: string; limit?: number } = {}): Promise<{
    keys: { name: string }[];
    list_complete: boolean;
    cursor?: string;
  }> {
    const prefix = opts.prefix ?? '';
    const all = [...this.store.keys()].filter(k => k.startsWith(prefix)).sort();
    const limit = opts.limit ?? all.length;
    const slice = all.slice(0, limit);
    return {
      keys: slice.map(name => ({ name })),
      list_complete: slice.length === all.length,
    };
  }

  // Test helpers.
  _raw(key: string): string | undefined {
    return this.store.get(key);
  }
  _size(): number {
    return this.store.size;
  }
  _clear(): void {
    this.store.clear();
  }
  _seed(key: string, value: unknown): void {
    this.store.set(key, typeof value === 'string' ? value : JSON.stringify(value));
  }
}

export function makeEnv(): Env & { _RELAYS: FakeKV; _BOXES: FakeKV } {
  const RELAYS = new FakeKV();
  const BOXES = new FakeKV();
  return { RELAYS: RELAYS as unknown as KVNamespace, BOXES: BOXES as unknown as KVNamespace, _RELAYS: RELAYS, _BOXES: BOXES };
}
