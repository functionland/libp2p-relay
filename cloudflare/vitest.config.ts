import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Node environment with Web Crypto + fetch built-in (Node 20+).
    environment: 'node',
    globals: false,
    pool: 'threads',
  },
});
