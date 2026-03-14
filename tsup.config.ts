import { defineConfig } from 'tsup';

export default defineConfig([
  // Library build (ESM + CJS)
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    target: 'node20',
    outDir: 'dist',
    outExtension({ format }) {
      return {
        js: format === 'esm' ? '.mjs' : '.cjs',
      };
    },
  },
  // CLI build (ESM only — runs via `node dist/cli.js`)
  {
    entry: ['src/cli.ts'],
    format: ['esm'],
    sourcemap: true,
    splitting: false,
    target: 'node20',
    outDir: 'dist',
    outExtension() {
      return { js: '.js' };
    },
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
]);
