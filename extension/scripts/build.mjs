// Build the MV3 extension: bundle the service worker (ESM), the content and
// injected scripts and the popup (IIFE), then copy the manifest, popup HTML, and
// the vault-core WASM binary into dist/.

import { build } from 'esbuild';
import { copyFile, mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = resolve(root, 'dist');

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

const common = {
  bundle: true,
  target: 'es2022',
  minify: true,
  legalComments: 'none',
  logLevel: 'info'
};

// Service worker as an ES module.
await build({
  ...common,
  entryPoints: { background: resolve(root, 'src/background.ts') },
  outdir: dist,
  format: 'esm'
});

// Content, injected, and popup scripts as self-contained IIFEs.
await build({
  ...common,
  entryPoints: {
    content: resolve(root, 'src/content.ts'),
    inject: resolve(root, 'src/inject.ts'),
    popup: resolve(root, 'src/popup/popup.ts')
  },
  outdir: dist,
  format: 'iife'
});

await copyFile(resolve(root, 'public/manifest.json'), resolve(dist, 'manifest.json'));
await copyFile(resolve(root, 'src/popup/popup.html'), resolve(dist, 'popup.html'));
await copyFile(
  resolve(root, '../crates/vault-core-wasm/pkg/vault_core_wasm_bg.wasm'),
  resolve(dist, 'vault_core_wasm_bg.wasm')
);

console.log('built extension → dist/');
