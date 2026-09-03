// Build the MV3 extension into loadable, unpacked folders (no store account
// needed) for Chromium (Chrome/Edge) and Firefox, plus zips for sideloading.
//
//   dist/          → Chrome/Edge (module service worker)
//   dist-firefox/  → Firefox (event-page background)
//   *.zip          → sideload/distribution archives

import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const chrome = resolve(root, 'dist');
const firefox = resolve(root, 'dist-firefox');
const wasm = resolve(root, '../crates/vault-core-wasm/pkg/vault_core_wasm_bg.wasm');

const common = { bundle: true, target: 'es2022', minify: true, legalComments: 'none' };

async function bundleJs(outdir, backgroundFormat) {
  // Service worker (Chrome: ESM module) or event-page background (Firefox: IIFE).
  await build({
    ...common,
    entryPoints: { background: resolve(root, 'src/background.ts') },
    outdir,
    format: backgroundFormat
  });
  // Content, injected, and popup scripts are always self-contained IIFEs.
  await build({
    ...common,
    entryPoints: {
      content: resolve(root, 'src/content.ts'),
      inject: resolve(root, 'src/inject.ts'),
      popup: resolve(root, 'src/popup/popup.ts')
    },
    outdir,
    format: 'iife'
  });
}

async function copyAssets(outdir, manifest) {
  await writeFile(resolve(outdir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  await copyFile(resolve(root, 'src/popup/popup.html'), resolve(outdir, 'popup.html'));
  await copyFile(wasm, resolve(outdir, 'vault_core_wasm_bg.wasm'));
}

function zip(dir, out) {
  try {
    execFileSync('zip', ['-r', '-FS', '-q', out, '.'], { cwd: dir });
    return true;
  } catch {
    return false;
  }
}

// --- Chromium (Chrome / Edge) ---------------------------------------------
await rm(chrome, { recursive: true, force: true });
await mkdir(chrome, { recursive: true });
await bundleJs(chrome, 'esm');
const baseManifest = JSON.parse(await readFile(resolve(root, 'public/manifest.json'), 'utf8'));
await copyAssets(chrome, baseManifest);

// --- Firefox --------------------------------------------------------------
await rm(firefox, { recursive: true, force: true });
await mkdir(firefox, { recursive: true });
await bundleJs(firefox, 'iife');
const ffManifest = structuredClone(baseManifest);
// Firefox uses an event-page background, not a service worker.
ffManifest.background = { scripts: ['background.js'] };
// `world: "MAIN"` content scripts need Firefox 128+.
ffManifest.browser_specific_settings.gecko.strict_min_version = '128.0';
await copyAssets(firefox, ffManifest);

// --- sideload archives ----------------------------------------------------
await rm(resolve(root, 'vault-extension-chrome.zip'), { force: true });
await rm(resolve(root, 'vault-extension-firefox.zip'), { force: true });
const zipped = zip(chrome, resolve(root, 'vault-extension-chrome.zip'));
zip(firefox, resolve(root, 'vault-extension-firefox.zip'));

console.log('built:');
console.log('  dist/          (Chrome/Edge — load unpacked)');
console.log('  dist-firefox/  (Firefox — load temporary add-on)');
if (zipped) console.log('  vault-extension-chrome.zip / vault-extension-firefox.zip');
