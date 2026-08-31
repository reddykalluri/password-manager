import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // Served as static files by the self-hosted instance; SPA fallback so
    // client-side routing works for all crypto-in-browser flows.
    adapter: adapter({ fallback: 'index.html', precompress: false }),
    // Strict CSP with zero external origins (web-client session hardening).
    // `wasm-unsafe-eval` is required to instantiate the vault-core WASM module.
    csp: {
      mode: 'auto',
      directives: {
        'default-src': ['self'],
        'script-src': ['self', 'wasm-unsafe-eval'],
        'style-src': ['self', 'unsafe-inline'],
        'img-src': ['self', 'data:'],
        'font-src': ['self'],
        'connect-src': ['self'],
        'object-src': ['none'],
        'base-uri': ['self'],
        'form-action': ['self'],
        'frame-ancestors': ['none']
      }
    }
  }
};

export default config;
