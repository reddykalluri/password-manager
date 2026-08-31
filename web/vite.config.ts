import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // The wasm-pack glue self-fetches its `.wasm`; don't pre-bundle it.
  optimizeDeps: { exclude: ['vault-core-wasm'] },
  build: { target: 'es2022' }
});
