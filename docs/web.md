# Web client

A SvelteKit single-page app (`web/`) served by the self-hosted instance. All
cryptography runs in the browser via `vault-core` compiled to WASM; the master
password and derived keys never leave the page.

## Build & test

```bash
cd web
npm install
npm run build:wasm     # → crates/vault-core-wasm/pkg  (needs wasm-pack)
npm run build          # → web/build  (static SPA, adapter-static)
npm run check          # svelte-check (type check)
npm run test:a11y      # Playwright + axe WCAG 2.2 AA gate
```

Serve it from the instance by pointing the server at the build:
`VAULT_WEB_ROOT=/path/to/web/build` (see [self-hosting.md](self-hosting.md)).

## Architecture

- **`src/lib/backend.ts`** — a `VaultBackend` abstraction with two
  implementations: `WasmBackend` (browser) and `TauriBackend` (desktop, native
  `invoke`). The desktop app reuses this same UI with native crypto.
- **`src/lib/session.svelte.ts`** — central state (Svelte 5 runes): auth flows
  (OPAQUE + TOTP/WebAuthn), sync (push on change, pull, 409 merge), auto-lock,
  and clipboard timed-clear.
- **`src/lib/api.ts`** — server client; access tokens in memory only (a hard
  reload requires re-unlock).
- **Routes** — `/enroll`, `/unlock`, `/vault` (adaptive list/detail), `/settings`,
  `/import-export`, `/onboard` (desktop instance URL), `/quick` (desktop
  quick-search window).

## Session hardening

- Strict **CSP** with zero external origins (`svelte.config.js`);
  `wasm-unsafe-eval` only, to instantiate the vault WASM.
- **Auto-lock** on idle (configurable) and **clipboard timed-clear** with a
  live-region announcement.
- Access tokens are never persisted; the encrypted record cache is held in memory.

## Accessibility

Base styles cover visible focus, reduced-motion, 44px targets, dark mode, and a
skip link. The axe gate (`npm run test:a11y`) runs on the unauthenticated pages
in CI; authenticated screens are covered by the manual audit (task 7.1).
