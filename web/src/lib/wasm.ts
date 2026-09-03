// WASM loader: initialises the vault-core module once and exposes its API.
import init, * as wasm from 'vault-core-wasm';

let ready: Promise<typeof wasm> | null = null;

/** Initialise (idempotent) and return the vault-core WASM API. */
export async function loadWasm(): Promise<typeof wasm> {
  if (!ready) {
    ready = init().then(() => wasm);
  }
  return ready;
}

export type { WasmVault } from 'vault-core-wasm';
