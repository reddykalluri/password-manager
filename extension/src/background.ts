// MV3 background service worker: holds the unlocked vault in extension-private
// memory (WASM), talks to the server for standalone sync, and delegates to the
// desktop app over native messaging when present. No long-lived plaintext
// secrets are persisted (browser-extensions spec: secret handling).

import initWasm, * as wasm from 'vault-core-wasm';
import { ExtApi, type AuthTokens } from './lib/api';
import { decideCapture, type CaptureDecision, type ExistingItem, type NeverAsk } from './lib/capture';
import { registrableDomain } from './lib/matching';
import { fail, ok, type Candidate, type ExtRequest } from './lib/messages';
import { desktopAvailable, desktopCandidates, desktopFill, desktopUnlockState } from './lib/nativeMessaging';

let wasmReady: Promise<void> | null = null;
function ensureWasm(): Promise<void> {
  if (!wasmReady) {
    // The .wasm is bundled as an extension resource.
    wasmReady = initWasm(chrome.runtime.getURL('vault_core_wasm_bg.wasm')).then(() => undefined);
  }
  return wasmReady;
}

const api = new ExtApi();
let vault: wasm.WasmVault | null = null;
let cursor = 0;
const baseVersions = new Map<string, number>();
const DEVICE = 'Browser extension';
const neverAsk: NeverAsk = { global: false, domains: [] };
let pending: CaptureDecision | null = null;

async function unlock(instanceUrl: string, username: string, password: string, totp?: string) {
  await ensureWasm();
  api.base = instanceUrl.replace(/\/$/, '');

  const ls = JSON.parse(wasm.opaqueLoginStart(password));
  const start = await api.loginStart(username, ls.message);
  const finalization = wasm.opaqueLoginFinish(ls.state, password, start.credential_response);
  const outcome = await api.loginFinish({
    flow_id: start.flow_id,
    credential_finalization: finalization,
    device_name: DEVICE,
    totp_code: totp
  });
  if (!('access_token' in outcome)) throw new Error('second factor required');
  api.accessToken = (outcome as AuthTokens).access_token;

  const crypto = await api.accountCrypto();
  const pulled = await api.pull(0);
  cursor = pulled.cursor;
  for (const r of pulled.records) baseVersions.set(r.id, r.version);
  vault = wasm.WasmVault.unlock(password, JSON.stringify(crypto), JSON.stringify(pulled.records));
}

function requireVault(): wasm.WasmVault {
  if (!vault) throw new Error('locked');
  return vault;
}

async function candidates(url: string): Promise<Candidate[]> {
  if (await desktopAvailable()) {
    return (await desktopCandidates(url)).map((i) => ({
      id: String(i.id),
      title: String(i.title ?? ''),
      username: String(i.username ?? '')
    }));
  }
  const v = requireVault();
  return v.candidatesFor(url).map((id) => {
    const c = JSON.parse(v.getItem(id));
    return { id, title: c.title, username: c.data?.type === 'login' ? c.data.username : '' };
  });
}

async function fill(id: string) {
  if (await desktopAvailable()) return desktopFill(id);
  const c = JSON.parse(requireVault().getItem(id));
  if (c.data?.type !== 'login') return null;
  return { username: c.data.username, password: c.data.password, totp: c.data.totp ?? null };
}

async function handle(req: ExtRequest) {
  switch (req.type) {
    case 'GET_STATE': {
      const delegated = await desktopAvailable();
      const unlocked = delegated ? await desktopUnlockState() : vault !== null;
      return ok({ unlocked, delegatedToDesktop: delegated });
    }
    case 'UNLOCK':
      await unlock(req.instanceUrl, req.username, req.password, req.totp);
      return ok({ unlocked: true });
    case 'LOCK':
      // Dropping the handle zeroises keys.
      vault = null;
      api.accessToken = null;
      baseVersions.clear();
      cursor = 0;
      return ok({ unlocked: false });
    case 'CANDIDATES':
      return ok(await candidates(req.url));
    case 'FILL':
      return ok(await fill(req.id));
    case 'SEARCH': {
      const v = requireVault();
      return ok(
        v.search(req.query).map((id) => {
          const c = JSON.parse(v.getItem(id));
          return {
            id,
            title: c.title,
            username: c.data?.type === 'login' ? c.data.username : ''
          } as Candidate;
        })
      );
    }
    case 'GENERATE':
      await ensureWasm();
      return ok(
        req.kind === 'password'
          ? wasm.generatePassword(JSON.stringify(req.opts))
          : wasm.generatePassphrase(JSON.stringify(req.opts))
      );
    case 'SAVE': {
      const v = requireVault();
      const content = {
        title: req.baseDomain,
        data: {
          type: 'login',
          username: req.username,
          password: req.password,
          uris: [{ value: req.url, match_rule: 'base_domain' }]
        },
        notes: '',
        tags: [],
        favorite: false,
        custom_fields: []
      };
      const id = v.createItem(JSON.stringify(content));
      await syncPush();
      clearPending();
      return ok({ id });
    }
    case 'UPDATE': {
      const v = requireVault();
      const c = JSON.parse(v.getItem(req.id));
      if (c.data?.type === 'login') c.data.password = req.newPassword;
      v.updateItem(req.id, JSON.stringify(c));
      await syncPush();
      clearPending();
      return ok({ id: req.id });
    }
    case 'CAPTURE': {
      if (!vault) return ok(null); // locked → ignore submitted creds
      const base = registrableDomain(req.url) ?? '';
      const existing: ExistingItem[] = vault.candidatesFor(req.url).map((id) => {
        const c = JSON.parse(requireVault().getItem(id));
        return {
          id,
          baseDomain: base,
          username: c.data?.username ?? '',
          password: c.data?.password ?? ''
        };
      });
      const decision = decideCapture(req.url, req.username, req.password, existing, neverAsk);
      if (decision.action !== 'none') {
        pending = decision;
        chrome.action?.setBadgeText({ text: '1' });
        chrome.action?.setBadgeBackgroundColor?.({ color: '#2f57d6' });
      }
      return ok(decision);
    }
    case 'GET_PENDING':
      return ok(pending);
    case 'CLEAR_PENDING':
      clearPending();
      return ok(null);
    default:
      return fail('unknown request');
  }
}

function clearPending() {
  pending = null;
  chrome.action?.setBadgeText({ text: '' });
}

async function syncPush() {
  const v = requireVault();
  const records: Array<{ id: string; version: number }> = JSON.parse(v.records());
  for (const rec of records) {
    const base = baseVersions.get(rec.id) ?? 0;
    if (rec.version === base) continue;
    try {
      const res = await api.push(rec, base);
      baseVersions.set(rec.id, res.new_version);
      cursor = Math.max(cursor, res.cursor);
    } catch {
      /* leave dirty; retried on next sync */
    }
  }
}

chrome.runtime.onMessage.addListener((req: ExtRequest, _sender, sendResponse) => {
  handle(req)
    .then(sendResponse)
    .catch((e) => sendResponse(fail((e as Error).message)));
  return true; // async response
});
