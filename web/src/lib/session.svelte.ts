// Central session state: auth flows, sync, auto-lock, and clipboard hygiene.
// Delegates all vault crypto to a VaultBackend (WASM in the browser, native
// vault-core via Tauri on the desktop). Uses Svelte 5 runes.

import { api, ApiError, isTokens, type SecondFactorChallenge } from './api';
import { createBackend, isTauri, type VaultBackend } from './backend';
import type { ItemContent, ItemRecord } from './types';
import { doWebauthnAssertion } from './webauthn';

export interface Summary {
  id: string;
  title: string;
  username: string;
  kind: string;
  favorite: boolean;
}

class Session {
  ready = $state(false);
  unlocked = $state(false);
  items = $state<Summary[]>([]);
  query = $state('');
  announce = $state('');
  error = $state<string | null>(null);
  recoveryCode = $state<string | null>(null);
  lockTimeoutSecs = $state(300);
  clipboardClearSecs = $state(60);
  clipboardCountdown = $state(0);

  private backend: VaultBackend = createBackend();
  private cursor = 0;
  private baseVersions = new Map<string, number>();
  private byId = new Map<string, Summary>();
  private deviceName = 'Desktop/Web';
  private lockInterval: ReturnType<typeof setInterval> | null = null;
  private clipToken = 0;
  private lastTouch = 0;

  async init() {
    api.loadInstance();
    this.ready = true;
  }

  /** Whether the app still needs instance-URL onboarding (desktop first run). */
  needsOnboarding(): boolean {
    return isTauri() && !api.hasInstance();
  }

  /** Adopt an already-unlocked native session (secondary windows, e.g. the
   * quick-search window, share the desktop's native vault). */
  async attach(): Promise<boolean> {
    const unlocked = await this.backend.unlocked();
    if (unlocked) {
      this.unlocked = true;
      await this.rebuildSummaries();
      await this.refreshList();
    }
    return unlocked;
  }

  say(msg: string) {
    this.announce = '';
    queueMicrotask(() => (this.announce = msg));
  }

  // --- stateless helpers ---
  async negotiateParams(targetMs = 500): Promise<string> {
    try {
      return await this.backend.benchmarkKdf(targetMs);
    } catch {
      return await this.backend.defaultKdfParams();
    }
  }
  async generatePassword(opts: unknown): Promise<string> {
    return this.backend.generatePassword(JSON.stringify(opts));
  }
  async generatePassphrase(opts: unknown): Promise<string> {
    return this.backend.generatePassphrase(JSON.stringify(opts));
  }
  async rateStrength(pw: string): Promise<{ score: number; entropy_bits: number; label: string }> {
    return JSON.parse(await this.backend.rateStrength(pw));
  }

  // --- enrolment ---
  async enroll(opts: { username: string; password: string; inviteCode?: string; paramsJson: string }) {
    const { recoveryCode, accountCrypto } = await this.backend.enroll(opts.password, opts.paramsJson);

    const rs = JSON.parse(await this.backend.opaqueRegisterStart(opts.password));
    const { registration_response } = await api.registerStart(opts.username, rs.message);
    const upload = await this.backend.opaqueRegisterFinish(rs.state, opts.password, registration_response);
    const tokens = await api.registerFinish({
      username: opts.username,
      registration_upload: upload,
      account_crypto: JSON.parse(accountCrypto),
      invite_code: opts.inviteCode || undefined,
      device_name: this.deviceName
    });
    api.setTokens(tokens);
    this.recoveryCode = recoveryCode;
    await this.afterUnlock();
  }

  // --- unlock / login ---
  async unlock(opts: { username: string; password: string; totpCode?: string }) {
    const ls = JSON.parse(await this.backend.opaqueLoginStart(opts.password));
    const start = await api.loginStart(opts.username, ls.message);
    const finalization = await this.backend.opaqueLoginFinish(ls.state, opts.password, start.credential_response);

    let outcome = await api.loginFinish({
      flow_id: start.flow_id,
      credential_finalization: finalization,
      device_name: this.deviceName,
      totp_code: opts.totpCode
    });

    if (!isTokens(outcome) && 'second_factor' in outcome) {
      const sf = (outcome as { second_factor: SecondFactorChallenge }).second_factor;
      const assertion = await doWebauthnAssertion(sf.webauthn_challenge);
      outcome = await api.loginWebauthnFinish({
        webauthn_flow_id: sf.webauthn_flow_id,
        credential: assertion,
        device_name: this.deviceName
      });
    }
    if (!isTokens(outcome)) throw new Error('unexpected login response');
    api.setTokens(outcome);

    const crypto = await api.accountCrypto();
    const pulled = await api.pull(0);
    this.cursor = pulled.cursor;
    await this.backend.unlock(opts.password, JSON.stringify(crypto), JSON.stringify(pulled.records));
    for (const r of pulled.records) this.baseVersions.set(r.id, r.version);
    await this.afterUnlock();
  }

  private async afterUnlock() {
    this.unlocked = true;
    this.error = null;
    await this.backend.setLockTimeoutSecs(this.lockTimeoutSecs);
    await this.rebuildSummaries();
    await this.refreshList();
    this.startLockWatch();
    this.say('Vault unlocked.');
  }

  async lock() {
    this.stopLockWatch();
    await this.backend.lock();
    api.clearTokens();
    this.unlocked = false;
    this.items = [];
    this.byId.clear();
    this.baseVersions.clear();
    this.cursor = 0;
    this.query = '';
    this.say('Vault locked.');
  }

  touch() {
    const now = Date.now();
    if (now - this.lastTouch < 1000) return; // throttle IPC on desktop
    this.lastTouch = now;
    void this.backend.touch();
  }

  private startLockWatch() {
    this.stopLockWatch();
    this.lockInterval = setInterval(async () => {
      if (await this.backend.shouldLock()) {
        await this.lock();
        this.say('Vault auto-locked after inactivity.');
      }
    }, 5000);
  }
  private stopLockWatch() {
    if (this.lockInterval) clearInterval(this.lockInterval);
    this.lockInterval = null;
  }
  async setLockTimeout(secs: number) {
    this.lockTimeoutSecs = secs;
    if (this.unlocked) await this.backend.setLockTimeoutSecs(secs);
  }

  // --- item model ---
  async getItem(id: string): Promise<ItemContent> {
    return JSON.parse(await this.backend.getItem(id));
  }

  async createItem(content: ItemContent): Promise<string> {
    const id = await this.backend.createItem(JSON.stringify(content));
    await this.loadSummary(id);
    await this.refreshList();
    await this.syncPush();
    this.say(`Created ${content.title}.`);
    return id;
  }

  async updateItem(id: string, content: ItemContent) {
    await this.backend.updateItem(id, JSON.stringify(content));
    if (content.binned_at) this.byId.delete(id);
    else await this.loadSummary(id);
    await this.refreshList();
    await this.syncPush();
    this.say(`Saved ${content.title}.`);
  }

  async moveToBin(id: string) {
    await this.backend.moveToBin(id);
    this.byId.delete(id);
    await this.refreshList();
    await this.syncPush();
    this.say('Moved to bin.');
  }
  async restoreFromBin(id: string) {
    await this.backend.restoreFromBin(id);
    await this.loadSummary(id);
    await this.refreshList();
    await this.syncPush();
  }

  async history(id: string): Promise<Array<{ modified_at: string; content: ItemContent }>> {
    return JSON.parse(await this.backend.history(id));
  }
  async restoreRevision(id: string, index: number) {
    await this.backend.restoreRevision(id, index);
    await this.loadSummary(id);
    await this.refreshList();
    await this.syncPush();
    this.say('Revision restored.');
  }

  // --- import / export ---
  async importPreview(kind: string, data: string) {
    return JSON.parse(await this.backend.importPreview(kind, data));
  }
  async importCommit(items: ItemContent[]): Promise<number> {
    const n = await this.backend.importCommit(JSON.stringify(items));
    await this.rebuildSummaries();
    await this.refreshList();
    await this.syncPush();
    this.say(`Imported ${n} item(s).`);
    return n;
  }
  exportEncrypted(password: string): Promise<string> {
    return this.backend.exportEncrypted(password);
  }
  exportCsvGated(password: string): Promise<string> {
    return this.backend.exportCsvGated(password);
  }

  // --- account security ---
  async changeMasterPassword(current: string, next: string, extra: { totp_code?: string } = {}) {
    const paramsJson = await this.negotiateParams();
    const updated = await this.backend.changeMasterPassword(current, next, paramsJson);
    await api.updateAccountCrypto(JSON.parse(updated), extra);
    this.say('Master password changed.');
  }
  async regenerateRecoveryCode(password: string): Promise<string> {
    const code = await this.backend.regenerateRecoveryCode(password);
    this.recoveryCode = code;
    return code;
  }
  async uploadCryptoAfterRecoveryRegen(extra: { totp_code?: string } = {}) {
    await api.updateAccountCrypto(JSON.parse(await this.backend.accountCrypto()), extra);
  }

  // --- clipboard ---
  async copySecret(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      this.say('Clipboard unavailable; copy manually.');
      return;
    }
    const token = ++this.clipToken;
    const secs = this.clipboardClearSecs;
    this.clipboardCountdown = secs;
    this.say(`${label} copied. Clipboard clears in ${secs} seconds.`);
    const tick = setInterval(() => {
      if (token !== this.clipToken) return clearInterval(tick);
      this.clipboardCountdown -= 1;
      if (this.clipboardCountdown <= 0) {
        clearInterval(tick);
        if (token === this.clipToken) {
          navigator.clipboard.writeText('').catch(() => {});
          this.say('Clipboard cleared.');
        }
      }
    }, 1000);
  }

  // --- search / list ---
  async refreshList() {
    if (!this.unlocked) {
      this.items = [];
      return;
    }
    const ids = this.query.trim() ? await this.backend.search(this.query) : await this.backend.listActive();
    this.items = ids.map((id) => this.byId.get(id)).filter((s): s is Summary => !!s);
  }
  setQuery(q: string) {
    this.query = q;
    void this.refreshList();
  }

  private async loadSummary(id: string) {
    const c: ItemContent = JSON.parse(await this.backend.getItem(id));
    const username = c.data.type === 'login' ? c.data.username : '';
    this.byId.set(id, { id, title: c.title, username, kind: c.data.type, favorite: c.favorite });
  }
  private async rebuildSummaries() {
    this.byId.clear();
    for (const id of await this.backend.listActive()) await this.loadSummary(id);
  }

  // --- sync ---
  private async syncPush() {
    const records: ItemRecord[] = JSON.parse(await this.backend.records());
    for (const rec of records) {
      const base = this.baseVersions.get(rec.id) ?? 0;
      if (rec.version === base) continue;
      try {
        const res = await api.push(rec, base);
        this.baseVersions.set(rec.id, res.new_version);
        this.cursor = Math.max(this.cursor, res.cursor);
      } catch (e) {
        if (e instanceof ApiError && e.status === 409) {
          const current = (e.body as { current: ItemRecord }).current;
          await this.backend.applyRecord(JSON.stringify(current));
          this.baseVersions.set(current.id, current.version);
          await this.loadSummary(current.id);
          await this.refreshList();
        } else {
          throw e;
        }
      }
    }
  }

  async pull() {
    if (!this.unlocked) return;
    const res = await api.pull(this.cursor);
    for (const rec of res.records) {
      await this.backend.applyRecord(JSON.stringify(rec));
      this.baseVersions.set(rec.id, rec.version);
    }
    this.cursor = res.cursor;
    await this.rebuildSummaries();
    await this.refreshList();
  }
}

export const session = new Session();
