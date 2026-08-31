// Central session state: auth flows, sync, auto-lock, and clipboard hygiene.
// Uses Svelte 5 runes; imported as a singleton across the app.

import { api, ApiError, isTokens, type SecondFactorChallenge } from './api';
import { loadWasm, type WasmVault } from './wasm';
import type { ItemContent, ItemRecord, KdfParams } from './types';
import { doWebauthnAssertion } from './webauthn';

export interface Summary {
  id: string;
  title: string;
  username: string;
  kind: string;
  favorite: boolean;
}

type Wasm = Awaited<ReturnType<typeof loadWasm>>;

class Session {
  ready = $state(false);
  unlocked = $state(false);
  items = $state<Summary[]>([]);
  query = $state('');
  announce = $state(''); // polite live-region text
  error = $state<string | null>(null);
  recoveryCode = $state<string | null>(null);
  lockTimeoutSecs = $state(300);
  clipboardClearSecs = $state(60);
  clipboardCountdown = $state(0);

  private wasm: Wasm | null = null;
  private vault: WasmVault | null = null;
  private cursor = 0;
  private baseVersions = new Map<string, number>();
  private byId = new Map<string, Summary>();
  private deviceName = 'Web browser';
  private lockInterval: ReturnType<typeof setInterval> | null = null;
  private clipToken = 0;

  async init() {
    this.wasm = await loadWasm();
    this.ready = true;
  }

  private w(): Wasm {
    if (!this.wasm) throw new Error('WASM not initialised');
    return this.wasm;
  }
  private v() {
    if (!this.vault) throw new Error('vault is locked');
    return this.vault;
  }

  say(msg: string) {
    this.announce = '';
    // Force the live region to re-announce identical messages.
    queueMicrotask(() => (this.announce = msg));
  }

  // --- KDF params ---
  async negotiateParams(targetMs = 500): Promise<string> {
    try {
      return await this.w().benchmarkKdf(targetMs);
    } catch {
      return await this.w().defaultKdfParams();
    }
  }

  // --- enrolment ---
  async enroll(opts: {
    username: string;
    password: string;
    inviteCode?: string;
    paramsJson: string;
  }) {
    const w = this.w();
    const vault = w.WasmVault.enroll(opts.password, opts.paramsJson);
    const accountCrypto = JSON.parse(vault.accountCrypto());
    const recovery = vault.takeRecoveryCode() ?? null;

    // OPAQUE registration.
    const rs = JSON.parse(w.opaqueRegisterStart(opts.password));
    const { registration_response } = await api.registerStart(opts.username, rs.message);
    const upload = w.opaqueRegisterFinish(rs.state, opts.password, registration_response);
    const tokens = await api.registerFinish({
      username: opts.username,
      registration_upload: upload,
      account_crypto: accountCrypto,
      invite_code: opts.inviteCode || undefined,
      device_name: this.deviceName
    });
    api.setTokens(tokens);

    this.vault = vault;
    this.recoveryCode = recovery;
    await this.afterUnlock();
  }

  // --- unlock / login ---
  async unlock(opts: { username: string; password: string; totpCode?: string }) {
    const w = this.w();
    // OPAQUE login round trip.
    const ls = JSON.parse(w.opaqueLoginStart(opts.password));
    const start = await api.loginStart(opts.username, ls.message);
    const finalization = w.opaqueLoginFinish(ls.state, opts.password, start.credential_response);

    let outcome = await api.loginFinish({
      flow_id: start.flow_id,
      credential_finalization: finalization,
      device_name: this.deviceName,
      totp_code: opts.totpCode
    });

    // WebAuthn second factor.
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

    // Pull crypto material + records, then unlock the vault in WASM.
    const crypto = await api.accountCrypto();
    const pulled = await api.pull(0);
    this.cursor = pulled.cursor;
    const vault = w.WasmVault.unlock(
      opts.password,
      JSON.stringify(crypto),
      JSON.stringify(pulled.records)
    );
    this.vault = vault;
    for (const r of pulled.records) this.baseVersions.set(r.id, r.version);
    await this.afterUnlock();
  }

  private async afterUnlock() {
    this.unlocked = true;
    this.error = null;
    this.v().setLockTimeoutSecs(BigInt(this.lockTimeoutSecs));
    this.rebuildSummaries();
    this.startLockWatch();
    this.say('Vault unlocked.');
  }

  lock() {
    this.stopLockWatch();
    if (this.vault) {
      this.vault.free(); // zeroises keys
      this.vault = null;
    }
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
    this.vault?.touch();
  }

  private startLockWatch() {
    this.stopLockWatch();
    this.lockInterval = setInterval(() => {
      if (this.vault?.shouldLock()) {
        this.lock();
        this.say('Vault auto-locked after inactivity.');
      }
    }, 5000);
  }
  private stopLockWatch() {
    if (this.lockInterval) clearInterval(this.lockInterval);
    this.lockInterval = null;
  }

  setLockTimeout(secs: number) {
    this.lockTimeoutSecs = secs;
    this.vault?.setLockTimeoutSecs(BigInt(secs));
  }

  // --- item model ---
  getItem(id: string): ItemContent {
    return JSON.parse(this.v().getItem(id));
  }

  async createItem(content: ItemContent): Promise<string> {
    const id = this.v().createItem(JSON.stringify(content));
    this.loadSummary(id);
    this.refreshList();
    await this.syncPush();
    this.say(`Created ${content.title}.`);
    return id;
  }

  async updateItem(id: string, content: ItemContent) {
    this.v().updateItem(id, JSON.stringify(content));
    if (content.binned_at) this.byId.delete(id);
    else this.loadSummary(id);
    this.refreshList();
    await this.syncPush();
    this.say(`Saved ${content.title}.`);
  }

  async moveToBin(id: string) {
    this.v().moveToBin(id);
    this.byId.delete(id);
    this.refreshList();
    await this.syncPush();
    this.say('Moved to bin.');
  }

  async restoreFromBin(id: string) {
    this.v().restoreFromBin(id);
    this.loadSummary(id);
    this.refreshList();
    await this.syncPush();
  }

  history(id: string): Array<{ modified_at: string; content: ItemContent }> {
    return JSON.parse(this.v().history(id));
  }
  async restoreRevision(id: string, index: number) {
    this.v().restoreRevision(id, index);
    this.loadSummary(id);
    this.refreshList();
    await this.syncPush();
    this.say('Revision restored.');
  }

  // --- generator ---
  generatePassword(opts: unknown): string {
    return this.w().generatePassword(JSON.stringify(opts));
  }
  generatePassphrase(opts: unknown): string {
    return this.w().generatePassphrase(JSON.stringify(opts));
  }
  rateStrength(pw: string): { score: number; entropy_bits: number; label: string } {
    return JSON.parse(this.w().rateStrength(pw));
  }

  // --- import / export ---
  importPreview(kind: string, data: string) {
    return JSON.parse(this.v().importPreview(kind, data));
  }
  async importCommit(items: ItemContent[]): Promise<number> {
    const n = this.v().importCommit(JSON.stringify(items));
    this.rebuildSummaries();
    this.refreshList();
    await this.syncPush();
    this.say(`Imported ${n} item(s).`);
    return n;
  }
  exportEncrypted(password: string): string {
    return this.v().exportEncrypted(password);
  }
  exportCsvGated(password: string): string {
    return this.v().exportCsvGated(password);
  }

  // --- account security ---
  async changeMasterPassword(current: string, next: string, extra: { totp_code?: string } = {}) {
    const paramsJson = await this.negotiateParams();
    const updated = this.v().changeMasterPassword(current, next, paramsJson);
    await api.updateAccountCrypto(JSON.parse(updated), extra);
    this.say('Master password changed.');
  }
  regenerateRecoveryCode(password: string): string {
    const code = this.v().regenerateRecoveryCode(password);
    this.recoveryCode = code;
    return code;
  }
  async uploadCryptoAfterRecoveryRegen(extra: { totp_code?: string } = {}) {
    await api.updateAccountCrypto(JSON.parse(this.v().accountCrypto()), extra);
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
  refreshList() {
    if (!this.vault) {
      this.items = [];
      return;
    }
    const ids = this.query.trim() ? this.vault.search(this.query) : this.vault.listActive();
    this.items = ids.map((id) => this.byId.get(id)).filter((s): s is Summary => !!s);
  }
  setQuery(q: string) {
    this.query = q;
    this.refreshList();
  }

  private loadSummary(id: string) {
    const c: ItemContent = JSON.parse(this.v().getItem(id));
    const username = c.data.type === 'login' ? c.data.username : '';
    this.byId.set(id, {
      id,
      title: c.title,
      username,
      kind: c.data.type,
      favorite: c.favorite
    });
  }
  private rebuildSummaries() {
    this.byId.clear();
    for (const id of this.v().listActive()) this.loadSummary(id);
  }

  // --- sync ---
  private async syncPush() {
    const records: ItemRecord[] = JSON.parse(this.v().records());
    for (const rec of records) {
      const base = this.baseVersions.get(rec.id) ?? 0;
      if (rec.version === base) continue; // unchanged since last sync
      try {
        const res = await api.push(rec, base);
        this.baseVersions.set(rec.id, res.new_version);
        this.cursor = Math.max(this.cursor, res.cursor);
      } catch (e) {
        if (e instanceof ApiError && e.status === 409) {
          const current = (e.body as { current: ItemRecord }).current;
          this.v().applyRecord(JSON.stringify(current)); // server wins
          this.baseVersions.set(current.id, current.version);
          this.loadSummary(current.id);
          this.refreshList();
        } else {
          throw e;
        }
      }
    }
  }

  async pull() {
    if (!this.vault) return;
    const res = await api.pull(this.cursor);
    for (const rec of res.records) {
      this.v().applyRecord(JSON.stringify(rec));
      this.baseVersions.set(rec.id, rec.version);
    }
    this.cursor = res.cursor;
    this.rebuildSummaries();
    this.refreshList();
  }
}

export const session = new Session();
export type { KdfParams };
