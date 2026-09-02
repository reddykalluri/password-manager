// Vault backend abstraction: the same UI runs on WASM crypto in a browser and
// on native vault-core (via Tauri `invoke`) in the desktop app.

/** Whether we are running inside the Tauri desktop shell. */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export interface EnrollResult {
  recoveryCode: string | null;
  accountCrypto: string; // JSON
}

/** All vault operations the session layer needs, uniformly async. */
export interface VaultBackend {
  benchmarkKdf(targetMs: number): Promise<string>;
  defaultKdfParams(): Promise<string>;
  generatePassword(optsJson: string): Promise<string>;
  generatePassphrase(optsJson: string): Promise<string>;
  rateStrength(pw: string): Promise<string>;

  opaqueRegisterStart(pw: string): Promise<string>;
  opaqueRegisterFinish(state: string, pw: string, resp: string): Promise<string>;
  opaqueLoginStart(pw: string): Promise<string>;
  opaqueLoginFinish(state: string, pw: string, resp: string): Promise<string>;

  enroll(pw: string, paramsJson: string): Promise<EnrollResult>;
  unlock(pw: string, cryptoJson: string, recordsJson: string): Promise<void>;
  unlockWithRecovery(code: string, cryptoJson: string, recordsJson: string): Promise<void>;
  lock(): Promise<void>;
  accountCrypto(): Promise<string>;
  records(): Promise<string>;
  applyRecord(json: string): Promise<void>;

  createItem(json: string): Promise<string>;
  getItem(id: string): Promise<string>;
  updateItem(id: string, json: string): Promise<void>;
  moveToBin(id: string): Promise<void>;
  restoreFromBin(id: string): Promise<void>;
  deletePermanent(id: string): Promise<void>;

  listActive(): Promise<string[]>;
  listBin(): Promise<string[]>;
  search(q: string): Promise<string[]>;
  candidatesFor(url: string): Promise<string[]>;
  folders(): Promise<string[]>;
  tags(): Promise<string[]>;

  history(id: string): Promise<string>;
  restoreRevision(id: string, index: number): Promise<void>;

  changeMasterPassword(cur: string, next: string, paramsJson: string): Promise<string>;
  regenerateRecoveryCode(pw: string): Promise<string>;

  importPreview(kind: string, data: string): Promise<string>;
  importCommit(itemsJson: string): Promise<number>;
  exportEncrypted(pw: string): Promise<string>;
  exportCsvGated(pw: string): Promise<string>;

  setLockTimeoutSecs(secs: number): Promise<void>;
  touch(): Promise<void>;
  shouldLock(): Promise<boolean>;

  /** Whether a vault is currently unlocked in this backend (native state is
   * shared across desktop windows). */
  unlocked(): Promise<boolean>;
}

/** WASM backend for the browser: wraps the vault-core WASM module. */
class WasmBackend implements VaultBackend {
  private wasm: Awaited<ReturnType<typeof import('./wasm').loadWasm>> | null = null;
  private vault: import('./wasm').WasmVault | null = null;

  private async w() {
    if (!this.wasm) this.wasm = await import('./wasm').then((m) => m.loadWasm());
    return this.wasm!;
  }
  private v() {
    if (!this.vault) throw new Error('vault is locked');
    return this.vault;
  }

  async benchmarkKdf(t: number) {
    return (await this.w()).benchmarkKdf(t);
  }
  async defaultKdfParams() {
    return (await this.w()).defaultKdfParams();
  }
  async generatePassword(o: string) {
    return (await this.w()).generatePassword(o);
  }
  async generatePassphrase(o: string) {
    return (await this.w()).generatePassphrase(o);
  }
  async rateStrength(pw: string) {
    return (await this.w()).rateStrength(pw);
  }
  async opaqueRegisterStart(pw: string) {
    return (await this.w()).opaqueRegisterStart(pw);
  }
  async opaqueRegisterFinish(s: string, pw: string, r: string) {
    return (await this.w()).opaqueRegisterFinish(s, pw, r);
  }
  async opaqueLoginStart(pw: string) {
    return (await this.w()).opaqueLoginStart(pw);
  }
  async opaqueLoginFinish(s: string, pw: string, r: string) {
    return (await this.w()).opaqueLoginFinish(s, pw, r);
  }
  async enroll(pw: string, params: string) {
    const w = await this.w();
    this.vault = w.WasmVault.enroll(pw, params);
    return { recoveryCode: this.vault.takeRecoveryCode() ?? null, accountCrypto: this.vault.accountCrypto() };
  }
  async unlock(pw: string, crypto: string, records: string) {
    const w = await this.w();
    this.vault = w.WasmVault.unlock(pw, crypto, records);
  }
  async unlockWithRecovery(code: string, crypto: string, records: string) {
    const w = await this.w();
    this.vault = w.WasmVault.unlockWithRecovery(code, crypto, records);
  }
  async lock() {
    this.vault?.free();
    this.vault = null;
  }
  async accountCrypto() {
    return this.v().accountCrypto();
  }
  async records() {
    return this.v().records();
  }
  async applyRecord(json: string) {
    this.v().applyRecord(json);
  }
  async createItem(json: string) {
    return this.v().createItem(json);
  }
  async getItem(id: string) {
    return this.v().getItem(id);
  }
  async updateItem(id: string, json: string) {
    this.v().updateItem(id, json);
  }
  async moveToBin(id: string) {
    this.v().moveToBin(id);
  }
  async restoreFromBin(id: string) {
    this.v().restoreFromBin(id);
  }
  async deletePermanent(id: string) {
    this.v().deletePermanent(id);
  }
  async listActive() {
    return this.v().listActive();
  }
  async listBin() {
    return this.v().listBin();
  }
  async search(q: string) {
    return this.v().search(q);
  }
  async candidatesFor(url: string) {
    return this.v().candidatesFor(url);
  }
  async folders() {
    return this.v().folders();
  }
  async tags() {
    return this.v().tags();
  }
  async history(id: string) {
    return this.v().history(id);
  }
  async restoreRevision(id: string, i: number) {
    this.v().restoreRevision(id, i);
  }
  async changeMasterPassword(c: string, n: string, p: string) {
    return this.v().changeMasterPassword(c, n, p);
  }
  async regenerateRecoveryCode(pw: string) {
    return this.v().regenerateRecoveryCode(pw);
  }
  async importPreview(kind: string, data: string) {
    return this.v().importPreview(kind, data);
  }
  async importCommit(json: string) {
    return this.v().importCommit(json);
  }
  async exportEncrypted(pw: string) {
    return this.v().exportEncrypted(pw);
  }
  async exportCsvGated(pw: string) {
    return this.v().exportCsvGated(pw);
  }
  async setLockTimeoutSecs(secs: number) {
    this.v().setLockTimeoutSecs(BigInt(secs));
  }
  async touch() {
    this.vault?.touch();
  }
  async shouldLock() {
    return this.vault?.shouldLock() ?? false;
  }
  async unlocked() {
    return this.vault !== null;
  }
}

/** Native backend for the desktop: proxies to native vault-core via Tauri. */
class TauriBackend implements VaultBackend {
  private async invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  }
  benchmarkKdf(t: number) {
    return this.invoke<string>('kdf_benchmark', { target_ms: t });
  }
  defaultKdfParams() {
    return this.invoke<string>('default_kdf_params');
  }
  generatePassword(o: string) {
    return this.invoke<string>('gen_password', { options_json: o });
  }
  generatePassphrase(o: string) {
    return this.invoke<string>('gen_passphrase', { options_json: o });
  }
  rateStrength(pw: string) {
    return this.invoke<string>('strength', { password: pw });
  }
  opaqueRegisterStart(pw: string) {
    return this.invoke<string>('opaque_register_start', { password: pw });
  }
  opaqueRegisterFinish(s: string, pw: string, r: string) {
    return this.invoke<string>('opaque_register_finish', { state_b64: s, password: pw, response_b64: r });
  }
  opaqueLoginStart(pw: string) {
    return this.invoke<string>('opaque_login_start', { password: pw });
  }
  opaqueLoginFinish(s: string, pw: string, r: string) {
    return this.invoke<string>('opaque_login_finish', { state_b64: s, password: pw, response_b64: r });
  }
  async enroll(pw: string, params: string) {
    const res = await this.invoke<{ recovery_code: string; account_crypto: unknown }>('vault_enroll', {
      password: pw,
      params_json: params
    });
    return { recoveryCode: res.recovery_code, accountCrypto: JSON.stringify(res.account_crypto) };
  }
  unlock(pw: string, crypto: string, records: string) {
    return this.invoke<void>('vault_unlock', { password: pw, crypto_json: crypto, records_json: records });
  }
  unlockWithRecovery(code: string, crypto: string, records: string) {
    return this.invoke<void>('vault_unlock_recovery', {
      recovery_code: code,
      crypto_json: crypto,
      records_json: records
    });
  }
  lock() {
    return this.invoke<void>('vault_lock');
  }
  accountCrypto() {
    return this.invoke<string>('account_crypto');
  }
  records() {
    return this.invoke<string>('records');
  }
  applyRecord(json: string) {
    return this.invoke<void>('apply_record', { record_json: json });
  }
  createItem(json: string) {
    return this.invoke<string>('create_item', { content_json: json });
  }
  getItem(id: string) {
    return this.invoke<string>('get_item', { id });
  }
  updateItem(id: string, json: string) {
    return this.invoke<void>('update_item', { id, content_json: json });
  }
  moveToBin(id: string) {
    return this.invoke<void>('move_to_bin', { id });
  }
  restoreFromBin(id: string) {
    return this.invoke<void>('restore_from_bin', { id });
  }
  deletePermanent(id: string) {
    return this.invoke<void>('delete_permanent', { id });
  }
  listActive() {
    return this.invoke<string[]>('list_active');
  }
  listBin() {
    return this.invoke<string[]>('list_bin');
  }
  search(q: string) {
    return this.invoke<string[]>('search', { query: q });
  }
  candidatesFor(url: string) {
    return this.invoke<string[]>('candidates_for', { url });
  }
  folders() {
    return this.invoke<string[]>('folders');
  }
  tags() {
    return this.invoke<string[]>('tags');
  }
  history(id: string) {
    return this.invoke<string>('history', { id });
  }
  restoreRevision(id: string, i: number) {
    return this.invoke<void>('restore_revision', { id, index: i });
  }
  changeMasterPassword(c: string, n: string, p: string) {
    return this.invoke<string>('change_master_password', { current: c, next: n, params_json: p });
  }
  regenerateRecoveryCode(pw: string) {
    return this.invoke<string>('regenerate_recovery_code', { password: pw });
  }
  importPreview(kind: string, data: string) {
    return this.invoke<string>('import_preview', { kind, data });
  }
  importCommit(json: string) {
    return this.invoke<number>('import_commit', { items_json: json });
  }
  exportEncrypted(pw: string) {
    return this.invoke<string>('export_encrypted', { export_password: pw });
  }
  exportCsvGated(pw: string) {
    return this.invoke<string>('export_csv_gated', { master_password: pw });
  }
  setLockTimeoutSecs(secs: number) {
    return this.invoke<void>('set_lock_timeout_secs', { secs });
  }
  touch() {
    return this.invoke<void>('touch');
  }
  shouldLock() {
    return this.invoke<boolean>('should_lock');
  }
  unlocked() {
    return this.invoke<boolean>('vault_unlocked');
  }
}

export function createBackend(): VaultBackend {
  return isTauri() ? new TauriBackend() : new WasmBackend();
}
