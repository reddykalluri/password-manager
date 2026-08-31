// Thin client for the vault-server API. Access tokens are held in memory only
// (never localStorage), so a hard reload requires re-unlocking (spec: session
// state does not survive a hard reload).

import type { AuditEntry, AuthTokens, DeviceView, ItemRecord } from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public body: unknown
  ) {
    super(`${status} ${code}`);
  }
}

const PREFIX = '/api/v1';

class Api {
  /** Same-origin by default (served by the instance); configurable for dev. */
  base = '';
  accessToken: string | null = null;
  refreshToken: string | null = null;

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = false
  ): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth && this.accessToken) headers['authorization'] = `Bearer ${this.accessToken}`;
    const res = await fetch(`${this.base}${PREFIX}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : null;
    if (!res.ok) {
      throw new ApiError(res.status, json?.error ?? 'error', json);
    }
    return json as T;
  }

  setTokens(t: AuthTokens) {
    this.accessToken = t.access_token;
    this.refreshToken = t.refresh_token;
  }

  clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
  }

  // --- auth ---
  registerStart(username: string, registration_request: string) {
    return this.request<{ registration_response: string }>(
      'POST',
      '/auth/register/start',
      { username, registration_request }
    );
  }
  registerFinish(body: {
    username: string;
    registration_upload: string;
    account_crypto: unknown;
    invite_code?: string;
    device_name: string;
  }) {
    return this.request<AuthTokens>('POST', '/auth/register/finish', body);
  }
  loginStart(username: string, credential_request: string) {
    return this.request<{ flow_id: string; credential_response: string }>(
      'POST',
      '/auth/login/start',
      { username, credential_request }
    );
  }
  loginFinish(body: {
    flow_id: string;
    credential_finalization: string;
    device_name: string;
    totp_code?: string;
  }) {
    return this.request<AuthTokens | { second_factor: SecondFactorChallenge }>(
      'POST',
      '/auth/login/finish',
      body
    );
  }
  loginWebauthnFinish(body: {
    webauthn_flow_id: string;
    credential: unknown;
    device_name: string;
  }) {
    return this.request<AuthTokens>('POST', '/auth/login/webauthn/finish', body);
  }

  // --- vault / sync ---
  accountCrypto() {
    return this.request<unknown>('GET', '/account/crypto', undefined, true);
  }
  updateAccountCrypto(account_crypto: unknown, extra: { totp_code?: string; stepup_token?: string } = {}) {
    return this.request<{ status: string }>(
      'PUT',
      '/account/crypto',
      { account_crypto, ...extra },
      true
    );
  }
  pull(cursor: number) {
    return this.request<{ records: ItemRecord[]; cursor: number }>(
      'GET',
      `/sync?cursor=${cursor}`,
      undefined,
      true
    );
  }
  push(record: ItemRecord, base_version: number) {
    return this.request<{ new_version: number; cursor: number }>(
      'POST',
      '/sync/push',
      { record, base_version },
      true
    );
  }

  // --- account ---
  activity() {
    return this.request<AuditEntry[]>('GET', '/account/activity', undefined, true);
  }
  devices() {
    return this.request<DeviceView[]>('GET', '/account/devices', undefined, true);
  }
  enrollTotp(secret: string, code: string) {
    return this.request<{ status: string }>('POST', '/account/2fa/totp', { secret, code }, true);
  }
}

export interface SecondFactorChallenge {
  webauthn_flow_id: string;
  webauthn_challenge: unknown;
}

export const api = new Api();

export function isTokens(x: unknown): x is AuthTokens {
  return !!x && typeof x === 'object' && 'access_token' in x;
}
