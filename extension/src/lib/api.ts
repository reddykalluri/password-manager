// Minimal server client for standalone extension operation (direct sync).

const PREFIX = '/api/v1';

export interface AuthTokens {
  account_id: string;
  device_id: string;
  access_token: string;
  refresh_token: string;
}

export class ExtApi {
  base = '';
  accessToken: string | null = null;

  private async req<T>(method: string, path: string, body?: unknown, auth = false): Promise<T> {
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
    if (!res.ok) throw new Error(json?.error ?? `http ${res.status}`);
    return json as T;
  }

  loginStart(username: string, credential_request: string) {
    return this.req<{ flow_id: string; credential_response: string }>(
      'POST',
      '/auth/login/start',
      { username, credential_request }
    );
  }
  loginFinish(body: { flow_id: string; credential_finalization: string; device_name: string; totp_code?: string }) {
    return this.req<AuthTokens | { second_factor: unknown }>('POST', '/auth/login/finish', body);
  }
  accountCrypto() {
    return this.req<unknown>('GET', '/account/crypto', undefined, true);
  }
  pull(cursor: number) {
    return this.req<{ records: Array<{ id: string; version: number }>; cursor: number }>(
      'GET',
      `/sync?cursor=${cursor}`,
      undefined,
      true
    );
  }
  push(record: unknown, base_version: number) {
    return this.req<{ new_version: number; cursor: number }>('POST', '/sync/push', {
      record,
      base_version
    }, true);
  }
}
