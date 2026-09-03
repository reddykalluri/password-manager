// Message contracts between the popup/content scripts and the background worker.

export interface Credential {
  username: string;
  password: string;
  totp?: string | null;
}

export interface Candidate {
  id: string;
  title: string;
  username: string;
}

export type ExtRequest =
  | { type: 'GET_STATE' }
  | { type: 'UNLOCK'; instanceUrl: string; username: string; password: string; totp?: string }
  | { type: 'LOCK' }
  | { type: 'CANDIDATES'; url: string }
  | { type: 'SEARCH'; query: string }
  | { type: 'FILL'; id: string }
  | { type: 'GENERATE'; kind: 'password' | 'passphrase'; opts: unknown }
  | { type: 'SAVE'; baseDomain: string; url: string; username: string; password: string }
  | { type: 'UPDATE'; id: string; newPassword: string }
  | { type: 'CAPTURE'; url: string; username: string; password: string }
  | { type: 'GET_PENDING' }
  | { type: 'CLEAR_PENDING' };

export interface State {
  unlocked: boolean;
  delegatedToDesktop: boolean;
}

export type ExtResponse =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

export function ok(data: unknown): ExtResponse {
  return { ok: true, data };
}
export function fail(error: string): ExtResponse {
  return { ok: false, error };
}
