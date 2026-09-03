// Shapes mirroring vault-core's serde JSON.

export interface KdfParams {
  mem_kib: number;
  iterations: number;
  parallelism: number;
}

export type UriMatch = 'base_domain' | 'host' | 'exact' | 'never';

export interface Uri {
  value: string;
  match_rule: UriMatch;
}

export interface LoginData {
  username: string;
  password: string;
  uris: Uri[];
  totp?: string | null;
}

export interface CardData {
  cardholder: string;
  number: string;
  brand: string;
  exp_month: string;
  exp_year: string;
  security_code: string;
}

export interface IdentityData {
  full_name: string;
  email: string;
  phone: string;
  address: string;
}

export interface CustomField {
  name: string;
  value: string;
  hidden: boolean;
}

// Internally-tagged: { type, ...fields }
export type ItemData =
  | ({ type: 'login' } & LoginData)
  | { type: 'secure_note' }
  | ({ type: 'card' } & CardData)
  | ({ type: 'identity' } & IdentityData);

export interface ItemContent {
  title: string;
  data: ItemData;
  notes: string;
  folder?: string | null;
  tags: string[];
  favorite: boolean;
  custom_fields: CustomField[];
  binned_at?: string | null;
}

export interface Strength {
  score: number; // 0..4
  entropy_bits: number;
  label: string;
}

export interface AuthTokens {
  account_id: string;
  device_id: string;
  access_token: string;
  refresh_token: string;
}

export interface ItemRecord {
  id: string;
  vault_id: string;
  version: number;
  modified_at: string;
  deleted: boolean;
  sealed?: unknown;
  history: unknown[];
}

export interface AuditEntry {
  event: string;
  ip: string | null;
  detail: string | null;
  created_at: string;
}

export interface DeviceView {
  id: string;
  name: string;
}

export function emptyLogin(title = ''): ItemContent {
  return {
    title,
    data: { type: 'login', username: '', password: '', uris: [], totp: null },
    notes: '',
    folder: null,
    tags: [],
    favorite: false,
    custom_fields: []
  };
}

export function newContent(kind: ItemData['type'], title = ''): ItemContent {
  let data: ItemData;
  switch (kind) {
    case 'login':
      data = { type: 'login', username: '', password: '', uris: [], totp: null };
      break;
    case 'secure_note':
      data = { type: 'secure_note' };
      break;
    case 'card':
      data = {
        type: 'card',
        cardholder: '',
        number: '',
        brand: '',
        exp_month: '',
        exp_year: '',
        security_code: ''
      };
      break;
    case 'identity':
      data = { type: 'identity', full_name: '', email: '', phone: '', address: '' };
      break;
  }
  return {
    title,
    data,
    notes: '',
    folder: null,
    tags: [],
    favorite: false,
    custom_fields: []
  };
}
