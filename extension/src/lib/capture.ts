// Save/update capture decisions: dedupe by base domain + username, with
// per-site and global never-ask lists (autofill-integration spec: save and
// update capture in browsers).

import { registrableDomain } from './matching';

export interface ExistingItem {
  id: string;
  baseDomain: string;
  username: string;
  password: string;
}

export interface NeverAsk {
  global: boolean;
  domains: string[];
}

export type CaptureDecision =
  | { action: 'none'; reason: string }
  | { action: 'save'; username: string; password: string; baseDomain: string }
  | { action: 'update'; id: string; username: string; newPassword: string };

export function decideCapture(
  pageUrl: string,
  submittedUsername: string,
  submittedPassword: string,
  existing: ExistingItem[],
  neverAsk: NeverAsk = { global: false, domains: [] }
): CaptureDecision {
  if (!submittedPassword) return { action: 'none', reason: 'no password submitted' };

  const base = registrableDomain(pageUrl);
  if (!base) return { action: 'none', reason: 'unparseable origin' };

  if (neverAsk.global) return { action: 'none', reason: 'never-ask (global)' };
  if (neverAsk.domains.includes(base)) return { action: 'none', reason: 'never-ask (site)' };

  // Dedupe by base domain + username.
  const match = existing.find((e) => e.baseDomain === base && e.username === submittedUsername);
  if (match) {
    if (match.password === submittedPassword) return { action: 'none', reason: 'unchanged' };
    // Password-change: offer to update; the old password is preserved in item
    // history by the vault on update.
    return {
      action: 'update',
      id: match.id,
      username: submittedUsername,
      newPassword: submittedPassword
    };
  }
  return { action: 'save', username: submittedUsername, password: submittedPassword, baseDomain: base };
}
