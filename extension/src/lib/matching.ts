// Domain matching (Public Suffix List via tldts) and phishing-resistance
// checks (autofill-integration spec: domain matching and phishing resistance).

import { getDomain } from 'tldts';

export type UriMatch = 'base_domain' | 'host' | 'exact' | 'never';

export interface StoredUri {
  value: string;
  match_rule: UriMatch;
}

/** Registrable (base) domain via the PSL, e.g. app.example.co.uk → example.co.uk. */
export function registrableDomain(input: string): string | null {
  return getDomain(input) ?? null;
}

/** Lowercased hostname, tolerating a missing scheme. */
export function hostOf(input: string): string | null {
  const withScheme = input.includes('://') ? input : `https://${input}`;
  try {
    return new URL(withScheme).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function normalize(url: string): string {
  return url.trim().replace(/\/+$/, '').toLowerCase();
}

/** Whether a stored URI matches the page URL under its match rule. */
export function uriMatches(uri: StoredUri, pageUrl: string): boolean {
  switch (uri.match_rule) {
    case 'never':
      return false;
    case 'exact':
      return normalize(uri.value) === normalize(pageUrl);
    case 'host': {
      const a = hostOf(uri.value);
      const b = hostOf(pageUrl);
      return !!a && a === b;
    }
    case 'base_domain':
    default: {
      const a = registrableDomain(uri.value);
      const b = registrableDomain(pageUrl);
      return !!a && a === b;
    }
  }
}

export function itemMatches(uris: StoredUri[], pageUrl: string): boolean {
  return uris.some((u) => uriMatches(u, pageUrl));
}

// --- phishing resistance ---------------------------------------------------

// Visual confusables collapsed to a canonical skeleton for lookalike detection.
const CONFUSABLES: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '6': 'b',
  '7': 't',
  '8': 'b',
  '9': 'g',
  $: 's',
  '@': 'a',
  '|': 'l',
  '!': 'i'
};

export function skeleton(s: string): string {
  return s
    .toLowerCase()
    .split('')
    .map((c) => CONFUSABLES[c] ?? c)
    .join('')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

/** Optimal string alignment distance (Damerau-Levenshtein with adjacent
 * transpositions as a single edit — the common typosquat case). */
export function levenshtein(a: string, b: string): number {
  const da = a.length;
  const db = b.length;
  const dp = Array.from({ length: da + 1 }, () => new Array<number>(db + 1).fill(0));
  for (let i = 0; i <= da; i++) dp[i][0] = i;
  for (let j = 0; j <= db; j++) dp[0][j] = j;
  for (let i = 1; i <= da; i++) {
    for (let j = 1; j <= db; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[da][db];
}

export interface PhishingAssessment {
  risky: boolean;
  reason?: string;
}

/**
 * Assess whether offering credentials to `pageUrl` is risky given the domains
 * the user actually has items for. A matching origin is safe; a non-matching but
 * visually-similar (typosquat/homograph/punycode) origin is flagged.
 */
export function assessOrigin(pageUrl: string, knownItemUris: StoredUri[]): PhishingAssessment {
  const pageDomain = registrableDomain(pageUrl);
  if (!pageDomain) return { risky: true, reason: 'unparseable origin' };

  const host = hostOf(pageUrl) ?? '';
  if (host.split('.').some((label) => label.startsWith('xn--'))) {
    return { risky: true, reason: 'internationalised (punycode) domain — possible homograph' };
  }

  if (itemMatches(knownItemUris, pageUrl)) return { risky: false };

  const pageSkel = skeleton(pageDomain);
  for (const uri of knownItemUris) {
    const known = registrableDomain(uri.value);
    if (!known || known === pageDomain) continue;
    if (skeleton(known) === pageSkel || levenshtein(known, pageDomain) <= 1) {
      return { risky: true, reason: `looks like ${known}` };
    }
  }
  return { risky: false };
}
