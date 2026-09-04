// Curated per-site form-detection overrides, keyed by registrable domain.
// Shipped as data (not code) so it can be updated out-of-band without a new
// extension release (autofill-integration spec: heuristics + updatable rules).

import type { CuratedRule } from './formDetection';

export const CURATED_RULES: Record<string, CuratedRule> = {
  // Example of an override for a site heuristics get wrong:
  // 'example.com': { username: '#login-user', password: '#login-pass' }
};

export function ruleForDomain(domain: string | null): CuratedRule | undefined {
  return domain ? CURATED_RULES[domain] : undefined;
}

/** Merge a fetched rule-set update over the built-in defaults. */
export function applyRuleUpdate(update: Record<string, CuratedRule>): void {
  Object.assign(CURATED_RULES, update);
}
