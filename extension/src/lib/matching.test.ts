import { describe, expect, it } from 'vitest';
import {
  assessOrigin,
  itemMatches,
  registrableDomain,
  skeleton,
  uriMatches,
  type StoredUri
} from './matching';

describe('PSL domain matching', () => {
  it('computes registrable domain via the PSL', () => {
    expect(registrableDomain('https://app.example.com/login')).toBe('example.com');
    expect(registrableDomain('https://foo.bar.co.uk/x')).toBe('bar.co.uk');
  });

  it('matches by base domain, host, exact, never', () => {
    const u = (value: string, match_rule: StoredUri['match_rule']) => ({ value, match_rule });
    expect(uriMatches(u('example.com', 'base_domain'), 'https://app.example.com/x')).toBe(true);
    expect(uriMatches(u('app.example.com', 'host'), 'https://www.example.com')).toBe(false);
    expect(uriMatches(u('https://x.example.com/a', 'exact'), 'https://x.example.com/a/')).toBe(true);
    expect(uriMatches(u('example.com', 'never'), 'https://example.com')).toBe(false);
  });
});

describe('phishing resistance (hostile-page suite)', () => {
  const items: StoredUri[] = [{ value: 'https://example.com', match_rule: 'base_domain' }];

  it('offers on the legitimate origin', () => {
    expect(itemMatches(items, 'https://example.com/login')).toBe(true);
    expect(assessOrigin('https://example.com/login', items).risky).toBe(false);
    expect(assessOrigin('https://accounts.example.com', items).risky).toBe(false);
  });

  it('flags a digit-for-letter typosquat (examp1e.com)', () => {
    expect(itemMatches(items, 'https://examp1e.com/login')).toBe(false);
    const a = assessOrigin('https://examp1e.com/login', items);
    expect(a.risky).toBe(true);
    expect(a.reason).toContain('example.com');
  });

  it('flags a one-edit typosquat (exampel.com)', () => {
    expect(assessOrigin('https://exampel.com', items).risky).toBe(true);
  });

  it('flags a punycode/IDN homograph', () => {
    // exаmple.com with a Cyrillic "а" encodes to an xn-- label.
    expect(assessOrigin('https://xn--exmple-4nf.com', items).risky).toBe(true);
  });

  it('does not falsely flag an unrelated domain, and never matches it', () => {
    const a = assessOrigin('https://totally-different.org', items);
    expect(a.risky).toBe(false);
    expect(itemMatches(items, 'https://totally-different.org')).toBe(false);
  });

  it('does not treat a subdomain-embedding lookalike as a match', () => {
    // example.com.evil.com registrable domain is evil.com.
    expect(itemMatches(items, 'https://example.com.evil.com/login')).toBe(false);
  });

  it('skeleton collapses common confusables', () => {
    expect(skeleton('examp1e')).toBe('example');
    expect(skeleton('rnicrosoft')).toBe('microsoft');
  });
});
