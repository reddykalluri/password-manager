import { describe, expect, it } from 'vitest';
import { decideCapture, type ExistingItem } from './capture';

const items: ExistingItem[] = [
  { id: 'a', baseDomain: 'example.com', username: 'alice', password: 'old-pass' }
];

describe('capture decisions', () => {
  it('offers to save a brand-new credential', () => {
    const d = decideCapture('https://example.com/login', 'bob', 'newpw', items);
    expect(d).toEqual({ action: 'save', username: 'bob', password: 'newpw', baseDomain: 'example.com' });
  });

  it('offers to update when the password changed for a known username', () => {
    const d = decideCapture('https://app.example.com/settings', 'alice', 'changed', items);
    expect(d).toMatchObject({ action: 'update', id: 'a', newPassword: 'changed' });
  });

  it('does nothing when nothing changed', () => {
    const d = decideCapture('https://example.com', 'alice', 'old-pass', items);
    expect(d.action).toBe('none');
  });

  it('respects the per-site never-ask list', () => {
    const d = decideCapture('https://example.com', 'x', 'y', items, {
      global: false,
      domains: ['example.com']
    });
    expect(d).toEqual({ action: 'none', reason: 'never-ask (site)' });
  });

  it('respects the global never-ask flag', () => {
    const d = decideCapture('https://other.com', 'x', 'y', items, { global: true, domains: [] });
    expect(d).toEqual({ action: 'none', reason: 'never-ask (global)' });
  });

  it('dedupes by base domain, not host', () => {
    // Same registrable domain, different host → still a match for update.
    const d = decideCapture('https://login.example.com', 'alice', 'changed', items);
    expect(d.action).toBe('update');
  });
});
