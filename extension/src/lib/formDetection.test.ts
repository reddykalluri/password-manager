import { JSDOM } from 'jsdom';
import { beforeEach, describe, expect, it } from 'vitest';
import { detectForms } from './formDetection';

function docFrom(html: string): Document {
  return new JSDOM(`<!doctype html><html><body>${html}</body></html>`).window.document;
}

describe('form detection', () => {
  it('detects a simple login form', () => {
    const doc = docFrom(`
      <form>
        <input name="email" type="email" autocomplete="username" />
        <input name="password" type="password" autocomplete="current-password" />
      </form>`);
    const forms = detectForms(doc);
    expect(forms).toHaveLength(1);
    expect(forms[0].kind).toBe('login');
    expect(forms[0].usernameField?.getAttribute('name')).toBe('email');
    expect(forms[0].passwordFields).toHaveLength(1);
  });

  it('classifies a registration form (new + confirm password)', () => {
    const doc = docFrom(`
      <form>
        <input name="user" />
        <input name="password" type="password" autocomplete="new-password" />
        <input name="confirm" type="password" />
      </form>`);
    expect(detectForms(doc)[0].kind).toBe('register');
  });

  it('classifies a password-change form (current + new)', () => {
    const doc = docFrom(`
      <form>
        <input type="password" autocomplete="current-password" />
        <input type="password" autocomplete="new-password" />
      </form>`);
    expect(detectForms(doc)[0].kind).toBe('change');
  });

  it('detects a username-only first step (multi-step login)', () => {
    const doc = docFrom(`<form><input name="username" autocomplete="username" /></form>`);
    const f = detectForms(doc)[0];
    expect(f.kind).toBe('login');
    expect(f.passwordFields).toHaveLength(0);
    expect(f.usernameField).not.toBeNull();
  });

  it('finds a TOTP field without treating it as the username', () => {
    const doc = docFrom(`
      <form>
        <input name="user" autocomplete="username" />
        <input type="password" />
        <input name="otp" autocomplete="one-time-code" inputmode="numeric" />
      </form>`);
    const f = detectForms(doc)[0];
    expect(f.totpField?.getAttribute('name')).toBe('otp');
    expect(f.usernameField?.getAttribute('name')).toBe('user');
  });

  it('honours curated per-site selectors', () => {
    const doc = docFrom(`
      <div id="login">
        <input class="weird-user-XYZ" />
        <input class="weird-pass" type="password" />
      </div>`);
    const f = detectForms(doc, { username: '.weird-user-XYZ' })[0];
    expect(f.usernameField?.className).toBe('weird-user-XYZ');
  });
});
