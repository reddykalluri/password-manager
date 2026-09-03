// Login/registration/change form detection: heuristics plus optional per-site
// curated overrides (autofill-integration spec: in-browser form fill).

export type FormKind = 'login' | 'register' | 'change' | 'unknown';

export interface DetectedForm {
  kind: FormKind;
  usernameField: HTMLInputElement | null;
  passwordFields: HTMLInputElement[];
  totpField: HTMLInputElement | null;
  scope: Element;
}

/** Per-domain selector overrides for sites heuristics get wrong. */
export interface CuratedRule {
  username?: string;
  password?: string;
  totp?: string;
}

function attr(el: Element, name: string): string {
  return (el.getAttribute(name) ?? '').toLowerCase();
}

function matches(el: Element, re: RegExp): boolean {
  return re.test(attr(el, 'name')) || re.test(attr(el, 'id')) || re.test(attr(el, 'autocomplete'));
}

const USERNAME_RE = /user|email|login|account|identifier|phone/i;
const TOTP_RE = /otp|totp|mfa|2fa|onetime|one-time|auth.?code|security.?code|\bcode\b/i;

function textInputs(scope: Element): HTMLInputElement[] {
  return Array.from(scope.querySelectorAll('input')).filter((el) => {
    const t = (el.getAttribute('type') ?? 'text').toLowerCase();
    return ['text', 'email', 'tel', 'number', ''].includes(t) || !el.hasAttribute('type');
  }) as HTMLInputElement[];
}

function analyzeScope(scope: Element, rule?: CuratedRule): DetectedForm | null {
  const passwordFields = Array.from(
    scope.querySelectorAll('input[type="password"]')
  ) as HTMLInputElement[];

  // Curated overrides take precedence when present.
  const curatedUser = rule?.username
    ? (scope.querySelector(rule.username) as HTMLInputElement | null)
    : null;
  const curatedTotp = rule?.totp
    ? (scope.querySelector(rule.totp) as HTMLInputElement | null)
    : null;

  const texts = textInputs(scope);

  let usernameField =
    curatedUser ??
    texts.find((el) => attr(el, 'autocomplete') === 'username') ??
    texts.find((el) => (el.getAttribute('type') ?? '') === 'email') ??
    texts.find((el) => matches(el, USERNAME_RE)) ??
    null;

  const totpField =
    curatedTotp ??
    texts.find((el) => attr(el, 'autocomplete') === 'one-time-code') ??
    texts.find((el) => matches(el, TOTP_RE)) ??
    null;
  // A TOTP field should not double as the username field.
  if (usernameField && usernameField === totpField) usernameField = null;

  if (passwordFields.length === 0 && !usernameField) return null;

  const kind = classify(usernameField, passwordFields);
  return { kind, usernameField, passwordFields, totpField, scope };
}

function classify(username: HTMLInputElement | null, passwords: HTMLInputElement[]): FormKind {
  if (passwords.length === 0) {
    // Username-only page: the first step of a multi-step login.
    return username ? 'login' : 'unknown';
  }
  const hasNew = passwords.some(
    (p) => attr(p, 'autocomplete') === 'new-password' || matches(p, /new|confirm|retype|repeat/i)
  );
  const hasCurrent = passwords.some((p) => attr(p, 'autocomplete') === 'current-password');
  if (passwords.length >= 2 || hasNew) {
    return hasCurrent ? 'change' : 'register';
  }
  return 'login';
}

/** Detect all candidate forms in a document (or a single scope). */
export function detectForms(doc: Document, rule?: CuratedRule): DetectedForm[] {
  const formEls = Array.from(doc.querySelectorAll('form'));
  const scopes: Element[] = formEls.length
    ? formEls
    : [doc.body ?? doc.documentElement].filter(Boolean);
  const out: DetectedForm[] = [];
  for (const scope of scopes) {
    const df = analyzeScope(scope, rule);
    if (df) out.push(df);
  }
  return out;
}
