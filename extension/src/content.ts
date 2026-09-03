// Content script: detect forms, fill on an explicit user gesture (never
// automatically), guard cross-origin iframe fills, and capture submissions for
// save/update. Runs in the isolated world; page JS never sees vault data beyond
// values written into fields.

import { ruleForDomain } from './lib/curatedRules';
import { detectForms, type DetectedForm } from './lib/formDetection';
import { registrableDomain } from './lib/matching';
import type { Candidate, Credential } from './lib/messages';

function currentForms(): DetectedForm[] {
  return detectForms(document, ruleForDomain(registrableDomain(location.href)));
}

function setValue(el: HTMLInputElement, value: string) {
  el.focus();
  el.value = value;
  // Fire the events frameworks listen for.
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function safeTopOrigin(): string | null {
  try {
    return window.top?.location.origin ?? null;
  } catch {
    return null; // cross-origin top: access denied
  }
}

/** Cross-origin iframe defence: confirm, naming both origins, before filling. */
function iframeFillAllowed(): boolean {
  if (window.top === window.self) return true;
  const top = safeTopOrigin();
  if (top && top === location.origin) return true;
  return window.confirm(
    `This login form (${location.origin}) is embedded in a different site` +
      `${top ? ` (${top})` : ''}. Fill credentials here?`
  );
}

async function send<T>(msg: unknown): Promise<T | null> {
  try {
    const resp = await chrome.runtime.sendMessage(msg);
    return resp?.ok ? (resp.data as T) : null;
  } catch {
    return null;
  }
}

async function fillById(id: string) {
  if (!iframeFillAllowed()) return;
  const cred = await send<Credential | null>({ type: 'FILL', id });
  if (!cred) return;
  const f = currentForms()[0];
  if (!f) return;
  if (f.usernameField && cred.username) setValue(f.usernameField, cred.username);
  if (f.passwordFields[0] && cred.password) setValue(f.passwordFields[0], cred.password);
  if (f.totpField && cred.totp) setValue(f.totpField, cred.totp);
}

/** Fill on the keyboard shortcut: pick the best candidate for this origin. */
async function fillShortcut() {
  const candidates = await send<Candidate[]>({ type: 'CANDIDATES', url: location.href });
  if (!candidates || candidates.length === 0) return;
  await fillById(candidates[0].id);
}

window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    void fillShortcut();
  }
});

// Save/update capture: on submit, hand the credentials to the background, which
// decides save vs update vs never-ask.
window.addEventListener(
  'submit',
  () => {
    const f = currentForms().find((x) => x.passwordFields.length > 0);
    if (!f) return;
    const username = f.usernameField?.value ?? '';
    const password = f.passwordFields[0]?.value ?? '';
    if (!password) return;
    void send({ type: 'CAPTURE', url: location.href, username, password });
  },
  true
);

// Popup can ask the content script to fill a chosen item.
chrome.runtime.onMessage.addListener((msg: { type?: string; id?: string }) => {
  if (msg?.type === 'FILL_IN_PAGE' && msg.id) void fillById(msg.id);
});

// Bridge passkey (WebAuthn) requests intercepted in the page world.
window.addEventListener('message', (event) => {
  if (event.source !== window || event.data?.__vault !== 'webauthn') return;
  // Relay to background; a full implementation completes the ceremony from the
  // vault and posts the result back. Where the vault has no passkey, it does not
  // interfere with the platform flow.
  void send({ type: 'CANDIDATES', url: location.href });
});
