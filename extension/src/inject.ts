// Injected into the page's MAIN world to observe WebAuthn (passkey) calls.
// Non-interfering: it notifies the extension and always delegates to the
// platform implementation, so where the vault has no passkey (or hooks are
// unavailable) native flows are unaffected (browser-extensions spec: passkey
// support "shall not interfere").

const creds = navigator.credentials as CredentialsContainer | undefined;
const origGet = creds?.get?.bind(creds);
const origCreate = creds?.create?.bind(creds);

if (creds && origGet) {
  creds.get = function (options?: CredentialRequestOptions) {
    if (options && 'publicKey' in options) {
      window.postMessage({ __vault: 'webauthn', op: 'get' }, window.location.origin);
    }
    return origGet(options);
  };
}

if (creds && origCreate) {
  creds.create = function (options?: CredentialCreationOptions) {
    if (options && 'publicKey' in options) {
      window.postMessage({ __vault: 'webauthn', op: 'create' }, window.location.origin);
    }
    return origCreate(options);
  };
}

export {};
