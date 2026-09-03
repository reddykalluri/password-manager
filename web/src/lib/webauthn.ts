// Browser WebAuthn assertion, converting to/from the webauthn-rs wire format.

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64url(b: ArrayBuffer): string {
  const bytes = new Uint8Array(b);
  let s = '';
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface RcrPublicKey {
  challenge: string;
  timeout?: number;
  rpId?: string;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: Array<{ id: string; type: string; transports?: AuthenticatorTransport[] }>;
}

/** Perform an assertion for a webauthn-rs RequestChallengeResponse. */
export async function doWebauthnAssertion(challenge: unknown): Promise<unknown> {
  const pk = (challenge as { publicKey: RcrPublicKey }).publicKey;
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBuf(pk.challenge),
    timeout: pk.timeout,
    rpId: pk.rpId,
    userVerification: pk.userVerification ?? 'preferred',
    allowCredentials: (pk.allowCredentials ?? []).map((c) => ({
      id: b64urlToBuf(c.id),
      type: 'public-key',
      transports: c.transports
    }))
  };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('WebAuthn assertion cancelled');
  const resp = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64url(resp.authenticatorData),
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      signature: bufToB64url(resp.signature),
      userHandle: resp.userHandle ? bufToB64url(resp.userHandle) : null
    },
    extensions: cred.getClientExtensionResults()
  };
}
