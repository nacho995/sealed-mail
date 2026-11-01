// Browser side of passkeys. Converts between the server's JSON options and the
// ArrayBuffer-based navigator.credentials API, and extracts the PRF secret.
//
// SECURITY: the PRF output is the key that unlocks the private key. It is returned
// to the caller only and is never placed in the JSON sent to the server — the
// serializers below build clientExtensionResults as an empty object on purpose.

function b64urlToBuf(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
// PRF input. Public and the same for every credential: the authenticator mixes in
// its own per-credential secret, so outputs still differ per passkey, and a constant
// lets sign-in work without first telling the server who is signing in.
let prfSalt = null;
async function prfInput() {
  if (!prfSalt) prfSalt = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode('sealed-mail/prf/v1'));
  return prfSalt;
}

class PrfUnsupportedError extends Error {}

function isSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

// Early, best-effort PRF capability check (newer browsers only). `undefined` means
// "cannot tell"; we then find out from the actual ceremony.
async function prfCapability() {
  try {
    if (typeof PublicKeyCredential.getClientCapabilities !== 'function') return undefined;
    const caps = await PublicKeyCredential.getClientCapabilities();
    return caps['extension:prf'];
  } catch { return undefined; }
}

function registrationToJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: {},
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : undefined,
    },
  };
}

function assertionToJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: {},
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: r.userHandle ? bufToB64url(r.userHandle) : undefined,
    },
  };
}

function prfFirst(cred) {
  const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  return ext.prf && ext.prf.results && ext.prf.results.first ? ext.prf.results.first : null;
}

// Create a passkey and obtain its PRF secret.
// Returns { response (JSON for the server), prfOutput (ArrayBuffer, keep local) }.
async function createWithPrf(options) {
  if ((await prfCapability()) === false) throw new PrfUnsupportedError();
  const salt = await prfInput();
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: { ...options.user, id: b64urlToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
    extensions: { ...(options.extensions || {}), prf: { eval: { first: salt } } },
  };
  const cred = await navigator.credentials.create({ publicKey });
  let prfOutput = prfFirst(cred);
  if (!prfOutput) {
    const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
    if (!ext.prf || ext.prf.enabled === false) throw new PrfUnsupportedError();
    // Some platforms enable PRF at creation but only evaluate it on a get(). This
    // local get() only reads the PRF value; its random challenge is never verified.
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: window.crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: cred.rawId }],
        userVerification: 'required',
        rpId: options.rp && options.rp.id,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    prfOutput = prfFirst(assertion);
    if (!prfOutput) throw new PrfUnsupportedError();
  }
  return { response: registrationToJSON(cred), prfOutput };
}

// Usernameless sign-in: the browser lists this site's passkeys, the user picks one,
// and we get the PRF secret for it. No email is sent beforehand.
async function getWithPrf(options) {
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
    extensions: { ...(options.extensions || {}), prf: { eval: { first: await prfInput() } } },
  };
  const cred = await navigator.credentials.get({ publicKey });
  const prfOutput = prfFirst(cred);
  if (!prfOutput) throw new PrfUnsupportedError();
  return { response: assertionToJSON(cred), prfOutput };
}

export const webauthn = { isSupported, createWithPrf, getWithPrf, PrfUnsupportedError };
