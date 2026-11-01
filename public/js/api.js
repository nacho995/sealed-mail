// Thin fetch wrapper. Reads the (non-HttpOnly) csrf cookie and echoes it back in a
// header on every state-changing request: the double-submit CSRF defense.

function csrfToken() {
  const m = document.cookie.match(/(?:^|; )csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

async function req(method, url, body) {
  const headers = {};
  const opts = { method, credentials: 'same-origin', headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (method !== 'GET') headers['x-csrf-token'] = csrfToken();
  const res = await fetch(url, opts);
  let data = null;
  try { data = await res.json(); } catch { /* no JSON body */ }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

export const api = {
  config: () => req('GET', '/api/config'),
  sendExternal: (p) => req('POST', '/api/messages/external', p),
  salt: (email) => req('GET', `/api/salt?email=${encodeURIComponent(email)}`),
  register: (p) => req('POST', '/api/register', p),
  login: (p) => req('POST', '/api/login', p),
  logout: () => req('POST', '/api/logout'),
  me: () => req('GET', '/api/me'),
  pubkey: (email) => req('GET', `/api/pubkey?email=${encodeURIComponent(email)}`),
  messages: (box) => req('GET', `/api/messages?box=${encodeURIComponent(box)}`),
  send: (p) => req('POST', '/api/messages', p),
  markRead: (id, box) => req('POST', `/api/messages/${id}/read?box=${encodeURIComponent(box)}`),

  recoverSalt: (email) => req('GET', `/api/recover/salt?email=${encodeURIComponent(email)}`),
  recoverBegin: (p) => req('POST', '/api/recover/begin', p),
  recoverComplete: (p) => req('POST', '/api/recover/complete', p),
  recoveryStatus: () => req('GET', '/api/recovery/status'),
  rotateRecovery: (p) => req('POST', '/api/recovery/rotate', p),
  reauth: (p) => req('POST', '/api/reauth', p),

  passkeyRegisterOptions: (authKey) => req('POST', '/api/passkeys/register/options', { authKey }),
  passkeyRegisterVerify: (p) => req('POST', '/api/passkeys/register/verify', p),
  passkeys: () => req('GET', '/api/passkeys'),
  deletePasskey: (id) => req('POST', `/api/passkeys/${encodeURIComponent(id)}/delete`, {}),
  passkeyLoginOptions: () => req('POST', '/api/passkeys/login/options', {}),
  passkeyLoginVerify: (p) => req('POST', '/api/passkeys/login/verify', p),
  revokeOtherSessions: () => req('POST', '/api/sessions/revoke-others', {}),
};
