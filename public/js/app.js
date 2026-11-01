import { crypto as seal } from './crypto.js';
import { api } from './api.js';
import { webauthn } from './webauthn.js';

// The private key lives ONLY in this in-memory object, imported non-extractable.
// It is never written to localStorage/disk, so a refresh drops it and the user
// unlocks again (password, passkey or recovery code).
const state = { email: null, privKey: null, pubKeyB64: null, box: 'inbox', recip: null };

const MIN_PASSWORD = 10;
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // mirrors the server's WebAuthn challenge lifetime

const $ = (id) => document.getElementById(id);
const show = (el) => { el.hidden = false; };
const hide = (el) => { el.hidden = true; };
const setMsg = (el, msg) => { el.textContent = msg || ''; el.hidden = !msg; };

// Raw key material (PKCS#8 bytes, PRF output) is wiped as soon as it has been used.
function zero(buf) { if (buf) new Uint8Array(buf).fill(0); }

// An error whose message is written for the person using the app.
class UserFacingError extends Error {}

const dateFmt = new Intl.DateTimeFormat('es', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const dayFmt = new Intl.DateTimeFormat('es', { day: 'numeric', month: 'long', year: 'numeric' });
const fmtDate = (ms) => dateFmt.format(new Date(ms));
const fmtDay = (ms) => dayFmt.format(new Date(ms));

// Top-level screens: exactly one is visible at a time.
const SCREENS = ['authView', 'recoverView', 'codeView', 'appView'];
function showScreen(id) { for (const s of SCREENS) $(s).hidden = s !== id; }

// Panels inside the signed-in app.
const PANELS = ['listView', 'readView', 'composeView', 'securityView'];
function showPanel(id) {
  for (const p of PANELS) $(p).hidden = p !== id;
  if (id !== 'securityView') { clearPendingPasskey(); closeSudo('cancelled'); }
}

// Is the client-authored "from" lying about who sent this? m.sender is set by the
// server from the authenticated session, so it is the trustworthy value.
function spoofedFrom(content, m) {
  return content && content.from &&
    String(content.from).toLowerCase() !== String(m.sender).toLowerCase();
}

function passkeyError(err) {
  if (err instanceof webauthn.PrfUnsupportedError) {
    return 'Este navegador o dispositivo no puede usar una passkey para abrir tu clave (le falta la extensión PRF). ' +
      'Prueba con Safari o Chrome actualizados, o con una llave de seguridad.';
  }
  if (err && err.name === 'NotAllowedError') return 'Se ha cancelado o ha tardado demasiado. Vuelve a intentarlo.';
  if (err && err.name === 'InvalidStateError') return 'Este dispositivo ya está añadido a tu cuenta.';
  return 'No se ha podido completar con Face ID o Touch ID.';
}

// ---- the envelope on the sign-in page ----
// Encrypts the headline for real, with a throwaway key, so the visitor sees exactly
// what a stored message looks like to the server.
async function sealHero() {
  const el = $('heroCipher');
  try {
    const { ciphertext } = await seal.encryptBody($('heroLine').textContent);
    el.textContent = ciphertext;
    el.classList.remove('sealing');
    el.classList.add('sealed');
  } catch {
    el.textContent = 'Este navegador no permite cifrar aquí (Web Crypto no está disponible).';
  }
}

// ---- recovery code screen ----
// The code is shown BEFORE the server stores it. onConfirm performs the write and
// runs only after the user says it is saved, so a failed request never leaves the
// account with a code nobody has.
let shownCode = null;
function showRecoveryCode(code, { onConfirm, onCancel = null }) {
  shownCode = code;
  const box = $('recoveryCode');
  box.textContent = '';
  for (const group of code.split('-')) {
    const span = document.createElement('span');
    span.textContent = group;
    box.appendChild(span);
  }
  $('codeSaved').checked = false;
  $('codeContinue').disabled = true;
  $('copyCodeBtn').textContent = 'Copiar el código';
  setMsg($('codeError'), '');
  $('codeCancel').hidden = !onCancel;
  showScreen('codeView');

  const clear = () => { shownCode = null; box.textContent = ''; };
  $('codeContinue').onclick = async () => {
    $('codeContinue').disabled = true;
    setMsg($('codeError'), '');
    try {
      await onConfirm();
      clear();
    } catch (err) {
      setMsg($('codeError'), err instanceof UserFacingError ? err.message : 'Algo ha fallado. Vuelve a intentarlo.');
      $('codeContinue').disabled = !$('codeSaved').checked;
    }
  };
  $('codeCancel').onclick = () => { clear(); if (onCancel) onCancel(); };
}
$('codeSaved').addEventListener('change', () => { $('codeContinue').disabled = !$('codeSaved').checked; });
$('copyCodeBtn').addEventListener('click', async () => {
  if (!shownCode) return;
  try {
    await navigator.clipboard.writeText(shownCode);
    $('copyCodeBtn').textContent = 'Copiado';
  } catch {
    window.getSelection().selectAllChildren($('recoveryCode'));
    $('copyCodeBtn').textContent = 'Seleccionado: cópialo con ⌘C';
  }
});

// ---- sign in / create account ----
let authMode = 'login';
function renderAuthMode() {
  const isReg = authMode === 'register';
  $('tabLogin').classList.toggle('active', !isReg);
  $('tabRegister').classList.toggle('active', isReg);
  $('authSubmit').textContent = isReg ? 'Crear cuenta' : 'Entrar';
  $('password').setAttribute('autocomplete', isReg ? 'new-password' : 'current-password');
  $('pwHint').hidden = !isReg;
  $('authAlt').hidden = isReg;
  setMsg($('authError'), '');
  setMsg($('altError'), '');
}

// Accepts raw PKCS#8 (imported non-extractable, then wiped) or a ready CryptoKey.
async function startSession(email, pkcs8OrKey, pubKeyB64) {
  state.email = email;
  if (pkcs8OrKey instanceof CryptoKey) {
    state.privKey = pkcs8OrKey;
  } else {
    state.privKey = await seal.importPrivateKey(pkcs8OrKey);
    zero(pkcs8OrKey);
  }
  state.pubKeyB64 = pubKeyB64 || (await api.me()).pubKey;
}

async function doRegister(email, password) {
  if (password.length < MIN_PASSWORD) throw new UserFacingError(`La contraseña necesita al menos ${MIN_PASSWORD} caracteres.`);
  const identity = await seal.generateIdentity();
  const pubKey = await seal.exportPublicKey(identity.publicKey);
  const pkcs8 = await seal.exportPkcs8(identity.privateKey);
  const pw = await seal.secretBundle(password, pkcs8);
  const code = seal.generateRecoveryCode();
  const recovery = await seal.secretBundle(seal.normalizeRecoveryCode(code), pkcs8);
  try {
    await api.register({
      email, pubKey,
      saltAuth: pw.saltAuth, saltWrap: pw.saltWrap, authKey: pw.authKey,
      encPrivKey: pw.encPrivKey, privIv: pw.privIv,
      recovery,
    });
  } catch {
    zero(pkcs8);
    throw new UserFacingError('No se ha podido crear la cuenta. Puede que ese correo ya esté registrado.');
  }
  // The extractable identity key is dropped; the session keeps a non-extractable import.
  await startSession(email.toLowerCase(), pkcs8, pubKey);
  // The account already exists, and the password works with or without this code;
  // if the code is lost now it can be regenerated from the Security panel.
  showRecoveryCode(code, { onConfirm: enterApp });
}

async function doLogin(email, password) {
  try {
    const { saltAuth } = await api.salt(email);
    const authKey = await seal.authKeyHex(password, saltAuth);
    const resp = await api.login({ email, authKey });
    const key = await seal.decryptPrivateKey(resp.encPrivKey, resp.privIv, await seal.wrapKey(password, resp.saltWrap));
    await startSession(resp.email, key);
  } catch {
    throw new UserFacingError('El correo o la contraseña no son correctos.');
  }
  await enterApp();
}

$('authForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('email').value.trim();
  const password = $('password').value;
  const btn = $('authSubmit');
  btn.disabled = true;
  setMsg($('authError'), '');
  try {
    if (authMode === 'register') await doRegister(email, password);
    else await doLogin(email, password);
    $('password').value = '';
  } catch (err) {
    setMsg($('authError'), err instanceof UserFacingError ? err.message : 'Algo ha fallado. Vuelve a intentarlo.');
  } finally {
    btn.disabled = false;
  }
});
$('tabLogin').addEventListener('click', () => { authMode = 'login'; renderAuthMode(); });
$('tabRegister').addEventListener('click', () => { authMode = 'register'; renderAuthMode(); });

// ---- sign in with a passkey (no email, no password) ----
$('passkeyLoginBtn').addEventListener('click', async () => {
  setMsg($('altError'), '');
  if (!webauthn.isSupported()) { setMsg($('altError'), 'Este navegador no admite passkeys.'); return; }
  const btn = $('passkeyLoginBtn');
  btn.disabled = true;
  try {
    const { challengeId, options } = await api.passkeyLoginOptions();
    const { response, prfOutput } = await webauthn.getWithPrf(options);
    let r;
    try {
      r = await api.passkeyLoginVerify({ challengeId, response });
    } catch {
      zero(prfOutput);
      throw new UserFacingError('Esa passkey no corresponde a ninguna cuenta activa. Puede que se quitara o que la cuenta se recuperase.');
    }
    const wrap = await seal.passkeyWrapKey(prfOutput);
    zero(prfOutput);
    const pkcs8 = await seal.decryptPkcs8(r.encPrivKey, r.privIv, wrap);
    await startSession(r.email, pkcs8);
    await enterApp();
  } catch (err) {
    setMsg($('altError'), err instanceof UserFacingError ? err.message : passkeyError(err));
  } finally {
    btn.disabled = false;
  }
});

// ---- recover with the recovery code ----
$('forgotBtn').addEventListener('click', () => {
  $('recEmail').value = $('email').value.trim();
  $('recCode').value = ''; $('recNewPw').value = '';
  setMsg($('recError'), '');
  showScreen('recoverView');
});
$('recBack').addEventListener('click', () => { showScreen('authView'); renderAuthMode(); });

$('recoverForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('recEmail').value.trim();
  const code = seal.normalizeRecoveryCode($('recCode').value);
  const newPw = $('recNewPw').value;
  setMsg($('recError'), '');
  if (code.length !== 32) { setMsg($('recError'), 'El código tiene 32 caracteres, en 8 grupos de 4.'); return; }
  if (newPw.length < MIN_PASSWORD) { setMsg($('recError'), `La contraseña nueva necesita al menos ${MIN_PASSWORD} caracteres.`); return; }
  const btn = $('recSubmit');
  btn.disabled = true;
  try {
    const { saltAuth } = await api.recoverSalt(email);
    const recAuthKey = await seal.authKeyHex(code, saltAuth);
    const b = await api.recoverBegin({ email, recAuthKey });
    const pkcs8 = await seal.decryptPkcs8(b.encPrivKey, b.privIv, await seal.wrapKey(code, b.saltWrap));
    // Re-wrap the SAME private key under the new password and a brand-new code, so
    // old mail stays readable. Nothing is written until the new code is saved.
    const password = await seal.secretBundle(newPw, pkcs8);
    const newCode = seal.generateRecoveryCode();
    const recovery = await seal.secretBundle(seal.normalizeRecoveryCode(newCode), pkcs8);
    const key = await seal.importPrivateKey(pkcs8);
    zero(pkcs8);
    $('recCode').value = ''; $('recNewPw').value = '';

    showRecoveryCode(newCode, {
      onConfirm: async () => {
        let r;
        try {
          r = await api.recoverComplete({ email, recAuthKey, password, recovery });
        } catch {
          throw new UserFacingError('No se ha podido completar la recuperación. Tu código anterior sigue sirviendo: vuelve a intentarlo.');
        }
        await startSession(r.email, key);
        await enterApp();
      },
      onCancel: () => showScreen('recoverView'),
    });
  } catch {
    setMsg($('recError'), 'El correo o el código no son correctos.');
  } finally {
    btn.disabled = false;
  }
});

// ---- app shell ----
async function enterApp() {
  showScreen('appView');
  $('whoami').textContent = state.email;
  show($('whoami'));
  show($('logoutBtn'));
  await openBox('inbox');
}

// The session can end underneath us (revoked from another device, expired).
function sessionEnded(message) {
  resetLocalState();
  showScreen('authView');
  authMode = 'login';
  renderAuthMode();
  setMsg($('authError'), message);
}

function setNavActive(target) {
  document.querySelectorAll('.navBtn').forEach((b) => b.classList.toggle('active', b === target));
}

async function openBox(box) {
  state.box = box;
  setNavActive(document.querySelector(`.navBtn[data-box="${box}"]`));
  $('boxTitle').textContent = box === 'sent' ? 'Enviados' : 'Entrada';
  showPanel('listView');
  const list = $('messageList');
  list.textContent = '';
  let messages;
  try {
    ({ messages } = await api.messages(box));
  } catch (err) {
    if (err && err.message === 'not authenticated') { sessionEnded('Tu sesión se ha cerrado. Vuelve a entrar.'); return; }
    setMsg($('emptyBox'), 'No se ha podido cargar la carpeta. Vuelve a intentarlo en un momento.');
    return;
  }
  setMsg($('emptyBox'), messages.length ? '' : (box === 'sent'
    ? 'Todavía no has enviado nada.'
    : 'Tu bandeja está vacía. Escribe a alguien que también use Sealed Mail: solo esa persona podrá leerlo.'));

  for (const m of messages) {
    let content = null;
    try {
      const messageKey = await seal.unwrapMessageKey(m.encKey, state.privKey);
      content = await seal.decryptBody(messageKey, m.ciphertext, m.iv);
    } catch { content = null; }
    list.appendChild(messageRow(m, box, content));
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Built with textContent only: subject/body/from are attacker-controlled plaintext.
function messageRow(m, box, content) {
  const li = el('li', 'msg');
  const from = el('span', 'msg-from');
  if (box === 'sent') {
    from.textContent = 'Para ' + (content && content.to ? content.to.join(', ') : 'destinatario desconocido');
  } else {
    from.textContent = m.sender;
    if (spoofedFrom(content, m)) from.appendChild(el('span', 'spoof', ` dice ser ${content.from}`));
  }
  li.append(from, el('span', 'msg-date', fmtDate(m.createdAt)));

  if (!content) {
    // Our key cannot open it: draw it as what it is, a closed envelope.
    li.classList.add('sealed');
    const subject = el('span', 'msg-subject');
    subject.append(el('span', 'seal tint'), document.createTextNode('Sobre cerrado'));
    li.append(subject, el('span', 'msg-preview', 'Tu clave no puede abrir este mensaje.'));
    return li;
  }

  li.append(
    el('span', 'msg-subject', content.subject || 'Sin asunto'),
    el('span', 'msg-preview', (content.body || '').slice(0, 140)),
  );
  if (box === 'inbox' && !m.read) li.classList.add('unread');
  li.tabIndex = 0;
  li.setAttribute('role', 'button');
  const open = () => openMessage(m, box, content);
  li.addEventListener('click', open);
  li.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  return li;
}

function openMessage(m, box, content) {
  showPanel('readView');
  $('readSubject').textContent = content.subject || 'Sin asunto';
  const from = $('readFrom');
  if (box === 'sent') {
    from.textContent = 'Para ' + (content.to || []).join(', ');
  } else {
    from.textContent = 'De ' + m.sender;
    if (spoofedFrom(content, m)) from.appendChild(el('span', 'spoof', ` (el mensaje dice ser de ${content.from})`));
  }
  $('readDate').textContent = fmtDate(m.createdAt);
  $('readBody').textContent = content.body || '';
  if (box === 'inbox' && !m.read) { m.read = 1; api.markRead(m.id, box).catch(() => {}); }
  $('backBtn').focus();
}

// ---- compose ----
function resetCompose() {
  $('to').value = ''; $('subject').value = ''; $('body').value = '';
  setMsg($('composeError'), ''); $('composeOk').hidden = true;
  setMsg($('recipFp'), ''); state.recip = null;
}
$('composeBtn').addEventListener('click', () => {
  setNavActive(null);
  showPanel('composeView');
  resetCompose();
  $('to').focus();
});

// Resolve the recipient and show their key fingerprint BEFORE sending, so the user
// can verify out-of-band and notice a substituted key.
async function resolveRecipient() {
  const to = $('to').value.trim().toLowerCase();
  state.recip = null;
  $('recipFp').classList.remove('spoof');
  if (!to) { setMsg($('recipFp'), ''); return; }
  try {
    const r = await api.pubkey(to);
    const fp = await seal.fingerprint(r.pubKey);
    state.recip = { email: to, pubKey: r.pubKey };
    // Prose in the UI face; only the string to compare character by character is mono.
    const line = $('recipFp');
    line.textContent = `Huella de ${to}: `;
    line.append(el('span', 'exact', fp), document.createTextNode('. Compárala con esa persona por otro canal.'));
    show(line);
  } catch {
    setMsg($('recipFp'), `${to} no tiene cuenta en Sealed Mail.`);
    $('recipFp').classList.add('spoof');
  }
}
$('to').addEventListener('change', resolveRecipient);

$('composeForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const to = $('to').value.trim().toLowerCase();
  const btn = $('sendBtn');
  btn.disabled = true;
  setMsg($('composeError'), ''); $('composeOk').hidden = true;
  try {
    if (!state.recip || state.recip.email !== to) await resolveRecipient();
    if (!state.recip || state.recip.email !== to) throw new UserFacingError(`${to} no tiene cuenta en Sealed Mail.`);
    const recipientPub = await seal.importPublicKey(state.recip.pubKey);
    const myPub = await seal.importPublicKey(state.pubKeyB64);
    const content = { from: state.email, to: [to], subject: $('subject').value, body: $('body').value };
    const { messageKey, ciphertext, iv } = await seal.encryptBody(content);
    const encKey = await seal.wrapMessageKey(messageKey, recipientPub);
    const selfEncKey = await seal.wrapMessageKey(messageKey, myPub);
    await api.send({ ciphertext, iv, recipients: [{ email: to, encKey }], selfEncKey });
    resetCompose();
    $('composeOk').hidden = false;
  } catch (err) {
    setMsg($('composeError'), err instanceof UserFacingError ? err.message : 'No se ha podido enviar. Tu mensaje sigue aquí.');
  } finally {
    btn.disabled = false;
  }
});
$('composeBack').addEventListener('click', () => openBox(state.box));

// ---- security ----

// "Sudo mode": ask for the password again. Resolves with the authKey (which the
// server re-checks) and an unwrap() that decrypts the private key only when it is
// actually needed; between the two only a non-extractable AES key is kept.
let sudoPending = null;
function requirePassword() {
  if (sudoPending) sudoPending.reject(new Error('cancelled')); // a newer action supersedes it
  return new Promise((resolve, reject) => {
    sudoPending = { resolve, reject };
    $('sudoPw').value = '';
    setMsg($('sudoError'), '');
    show($('sudoForm'));
    $('sudoForm').scrollIntoView({ block: 'nearest' });
    $('sudoPw').focus();
  });
}
function closeSudo(reason) {
  hide($('sudoForm'));
  $('sudoPw').value = '';
  if (sudoPending && reason) sudoPending.reject(new Error(reason));
  sudoPending = null;
}
$('sudoCancel').addEventListener('click', () => closeSudo('cancelled'));
$('sudoForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!sudoPending) return;
  const pw = $('sudoPw').value;
  $('sudoOk').disabled = true;
  try {
    const { saltAuth } = await api.salt(state.email);
    const authKey = await seal.authKeyHex(pw, saltAuth);
    const b = await api.reauth({ authKey });
    const wrap = await seal.wrapKey(pw, b.saltWrap);
    const unwrap = () => seal.decryptPkcs8(b.encPrivKey, b.privIv, wrap);
    const { resolve } = sudoPending;
    closeSudo(null);
    resolve({ authKey, unwrap });
  } catch {
    setMsg($('sudoError'), 'Esa no es tu contraseña.');
  } finally {
    $('sudoOk').disabled = false;
  }
});

async function renderSecurity() {
  try {
    const fp = await seal.fingerprint(state.pubKeyB64);
    const box = $('myFp');
    box.textContent = '';
    for (const group of fp.split(' ')) box.appendChild(el('span', null, group));
  } catch { /* fingerprint is informative only */ }

  try {
    const { hasRecoveryCode } = await api.recoveryStatus();
    $('recStatus').textContent = hasRecoveryCode
      ? 'Tienes un código activo. Genera otro si lo has perdido o crees que alguien lo ha visto: el anterior dejará de servir.'
      : 'No tienes código de recuperación. Si olvidas la contraseña perderás tus correos: genera uno ahora.';
  } catch { $('recStatus').textContent = ''; }

  const list = $('passkeyList');
  list.textContent = '';
  try {
    const { passkeys } = await api.passkeys();
    if (!passkeys.length) list.appendChild(el('li', 'none', 'Todavía no has añadido ningún dispositivo.'));
    for (const p of passkeys) {
      const device = el('span', 'device');
      device.append(
        el('span', null, p.label),
        el('small', null, `${p.kind}. Añadido el ${fmtDay(p.createdAt)}. ` +
          (p.lastUsedAt ? `Último uso: ${fmtDate(p.lastUsedAt)}.` : 'Sin usar todavía.')),
      );
      const del = el('button', 'btn ghost', 'Quitar');
      del.type = 'button';
      // Two-step confirmation, built into the page.
      del.addEventListener('click', async () => {
        if (del.dataset.armed !== '1') { del.dataset.armed = '1'; del.textContent = 'Quitar, seguro'; return; }
        try { await api.deletePasskey(p.id); } catch { /* the re-render shows the real state */ }
        renderSecurity();
      });
      const li = el('li');
      li.append(device, del);
      list.appendChild(li);
    }
  } catch { /* leave the list empty */ }
}

async function openSecurity() {
  setNavActive($('securityBtn'));
  showPanel('securityView');
  setMsg($('passkeyMsg'), ''); setMsg($('rotateMsg'), ''); setMsg($('sessionsMsg'), '');
  await renderSecurity();
}
$('securityBtn').addEventListener('click', openSecurity);

$('rotateCodeBtn').addEventListener('click', async () => {
  let authKey; let recovery; let code;
  try {
    const sudo = await requirePassword();
    authKey = sudo.authKey;
    const pkcs8 = await sudo.unwrap();
    code = seal.generateRecoveryCode();
    recovery = await seal.secretBundle(seal.normalizeRecoveryCode(code), pkcs8);
    zero(pkcs8);
  } catch { return; } // cancelled, or the sudo form already shows the error

  showRecoveryCode(code, {
    onConfirm: async () => {
      try {
        await api.rotateRecovery({ authKey, recovery });
      } catch {
        throw new UserFacingError('No se ha podido guardar el código nuevo. El anterior sigue sirviendo.');
      }
      showScreen('appView');
      await openSecurity();
      setMsg($('rotateMsg'), 'Código nuevo activo. El anterior ya no sirve.');
    },
    onCancel: () => { showScreen('appView'); openSecurity(); },
  });
});

// Adding a passkey takes two presses on purpose: Safari only lets a page start the
// biometric prompt right after a user gesture, so the slow part (password check,
// fetching the challenge) happens first and the second press goes straight to the
// authenticator. Between the two only a non-extractable key is held, and it is
// dropped when the challenge expires or the user leaves the panel.
let pendingPasskey = null;
let pendingTimer = null;
function clearPendingPasskey() {
  pendingPasskey = null;
  clearTimeout(pendingTimer);
  $('addPasskeyBtn').textContent = 'Añadir este dispositivo';
}

$('addPasskeyBtn').addEventListener('click', async () => {
  const btn = $('addPasskeyBtn');
  setMsg($('passkeyMsg'), '');
  if (!webauthn.isSupported()) { setMsg($('passkeyMsg'), 'Este navegador no admite passkeys.'); return; }

  if (!pendingPasskey) {
    const label = $('passkeyLabel').value.trim();
    if (!label) { setMsg($('passkeyMsg'), 'Ponle un nombre que reconozcas, por ejemplo «MacBook de casa».'); $('passkeyLabel').focus(); return; }
    try {
      const { authKey, unwrap } = await requirePassword();
      const { challengeId, options } = await api.passkeyRegisterOptions(authKey);
      pendingPasskey = { unwrap, challengeId, options, label };
      pendingTimer = setTimeout(() => {
        clearPendingPasskey();
        setMsg($('passkeyMsg'), 'Ha pasado demasiado tiempo. Vuelve a pulsar «Añadir este dispositivo».');
      }, CHALLENGE_TTL_MS - 15000);
      btn.textContent = 'Usar Face ID o Touch ID ahora';
      setMsg($('passkeyMsg'), 'Contraseña correcta. Pulsa el botón y sigue las instrucciones de tu dispositivo.');
    } catch (err) {
      if (!err || err.message !== 'cancelled') setMsg($('passkeyMsg'), 'No se ha podido preparar el registro. Vuelve a intentarlo.');
    }
    return;
  }

  const { unwrap, challengeId, options, label } = pendingPasskey;
  btn.disabled = true;
  try {
    const { response, prfOutput } = await webauthn.createWithPrf(options);
    const wrap = await seal.passkeyWrapKey(prfOutput);
    zero(prfOutput);
    const pkcs8 = await unwrap();
    const { encPrivKey, privIv } = await seal.encryptPkcs8(pkcs8, wrap);
    zero(pkcs8);
    await api.passkeyRegisterVerify({ challengeId, response, encPrivKey, privIv, label });
    $('passkeyLabel').value = '';
    setMsg($('passkeyMsg'), `«${label}» añadido. Ya puedes entrar con Face ID o Touch ID.`);
    await renderSecurity();
  } catch (err) {
    setMsg($('passkeyMsg'), passkeyError(err));
  } finally {
    clearPendingPasskey(); // the single-use challenge and the unwrap closure go either way
    btn.disabled = false;
  }
});

$('revokeOthersBtn').addEventListener('click', async () => {
  try {
    const { revoked } = await api.revokeOtherSessions();
    setMsg($('sessionsMsg'), revoked
      ? `Se ${revoked === 1 ? 'ha cerrado 1 sesión' : `han cerrado ${revoked} sesiones`}. Esta sigue abierta.`
      : 'No había otras sesiones abiertas.');
  } catch {
    setMsg($('sessionsMsg'), 'No se ha podido cerrar las sesiones. Vuelve a intentarlo.');
  }
});

// ---- nav / session ----
document.querySelectorAll('.navBtn[data-box]').forEach((b) =>
  b.addEventListener('click', () => openBox(b.dataset.box)));
$('backBtn').addEventListener('click', () => openBox(state.box));

function resetLocalState() {
  state.email = null; state.privKey = null; state.pubKeyB64 = null; state.recip = null;
  clearPendingPasskey();
  closeSudo('cancelled');
  hide($('whoami')); hide($('logoutBtn'));
}
$('logoutBtn').addEventListener('click', async () => {
  try { await api.logout(); } catch { /* ignore */ }
  resetLocalState();
  showScreen('authView');
  authMode = 'login';
  renderAuthMode();
});

// On load we always show the sign-in screen: the private key only lived in memory,
// so a surviving session cookie cannot decrypt anything until the user unlocks
// again. We do NOT destroy the server session here (that would sign out other tabs).
showScreen('authView');
renderAuthMode();
sealHero();
