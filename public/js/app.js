import { crypto as seal } from './crypto.js';
import { api } from './api.js';
import { webauthn } from './webauthn.js';

// The private key lives ONLY in this in-memory object, imported non-extractable.
// It is never written to localStorage/disk, so a refresh drops it and the user
// unlocks again (password, passkey or recovery code).
// mailDomain: the domain our addresses live on (from /api/config); anything else is
// an outside address that can only receive ordinary email.
const state = { email: null, privKey: null, pubKeyB64: null, box: 'inbox', recip: null, mailDomain: 'sealed.local' };

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
// What the status bar says on the screens outside the app (the app sets its own).
const SCREEN_STATUS = {
  authView: ['sin sesión', 'tab siguiente campo  ↵ entrar'],
  recoverView: ['recuperar la cuenta', 'tab siguiente campo  ↵ comprobar'],
  codeView: ['código de recuperación', 'tab moverte  espacio marcar la casilla'],
};
function showScreen(id) {
  for (const s of SCREENS) $(s).hidden = s !== id;
  if (SCREEN_STATUS[id]) setStatus(...SCREEN_STATUS[id]);
}

// Panels inside the signed-in app. On a wide screen an open message keeps the folder
// beside it, like mutt's index and pager.
const PANELS = ['listView', 'readView', 'composeView', 'securityView'];
const SPLIT = window.matchMedia('(min-width: 1100px)');
function showPanel(id) {
  for (const p of PANELS) $(p).hidden = p !== id && !(id === 'readView' && p === 'listView' && SPLIT.matches);
  if (id !== 'securityView') { clearPendingPasskey(); closeSudo('cancelled'); }
}
SPLIT.addEventListener('change', () => {
  if (!$('readView').hidden) $('listView').hidden = !SPLIT.matches;
});

// An outside sender counts as verified only when the receiving provider's DMARC check passed.
function senderVerified(content) {
  return !!(content && content.auth && content.auth.dmarc === 'pass');
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

// ---- motion helpers ----
// Every animation here answers something real (a sentence being decrypted, a
// message being sealed) and is skipped for anyone who asks for reduced motion.
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CIPHER_GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const randomGlyph = () => CIPHER_GLYPHS[Math.floor(Math.random() * CIPHER_GLYPHS.length)];
// Same shape as `text` (spaces and line breaks kept) but every other character random.
const scrambled = (text) => text.replace(/\S/g, randomGlyph);
const SCRAMBLE_MAX = 1500; // longer texts: animate the start, the rest appears at the end

// Reveals `text` in `node` left to right, the part not yet revealed shown as cipher
// glyphs, as if it were being decrypted. `alive()` lets a newer call cancel this one.
async function decodeInto(node, text, duration, alive = () => true) {
  if (reducedMotion || !text) { node.textContent = text; return; }
  const head = text.slice(0, SCRAMBLE_MAX);
  const start = performance.now();
  for (;;) {
    if (!alive()) return;
    const p = Math.min(1, (performance.now() - start) / duration);
    const shown = Math.floor(head.length * p);
    const rest = el('span', 'scrambling', scrambled(head.slice(shown)));
    node.replaceChildren(document.createTextNode(head.slice(0, shown)), rest);
    if (p >= 1) break;
    await new Promise(requestAnimationFrame);
  }
  if (alive()) node.textContent = text;
}

// The juggler lives in a <template> and is copied into each spot that shows it.
for (const slot of document.querySelectorAll('.juggler-slot')) {
  slot.appendChild($('jugglerTpl').content.cloneNode(true));
}

// ---- the sign-in session ----
// The headline decrypts itself on screen, then is encrypted for real with a
// throwaway key and shown ASCII-armored: exactly what the server would store.

// PGP-style armor: fixed-width lines between BEGIN/END markers.
function armorLines(b64) {
  return ['-----BEGIN SEALED MESSAGE-----', 'Version: sealed-mail 0.1 (AES-256-GCM)', '',
    ...(b64.match(/.{1,64}/g) || []), '-----END SEALED MESSAGE-----'];
}
const armor = (b64) => armorLines(b64).join('\n');

// Writes the armor into `box` a line at a time, each kind of line in its colour.
async function printArmor(box, b64) {
  box.textContent = '';
  for (const line of armorLines(b64)) {
    const kind = line.startsWith('-----') ? 'armor-mark' : line.startsWith('Version') ? 'armor-head' : 'armor-data';
    box.append(el('span', kind, line), document.createTextNode('\n'));
    if (!reducedMotion) await sleep(55);
  }
}

// The first 64 bytes as `xxd` prints them: offset, 16 bytes in hex, then as ASCII.
async function printHexdump(box, b64) {
  const raw = atob(b64).slice(0, 64);
  box.textContent = '';
  for (let off = 0; off < raw.length; off += 16) {
    const chunk = [...raw.slice(off, off + 16)].map((c) => c.charCodeAt(0));
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0'))
      .reduce((acc, h, i) => acc + h + (i % 2 ? ' ' : ''), '').padEnd(40);
    const ascii = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    box.append(el('span', 'hex-off', `${off.toString(16).padStart(8, '0')}:`), document.createTextNode(' '),
      el('span', 'hex-bytes', hex), document.createTextNode(' '), el('span', 'hex-ascii', ascii), document.createTextNode('\n'));
    if (!reducedMotion) await sleep(70);
  }
}

// One step of a CLI log: a spinner, then a green tick. The figures in the text are
// measured in this browser.
const SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏';
async function bootStep(text) {
  const mark = el('span', 'boot-mark', reducedMotion ? '✓' : SPINNER[0]);
  mark.setAttribute('aria-hidden', 'true');
  const li = el('li');
  li.append(mark, el('span', 'boot-text', text));
  $('bootLog').appendChild(li);
  if (!reducedMotion) {
    for (let f = 1; f < 9; f++) { await sleep(55); mark.textContent = SPINNER[f % SPINNER.length]; }
  }
  mark.textContent = '✓';
  li.classList.add('done');
}

async function sealHero() {
  const line = $('heroLine').dataset.line;
  const box = $('heroCipher');
  await decodeInto($('heroTyped'), line, 1300);
  try {
    const t0 = performance.now();
    const { ciphertext } = await seal.encryptBody(line);
    const ms = performance.now() - t0;
    const bytes = new TextEncoder().encode(JSON.stringify(line)).length;
    await bootStep('clave AES-256 de un solo uso generada en este navegador');
    await bootStep(`${bytes} bytes cifrados en ${new Intl.NumberFormat('es', { maximumFractionDigits: 1 }).format(ms)} ms`);
    await printArmor(box, ciphertext);
    await printHexdump($('heroHex'), ciphertext);
    await bootStep('clave descartada: ese bloque ya no lo abre nadie, tampoco el servidor');
  } catch {
    box.textContent = 'Este navegador no permite cifrar aquí (Web Crypto no está disponible).';
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
  $('copyCodeBtn').textContent = 'copiar el código';
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
    $('copyCodeBtn').textContent = 'copiado';
  } catch {
    window.getSelection().selectAllChildren($('recoveryCode'));
    $('copyCodeBtn').textContent = 'seleccionado: cópialo con ⌘C';
  }
});

// ---- sign in / create account ----
let authMode = 'login';
function renderAuthMode() {
  const isReg = authMode === 'register';
  $('tabLogin').classList.toggle('active', !isReg);
  $('tabRegister').classList.toggle('active', isReg);
  $('authSubmit').textContent = isReg ? 'crear cuenta' : 'entrar';
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
  if (!email.toLowerCase().endsWith(`@${state.mailDomain}`)) {
    throw new UserFacingError(`Tu dirección tiene que terminar en @${state.mailDomain}, por ejemplo nombre@${state.mailDomain}.`);
  }
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

// Status bar: where you are on the left, the keys that work here on the right.
// Status bar, powerline style: the place as coloured segments ("entrada  5 mensajes"
// splits on double spaces), then each key as a keycap followed by what it does.
function setStatus(text, keys) {
  const segs = $('statusText');
  segs.textContent = '';
  for (const part of String(text).split('  ').filter(Boolean)) segs.appendChild(el('span', 'seg', part));
  const list = $('statusKeys');
  list.textContent = '';
  for (const item of String(keys).split('  ').filter(Boolean)) {
    const [key, ...what] = item.split(' ');
    const span = el('span', 'key');
    span.append(el('kbd', null, key), document.createTextNode(what.join(' ')));
    list.appendChild(span);
  }
}
const FOLDER_KEYS = 'j/k mover  ↵ abrir  c escribir  s seguridad';

// The folder index: one row per message, one of them selected, as in mutt or pine.
const index = { rows: [], sel: -1, load: 0 };

function selectRow(i, { focus = true } = {}) {
  if (!index.rows.length) return;
  index.sel = Math.max(0, Math.min(i, index.rows.length - 1));
  index.rows.forEach((r, n) => r.li.classList.toggle('selected', n === index.sel));
  const li = index.rows[index.sel].li;
  if (focus) li.focus();
  li.scrollIntoView({ block: 'nearest' });
}

function folderName(box) { return box === 'sent' ? 'enviados' : 'entrada'; }

function folderStatus(box, messages) {
  const n = messages.length;
  let text = `${folderName(box)}  ${n} ${n === 1 ? 'mensaje' : 'mensajes'}`;
  const unread = box === 'inbox' ? messages.filter((m) => !m.read).length : 0;
  if (unread) text += `, ${unread} sin leer`;
  setStatus(text, FOLDER_KEYS);
}

// The empty-folder note (the juggler keeps it company).
function setEmpty(text) {
  $('emptyText').textContent = text;
  $('emptyBox').hidden = !text;
}

async function openBox(box) {
  state.box = box;
  setNavActive(document.querySelector(`.navBtn[data-box="${box}"]`));
  $('boxTitle').textContent = folderName(box);
  showPanel('listView');
  setStatus(`${folderName(box)}  cargando`, FOLDER_KEYS);
  const list = $('messageList');
  list.textContent = '';
  index.rows = []; index.sel = -1;
  // A newer navigation (another folder, compose, security) may happen while this one
  // is still loading; when it does, this load must not touch the screen.
  const load = ++index.load;
  const stale = () => load !== index.load || $('listView').hidden;
  let messages;
  try {
    ({ messages } = await api.messages(box));
    if (stale()) return;
  } catch (err) {
    if (err && err.message === 'not authenticated') { sessionEnded('Tu sesión se ha cerrado. Vuelve a entrar.'); return; }
    if (stale()) return;
    setEmpty('No se ha podido cargar la carpeta. Vuelve a intentarlo en un momento.');
    setStatus(`${folderName(box)}  sin conexión con el servidor`, FOLDER_KEYS);
    return;
  }
  setEmpty(messages.length ? '' : (box === 'sent'
    ? 'Todavía no has enviado nada. Pulsa c para escribir.'
    : 'Tu bandeja está vacía. Pulsa c para escribir a alguien que también use Sealed Mail: solo esa persona podrá leerlo.'));

  for (const m of messages) {
    let content = null;
    try {
      const messageKey = await seal.unwrapMessageKey(m.encKey, state.privKey);
      content = await seal.decryptBody(messageKey, m.ciphertext, m.iv);
      m.messageKey = messageKey; // non-extractable; opens this message's attachments
    } catch { content = null; }
    if (stale()) return;
    const li = messageRow(m, box, content, index.rows.length);
    index.rows.push({ li, m, content });
    list.appendChild(li);
  }
  folderStatus(box, messages);
  if (index.rows.length) selectRow(0, { focus: false });
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// One index line: flag, date, who, subject. Built with textContent only, because
// subject, body and from are attacker-controlled plaintext.
function messageRow(m, box, content, position) {
  const li = el('li', 'msg');
  const unread = box === 'inbox' && !m.read && content;
  // The flag column is never truncated, so warnings live there too: the from column
  // can be cut off with an ellipsis and take the spoof notice with it.
  //   N new   ! the message claims another sender   ? from outside, sender not verified
  const spoofed = box === 'inbox' && spoofedFrom(content, m);
  const unverified = box === 'inbox' && m.external && !senderVerified(content);
  const flag = el('span', 'msg-flag', (unread ? 'N' : ' ') + (spoofed ? '!' : unverified ? '?' : ''));
  if (spoofed || unverified) {
    flag.classList.add(spoofed ? 'alert' : 'unverified');
    flag.title = spoofed ? `Dice ser ${content.from}, pero lo envió ${m.sender}` : 'De fuera, sin verificar';
  }
  li.append(flag, el('span', 'msg-date', fmtDate(m.createdAt)));

  const from = el('span', 'msg-from');
  if (box === 'sent') {
    from.textContent = 'para ' + (content && content.to ? content.to.join(', ') : 'destinatario desconocido');
  } else {
    from.textContent = m.sender;
    if (spoofedFrom(content, m)) from.appendChild(el('span', 'spoof', ` dice ser ${content.from}`));
  }
  // Ordinary email: arrived from outside, or left without end-to-end encryption.
  if (m.external) {
    const label = box === 'sent' ? 'correo normal' : senderVerified(content) ? 'de fuera, verificado' : 'de fuera, sin verificar';
    from.appendChild(el('span', 'badge', label));
  }
  li.append(from);

  if (unread) li.classList.add('unread');
  li.tabIndex = -1;
  li.setAttribute('role', 'button');
  li.addEventListener('click', () => { selectRow(position); if (content) openMessage(m, box, content); });

  if (!content) {
    // Our key cannot open it: show it as what it is, bytes nobody here can read.
    li.classList.add('sealed');
    li.append(el('span', 'msg-subject', '[cifrado] ░░░░░░░░░░░░░░░░░░░░'));
    li.title = 'Tu clave no puede abrir este mensaje.';
    return li;
  }
  const subject = el('span', 'msg-subject', content.subject || '(sin asunto)');
  const files = attachmentsOf(content);
  if (files.length) subject.appendChild(el('span', 'badge', files.length === 1 ? '1 adjunto' : `${files.length} adjuntos`));
  li.append(subject);
  return li;
}

let readRun = 0; // a newer message cancels the decrypt animation of the previous one
function openMessage(m, box, content) {
  showPanel('readView');
  const subject = content.subject || '(sin asunto)';
  $('readSubject').textContent = subject;
  const from = $('readFrom');
  if (box === 'sent') {
    $('readFromLabel').textContent = 'Para';
    from.textContent = (content.to || []).join(', ');
  } else {
    $('readFromLabel').textContent = 'De';
    from.textContent = m.sender;
    if (spoofedFrom(content, m)) from.appendChild(el('span', 'spoof', ` (el mensaje dice ser de ${content.from})`));
  }
  $('readDate').textContent = fmtDate(m.createdAt);
  let note = '';
  if (m.external && box === 'sent') {
    note = 'Salió como correo normal: quien gestione el correo del destinatario puede leerlo. Tu copia está cifrada.';
  } else if (m.external && senderVerified(content)) {
    note = 'Llegó de fuera como correo normal y el servidor lo cifró al recibirlo. El dominio del remitente lo ha autenticado (DMARC), así que viene de quien dice.';
  } else if (m.external) {
    note = 'Llegó de fuera como correo normal y el servidor lo cifró al recibirlo, pero no se ha podido comprobar que el remitente sea quien dice ser.';
  }
  setMsg($('readNote'), note);
  // the letter decrypts on screen (it really was just decrypted, in this browser)
  const run = ++readRun;
  decodeInto($('readBody'), content.body || '', 450, () => run === readRun);
  renderReadFiles(m, content);
  if (box === 'inbox' && !m.read) {
    m.read = 1;
    api.markRead(m.id, box).catch(() => {});
    const row = index.rows.find((r) => r.m === m);
    if (row) {
      row.li.classList.remove('unread');
      const flag = row.li.querySelector('.msg-flag');
      flag.textContent = ' ' + flag.textContent.slice(1);
    }
  }
  setStatus(`${folderName(box)}  leyendo: ${subject}`, SPLIT.matches ? 'j/k mover  ↵ abrir  q cerrar' : 'q volver  c escribir');
  // Side by side, keep the keyboard on the folder; alone, start at the reader.
  if (!SPLIT.matches) $('backBtn').focus();
}

// Back to the folder as it was: same selection, read flags already updated.
function closeReader() {
  showPanel('listView');
  folderStatus(state.box, index.rows.map((r) => r.m));
  if (index.sel >= 0) selectRow(index.sel);
}

// ---- attachments ----
const FILE_LIMITS = { count: 10, totalBytes: 10 * 1024 * 1024 }; // mirrors server/attachments.js
const sizeFmt = new Intl.NumberFormat('es', { maximumFractionDigits: 1 });
function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${sizeFmt.format(n / 1024)} KB`;
  return `${sizeFmt.format(n / (1024 * 1024))} MB`;
}
// The list in a decrypted body as [{ meta, index }], skipping malformed entries (it is
// sender-controlled) without shifting the others: index is the file's real position.
function attachmentsOf(content) {
  const list = content && Array.isArray(content.attachments) ? content.attachments.slice(0, FILE_LIMITS.count) : [];
  return list.map((meta, index) => ({ meta, index }))
    .filter(({ meta: a }) => a && typeof a.name === 'string' && Number.isInteger(a.size) && typeof a.sha256 === 'string');
}
// A name that is safe to show and to save under: no path separators, control
// characters or bidirectional overrides (which can make "fdp.exe" read as ".pdf").
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
function safeFileName(name) {
  const n = String(name).replace(UNSAFE_NAME_CHARS, '').replace(/[\\/]/g, '_').trim().slice(0, 200);
  return n && n !== '.' && n !== '..' ? n : 'adjunto';
}

function renderReadFiles(m, content) {
  const files = attachmentsOf(content);
  const list = $('readFileList');
  list.textContent = '';
  $('readFiles').hidden = !files.length;
  files.forEach(({ meta, index }) => {
    const li = el('li', 'file');
    const btn = el('button', 'btn', 'guardar');
    btn.type = 'button';
    btn.addEventListener('click', () => saveAttachment(m, meta, index, btn));
    li.append(el('span', 'file-name', safeFileName(meta.name)), el('span', 'file-size', fmtSize(meta.size)), btn);
    list.appendChild(li);
  });
}

// Downloads, decrypts and checks one attachment, then hands it to the browser as a
// download. Always application/octet-stream, so nothing sent to you is ever rendered
// or run by the browser just by saving it.
async function saveAttachment(m, meta, i, btn) {
  btn.disabled = true;
  btn.textContent = 'descifrando';
  try {
    const { ciphertext, iv } = await api.attachment(m.id, i);
    const bytes = await seal.decryptAttachment(m.messageKey, ciphertext, iv, i, meta);
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = safeFileName(meta.name);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    btn.textContent = 'guardado';
  } catch {
    btn.textContent = 'no se puede abrir: no coincide con el mensaje';
    btn.classList.add('spoof');
    return;
  } finally {
    btn.disabled = false;
  }
}

// Files chosen for the message being written. Read only when it is sent.
const draftFiles = [];
const draftBytes = () => draftFiles.reduce((n, f) => n + f.size, 0);

function renderDraftFiles(problem = '') {
  const list = $('attachList');
  list.textContent = '';
  draftFiles.forEach((f, i) => {
    const li = el('li', 'file');
    const del = el('button', 'btn ghost', 'quitar');
    del.type = 'button';
    del.addEventListener('click', () => { draftFiles.splice(i, 1); renderDraftFiles(); });
    li.append(el('span', 'file-name', f.name), el('span', 'file-size', fmtSize(f.size)), del);
    list.appendChild(li);
  });
  const used = draftFiles.length
    ? `${draftFiles.length} de ${FILE_LIMITS.count} archivos, ${fmtSize(draftBytes())} de 10 MB. Se cifran en tu navegador antes de salir.`
    : '';
  setMsg($('attachInfo'), problem || used);
  $('attachInfo').classList.toggle('spoof', Boolean(problem));
  $('attachMeterBox').hidden = !draftFiles.length;
  $('attachMeter').style.setProperty('--p', String(Math.min(1, draftBytes() / FILE_LIMITS.totalBytes)));
}

// ---- sealing animation ----
// While a message is encrypted and sent, the compose pane shows it crumbling into
// cipher glyphs, with the real steps as progress, and ends on the actual ciphertext.
// It never holds back an error: fail() removes it at once.
function startSealing(plain) {
  const box = $('sealing');
  const text = $('sealingText');
  const msg = $('sealingMsg');
  const meter = $('sealingMeter');
  const started = performance.now();
  let alive = true;
  box.hidden = false;
  msg.className = 'sealing-msg';
  msg.textContent = 'cifrando en este navegador';
  meter.style.setProperty('--p', '0.12');
  const src = (plain || ' ').slice(0, 900);
  text.textContent = src;
  (async () => {
    if (reducedMotion) return;
    const t0 = performance.now();
    while (alive) {
      const p = Math.min(1, (performance.now() - t0) / 900);
      const k = Math.floor(src.length * p);
      text.replaceChildren(el('span', 'scrambling', scrambled(src.slice(0, k))), document.createTextNode(src.slice(k)));
      if (p >= 1) break;
      await new Promise(requestAnimationFrame);
    }
  })();
  return {
    step(p, label) { meter.style.setProperty('--p', String(p)); msg.textContent = label; },
    async done(ciphertextB64, label) {
      const wait = 1000 - (performance.now() - started);
      if (wait > 0 && !reducedMotion) await sleep(wait);
      alive = false;
      text.textContent = armorLines(ciphertextB64).slice(0, 9).join('\n');
      meter.style.setProperty('--p', '1');
      msg.textContent = `✓ ${label}`;
      msg.classList.add('done');
      await sleep(reducedMotion ? 900 : 1600);
      box.hidden = true;
    },
    fail() { alive = false; box.hidden = true; },
  };
}

$('attachBtn').addEventListener('click', () => $('fileInput').click());
$('fileInput').addEventListener('change', () => {
  let problem = '';
  for (const file of $('fileInput').files) {
    if (draftFiles.length >= FILE_LIMITS.count) { problem = `Como mucho ${FILE_LIMITS.count} archivos por mensaje.`; break; }
    if (draftBytes() + file.size > FILE_LIMITS.totalBytes) { problem = `${file.name} no cabe: el límite es 10 MB por mensaje.`; continue; }
    draftFiles.push(file);
  }
  $('fileInput').value = '';
  renderDraftFiles(problem);
});

// ---- compose ----
const SEND_SEALED = 'cifrar y enviar';
const SEND_PLAIN = 'enviar sin cifrado de extremo a extremo';

function resetCompose() {
  $('to').value = ''; $('subject').value = ''; $('body').value = '';
  setMsg($('composeError'), ''); $('composeOk').hidden = true;
  setMsg($('recipFp'), ''); state.recip = null;
  $('sendBtn').textContent = SEND_SEALED;
  draftFiles.length = 0;
  renderDraftFiles();
}
$('composeBtn').addEventListener('click', () => {
  setNavActive(null);
  showPanel('composeView');
  resetCompose();
  setStatus('mensaje nuevo', 'esc salir del campo  a adjuntar  e entrada');
  $('to').focus();
});

// Resolve the recipient and show their key fingerprint BEFORE sending, so the user
// can verify out-of-band and notice a substituted key.
async function resolveRecipient() {
  const to = $('to').value.trim().toLowerCase();
  const line = $('recipFp');
  state.recip = null;
  line.classList.remove('spoof', 'warn');
  $('sendBtn').textContent = SEND_SEALED;
  if (!to) { setMsg(line, ''); return; }

  // Someone outside Sealed Mail (Gmail, Outlook…): they have no key here, so this can
  // only go out as an ordinary email. Say so before sending, not after.
  if (!to.endsWith(`@${state.mailDomain}`)) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) { setMsg(line, 'Esa dirección no parece válida.'); line.classList.add('spoof'); return; }
    state.recip = { email: to, external: true };
    setMsg(line, 'Esta dirección no es de Sealed Mail, así que el mensaje saldrá como un correo normal: ' +
      'quien gestione su correo podrá leerlo. Tu copia en Enviados sí queda cifrada.');
    line.classList.add('warn');
    $('sendBtn').textContent = SEND_PLAIN;
    return;
  }

  try {
    const r = await api.pubkey(to);
    const fp = await seal.fingerprint(r.pubKey);
    state.recip = { email: to, pubKey: r.pubKey };
    // Prose in the UI face; only the string to compare character by character is mono.
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
  let anim = null;
  try {
    if (!state.recip || state.recip.email !== to) await resolveRecipient();
    if (!state.recip || state.recip.email !== to) throw new UserFacingError(`${to} no tiene cuenta en Sealed Mail.`);
    const myPub = await seal.importPublicKey(state.pubKeyB64);
    const content = { from: state.email, to: [to], subject: $('subject').value, body: $('body').value };
    anim = startSealing(`${content.subject}\n\n${content.body}`);
    // Files: described inside the encrypted body, then each encrypted under its key.
    if (draftFiles.length) anim.step(0.3, `cifrando ${draftFiles.length === 1 ? '1 adjunto' : `${draftFiles.length} adjuntos`}`);
    const fileBytes = await Promise.all(draftFiles.map((f) => f.arrayBuffer()));
    if (fileBytes.length) {
      content.attachments = await Promise.all(draftFiles.map((f, i) =>
        seal.describeFile(f.name, f.type || 'application/octet-stream', fileBytes[i])));
    }
    const { messageKey, ciphertext, iv } = await seal.encryptBody(content);
    const selfEncKey = await seal.wrapMessageKey(messageKey, myPub);
    const sealedFiles = [];
    for (const [i, bytes] of fileBytes.entries()) sealedFiles.push(await seal.encryptAttachment(messageKey, bytes, i));
    anim.step(0.65, state.recip.external ? 'enviando como correo normal' : 'enviando el sobre cifrado');

    if (state.recip.external) {
      // The text and files go to our server in clear (over the session) because the
      // outside mail system cannot read anything else; only your own copy is stored,
      // encrypted.
      const files = content.attachments
        ? content.attachments.map((a, i) => ({ name: a.name, type: a.type, data: seal.bufToB64(fileBytes[i]) }))
        : undefined;
      try {
        await api.sendExternal({
          to, subject: content.subject, body: content.body, files,
          selfCopy: { ciphertext, iv, encKey: selfEncKey, attachments: sealedFiles.length ? sealedFiles : undefined },
        });
      } catch (err) {
        throw new UserFacingError(err && err.message === 'attachment quota exceeded'
          ? 'Has llegado al límite de 250 MB de adjuntos de tu cuenta.'
          : 'El servidor de correo saliente no ha aceptado el mensaje. Tu mensaje sigue aquí.');
      }
      await anim.done(ciphertext, `enviado a ${to} como correo normal`);
      resetCompose();
      setMsg($('composeOk'), `Enviado a ${to} como correo normal.`);
      return;
    }

    const encKey = await seal.wrapMessageKey(messageKey, await seal.importPublicKey(state.recip.pubKey));
    try {
      await api.send({ ciphertext, iv, recipients: [{ email: to, encKey }], selfEncKey,
        attachments: sealedFiles.length ? sealedFiles : undefined });
    } catch (err) {
      if (err && err.message === 'attachment quota exceeded') throw new UserFacingError('Has llegado al límite de 250 MB de adjuntos de tu cuenta.');
      throw err;
    }
    await anim.done(ciphertext, `sellado y enviado: solo ${to} puede abrirlo`);
    resetCompose();
    setMsg($('composeOk'), 'Enviado. Solo el destinatario puede abrirlo.');
  } catch (err) {
    if (anim) anim.fail();
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
      const del = el('button', 'btn ghost', 'quitar');
      del.type = 'button';
      // Two-step confirmation, built into the page.
      del.addEventListener('click', async () => {
        if (del.dataset.armed !== '1') { del.dataset.armed = '1'; del.textContent = 'quitar, seguro'; return; }
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
  setStatus('seguridad', 'e entrada  v enviados  c escribir');
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
  $('addPasskeyBtn').textContent = 'añadir este dispositivo';
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
        setMsg($('passkeyMsg'), 'Ha pasado demasiado tiempo. Vuelve a pulsar «añadir este dispositivo».');
      }, CHALLENGE_TTL_MS - 15000);
      btn.textContent = 'usar Face ID o Touch ID ahora';
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
$('backBtn').addEventListener('click', closeReader);

// ---- keyboard ----
// Single-letter keys, as in a terminal mail reader. They never fire while the user
// is typing in a field or holding a modifier, so ⌘C and friends keep working.
function typingIn(target) {
  return target instanceof HTMLElement &&
    (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
}

document.addEventListener('keydown', (e) => {
  if ($('appView').hidden || e.metaKey || e.ctrlKey || e.altKey) return;
  if (typingIn(e.target)) {
    // Escape leaves the field, so the letter keys work again without the mouse.
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  const key = e.key;
  // Enter on a focused button or link belongs to that control.
  if (key === 'Enter' && e.target instanceof Element && e.target.closest('button, a')) return;
  const inFolder = !$('listView').hidden;
  let handled = true;
  if (key === 'c') $('composeBtn').click();
  else if (key === 'e') openBox('inbox');
  else if (key === 'v') openBox('sent');
  else if (key === 's') openSecurity();
  else if (key === 'a' && !$('composeView').hidden) $('attachBtn').click();
  else if (inFolder && (key === 'j' || key === 'ArrowDown')) selectRow(index.sel + 1);
  else if (inFolder && (key === 'k' || key === 'ArrowUp')) selectRow(index.sel - 1);
  else if (inFolder && key === 'Enter' && index.sel >= 0) index.rows[index.sel].li.click();
  else if (!$('readView').hidden && (key === 'q' || key === 'Escape')) closeReader();
  else if (!inFolder && (key === 'q' || key === 'Escape')) openBox(state.box);
  else handled = false;
  if (handled) e.preventDefault();
});

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
api.config().then(({ mailDomain }) => {
  state.mailDomain = mailDomain;
  $('email').placeholder = `nombre@${mailDomain}`;
  $('recEmail').placeholder = `nombre@${mailDomain}`;
  $('to').placeholder = `nombre@${mailDomain} o cualquier dirección`;
}).catch(() => { /* keep the default domain */ });
