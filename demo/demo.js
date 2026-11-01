// "Play the server": the visitor holds everything the Sealed Mail server stores and
// tries to read Alice's mail to Bob. Every operation goes through the app's real
// crypto module (js/crypto.js, copied unchanged from public/js/crypto.js at build).
//
// Demo-only shortcut: to let the visitor change Bob's password on the fly, this page
// keeps Bob's raw private key bytes in memory. The real app never does that.
import { crypto as seal } from './js/crypto.js';
import { randomPassword, COMMON_PASSWORDS, searchSpace, yearsToSearch, humanYears } from './attack-math.js';

const $ = (id) => document.getElementById(id);
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
const preview = (s, n = 72) => (s.length > n ? `${s.slice(0, n)}… (${s.length} caracteres)` : s);
// The app's own base64 helpers, so the wire format is exactly the app's.
const b64ToBytes = (b64) => new Uint8Array(seal.b64ToBuf(b64));
const bytesToB64 = (bytes) => seal.bufToB64(bytes);

// ---------- state ----------
const S = {
  act: 1,
  bob: null, server: null, // { pub, pubB64, priv?, fp } (Alice only sends, so she needs no key here)
  bobKey: null,          // Bob's working private key (null while he is locked out)
  recovered: false,      // step 5: Bob got back in with his code
  bobPkcs8: null,        // demo-only, see header comment
  bobPassword: '', pwBundle: null,
  pwReady: Promise.resolve(), // settles when pwBundle matches bobPassword
  crackedKey: null,      // Bob's key once you cracked his password (step 4)
  recCode: '', recBundle: null,
  stored: null,          // what the server keeps: { bytes, iv, encKey }
  delivered: null,       // what reaches Bob (differs from stored only when you swap keys)
  stolen: null,          // plaintext you read in step 3
  flips: new Set(),      // byte indexes you flipped in step 2
  cracked: null,         // password you found in step 4
  attacking: false,
  seq: 0,                // pipeline runs (newest wins)
  bobSeq: 0,             // Bob renders (newest wins)
  crackSeq: 0,           // live reads with the cracked key (newest wins)
};

async function makeIdentity() {
  const kp = await seal.generateIdentity();
  const pubB64 = await seal.exportPublicKey(kp.publicKey);
  return { pubB64, pub: await seal.importPublicKey(pubB64), priv: kp.privateKey, fp: await seal.fingerprint(pubB64) };
}

// ---------- rendering ----------
function renderFingerprint(box, fp, compareTo) {
  box.textContent = '';
  const mine = fp.split(' ');
  const other = compareTo ? compareTo.split(' ') : mine;
  mine.forEach((g, i) => box.appendChild(el('span', g === other[i] ? '' : 'diff', g)));
}

function renderServer() {
  const { bytes, iv, encKey } = S.stored;
  const box = $('bytes');
  box.textContent = '';
  bytes.forEach((b, i) => {
    const flipped = S.flips.has(i);
    const cell = el('button', flipped ? 'byte flipped' : 'byte', ((flipped ? b ^ 1 : b)).toString(16).padStart(2, '0'));
    cell.type = 'button';
    cell.dataset.i = i;
    cell.tabIndex = S.act === 2 ? 0 : -1;
    box.appendChild(cell);
  });
  $('ctSize').textContent = `${bytes.length} bytes, IV ${b64ToBytes(iv).length * 8} bits`;
  $('bytesNote').textContent = S.act === 2
    ? (S.flips.size ? `Has cambiado ${S.flips.size} ${S.flips.size === 1 ? 'bit' : 'bits'} de ${bytes.length * 8}.` : 'Pulsa un byte para cambiarle un bit.')
    : 'Cada pulsación vuelve a cifrar con una clave y un IV nuevos: el mismo texto nunca da el mismo sobre.';
  $('wrapped').textContent = preview(encKey);

  $('stolen').hidden = S.stolen === null;
  $('stolenText').textContent = S.stolen === null ? '' : (S.stolen || '(mensaje vacío)');
  $('pwBlob').textContent = preview(S.pwBundle.encPrivKey);
  $('recBlob').textContent = preview(S.recBundle.encPrivKey);
}

async function renderBob() {
  const inbox = document.querySelector('.inbox');
  const status = $('bobStatus');
  // Several callers (typing, byte clicks, buttons) render Bob concurrently. Snapshot the
  // state now, and only the most recent render may touch the DOM when it finishes.
  const my = ++S.bobSeq;
  const key = S.bobKey;
  const { bytes, iv, encKey } = S.delivered;
  const flips = S.act === 2 ? new Set(S.flips) : new Set();

  let body = null;
  if (key) {
    const tampered = flips.size ? bytes.map((b, i) => (flips.has(i) ? b ^ 1 : b)) : bytes;
    try {
      const mk = await seal.unwrapMessageKey(encKey, key);
      body = (await seal.decryptBody(mk, bytesToB64(tampered), iv)).body;
    } catch { body = null; }
  }
  if (my !== S.bobSeq) return;

  inbox.classList.remove('locked', 'rejected');
  status.className = 'status';
  if (!key) {
    inbox.classList.add('locked');
    $('bobText').classList.add('tint');
    $('bobText').textContent = 'Sobre cerrado. Sin su contraseña, Bob no puede abrir su clave privada.';
    status.textContent = '';
  } else if (body !== null) {
    $('bobText').classList.remove('tint');
    $('bobText').textContent = body || '(vacío)';
    status.textContent = 'Descifrado y verificado en su navegador.';
    status.classList.add('ok');
  } else {
    // A message that fails authentication is drawn as what it is: an envelope nobody can open.
    inbox.classList.add('rejected');
    $('bobText').classList.add('tint');
    $('bobText').textContent = 'Sobre rechazado';
    status.textContent = 'Rechazado: el sobre ha sido manipulado. AES-GCM no entrega ni una parte.';
    status.classList.add('bad');
  }
}

function renderFingerprints() {
  const swapped = S.act === 3 && $('mitm').checked;
  const seen = swapped ? S.server.fp : S.bob.fp;
  renderFingerprint($('aliceSeesFp'), seen, S.bob.fp);
  renderFingerprint($('bobFp'), S.bob.fp, seen);
}

const BRIEFS = {
  1: 'Escribe como Alice. Mira qué te llega a ti y qué lee Bob.',
  2: 'Antes de entregárselo a Bob, pulsa cualquier byte del mensaje cifrado para cambiarle un bit.',
  3: 'Activa el interruptor: cuando Alice pida la clave pública de Bob, le darás la tuya.',
  4: 'Guardas la clave privada de Bob cifrada con su contraseña. Elige esa contraseña y lanza un ataque de diccionario.',
  5: 'Bob ha olvidado su contraseña. Ayúdale a entrar con su código de recuperación; luego intenta adivinarlo tú.',
};

function renderVerdict() {
  let v = '';
  if (S.act === 1) {
    v = 'No puedes leerlo. Tienes los bytes, la clave del mensaje envuelta y la clave pública de Bob, pero la clave privada que abre el sobre solo existe en el navegador de Bob.';
  } else if (S.act === 2 && S.flips.size) {
    v = `Has cambiado ${S.flips.size === 1 ? 'un solo bit' : `${S.flips.size} bits`} y Bob ha rechazado el mensaje entero. AES-GCM lleva una etiqueta de autenticación: el servidor no puede alterar un mensaje sin que se note.`;
  } else if (S.act === 3 && $('mitm').checked) {
    v = 'Lo has leído. Este es el ataque que el cifrado por sí solo no detiene: un servidor que reparte claves falsas. La defensa es que Alice y Bob comparen sus huellas por otro canal. Mira las dos columnas: no coinciden.';
  } else if (S.act === 4 && S.cracked !== null) {
    v = `Contraseña encontrada: «${S.cracked}». Con ella abres la clave privada de Bob y lees todo su correo, el pasado y el futuro. El cifrado aguanta; una contraseña débil, no.`;
  } else if (S.act === 5 && S.bobKey && S.recovered) {
    v = 'Bob ha vuelto a entrar sin perder nada: su clave privada estaba guardada también bajo el código de recuperación, y ese código solo lo tiene él, en papel.';
  }
  $('verdict').textContent = v;
}

// ---------- the pipeline: Alice writes, the server stores, Bob reads ----------
let typingTimer;
function schedule() { clearTimeout(typingTimer); typingTimer = setTimeout(pipeline, 120); }

async function pipeline() {
  const my = ++S.seq;
  const body = $('aliceText').value;
  const swapped = S.act === 3 && $('mitm').checked;
  const recipient = swapped ? S.server : S.bob;

  const sealed = await seal.encryptBody({ body });
  const encKey = await seal.wrapMessageKey(sealed.messageKey, recipient.pub);
  const stored = { bytes: b64ToBytes(sealed.ciphertext), iv: sealed.iv, encKey };

  let delivered = stored;
  let stolen = null;
  if (swapped) {
    // You hold the matching private key: open it, read it, then re-seal it for the
    // real Bob so that he notices nothing.
    const mk = await seal.unwrapMessageKey(encKey, S.server.priv);
    stolen = (await seal.decryptBody(mk, sealed.ciphertext, sealed.iv)).body;
    const resealed = await seal.encryptBody({ body: stolen });
    delivered = {
      bytes: b64ToBytes(resealed.ciphertext), iv: resealed.iv,
      encKey: await seal.wrapMessageKey(resealed.messageKey, S.bob.pub),
    };
  }
  if (my !== S.seq) return; // a newer keystroke already started

  S.stored = stored; S.delivered = delivered; S.stolen = stolen;
  S.flips.clear();
  renderServer();
  renderFingerprints();
  await renderBob();
  // Once Bob's password has fallen you keep reading, live, whatever Alice writes next.
  if (S.act === 4 && S.crackedKey) await readCrackedMail();
  renderVerdict();
}

// ---------- step 2: tamper ----------
$('bytes').addEventListener('click', async (e) => {
  const cell = e.target.closest('.byte');
  if (!cell || S.act !== 2) return;
  const i = Number(cell.dataset.i);
  if (S.flips.has(i)) S.flips.delete(i); else S.flips.add(i);
  renderServer();
  await renderBob();
  renderVerdict();
  $('bytes').querySelector(`[data-i="${i}"]`)?.focus();
});
$('flipRandom').addEventListener('click', async () => {
  const n = S.stored.bytes.length;
  const free = [...Array(n).keys()].filter((i) => !S.flips.has(i));
  if (!free.length) return;
  S.flips.add(free[Math.floor(Math.random() * free.length)]);
  renderServer(); await renderBob(); renderVerdict();
});
$('restore').addEventListener('click', async () => { S.flips.clear(); renderServer(); await renderBob(); renderVerdict(); });

// ---------- step 3: key substitution ----------
$('mitm').addEventListener('change', pipeline);

// ---------- step 4: dictionary attack on Bob's password-wrapped key ----------
// Re-wrapping Bob's key takes two PBKDF2 runs. S.pwReady lets the attack wait for
// it, and the bundle is only stored if it still belongs to the latest password.
function setBobPassword(pw) {
  S.bobPassword = pw;
  S.cracked = null; S.crackedKey = null;
  $('pwProgress').textContent = ''; $('pwProgress').className = 'progress';
  $('crackedBox').hidden = true;
  S.pwReady = seal.secretBundle(pw, S.bobPkcs8).then((bundle) => {
    if (S.bobPassword !== pw) return;
    S.pwBundle = bundle;
    if (S.stored) { renderServer(); renderVerdict(); } // nothing to repaint yet during boot
  });
  return S.pwReady;
}

// With the cracked key you are Bob: open whatever is stored right now. The message is
// read in one go so a keystroke cannot swap it halfway through.
async function readCrackedMail() {
  const my = ++S.crackSeq;
  const { bytes, iv, encKey } = S.stored;
  try {
    const mk = await seal.unwrapMessageKey(encKey, S.crackedKey);
    const { body } = await seal.decryptBody(mk, bytesToB64(bytes), iv);
    if (my !== S.crackSeq) return;
    $('crackedText').textContent = body || '(mensaje vacío)';
    $('crackedBox').hidden = false;
  } catch { /* the password changed meanwhile; the next render settles it */ }
}
let pwTimer;
$('bobPw').addEventListener('input', () => {
  clearTimeout(pwTimer);
  pwTimer = setTimeout(() => setBobPassword($('bobPw').value), 300);
});
document.querySelectorAll('.chip').forEach((chip) => chip.addEventListener('click', () => {
  const pw = chip.dataset.pw || randomPassword(12);
  $('bobPw').value = pw;
  setBobPassword(pw);
}));

// One guess = what a real attacker does with a stolen database row: derive the
// wrapping key from the guess (PBKDF2, 310 000 rounds) and try to open the blob.
async function tryPassword(guess, bundle) {
  try {
    await seal.decryptPkcs8(bundle.encPrivKey, bundle.privIv, await seal.wrapKey(guess, bundle.saltWrap));
    return true;
  } catch { return false; }
}

// getBundle is awaited first, so the attack always targets the current secret.
// lockWhile: controls that would change that secret, disabled for the duration.
async function runAttack({ button, out, guesses, getBundle, onWin, explainLoss, lockWhile = [] }) {
  if (S.attacking) return;
  S.attacking = true;
  button.disabled = true;
  lockWhile.forEach((c) => { c.disabled = true; });
  out.className = 'progress';
  try {
    const bundle = await getBundle();
    const started = performance.now();
    let tried = 0;
    let found = null;
    for (const guess of guesses) {
      if (S.act !== Number(button.closest('.power').dataset.for)) break; // the visitor left the step
      out.textContent = `Probando «${guess}»  (${tried + 1} de ${guesses.length})`;
      tried++;
      if (await tryPassword(guess, bundle)) { found = guess; break; }
    }
    const msPerGuess = (performance.now() - started) / Math.max(tried, 1);
    if (found !== null) {
      out.className = 'progress win';
      out.textContent = `Abierta al intento ${tried}. La contraseña era «${found}».`;
      await onWin(found, bundle);
    } else if (tried === guesses.length) {
      out.className = 'progress lose';
      out.textContent = explainLoss(tried, msPerGuess);
    } else {
      out.textContent = '';
    }
  } catch {
    out.className = 'progress';
    out.textContent = 'El ataque se ha interrumpido. Vuelve a lanzarlo.';
  } finally {
    // Whatever happened, the attack controls must come back.
    S.attacking = false;
    button.disabled = false;
    lockWhile.forEach((c) => { c.disabled = false; });
    renderVerdict();
  }
}

$('attackPw').addEventListener('click', () => runAttack({
  button: $('attackPw'),
  out: $('pwProgress'),
  guesses: COMMON_PASSWORDS,
  getBundle: async () => { await S.pwReady; return S.pwBundle; },
  lockWhile: [$('bobPw'), ...document.querySelectorAll('.chip')],
  // Unwrap Bob's key once; live reading then reuses it instead of re-running PBKDF2.
  onWin: async (pw, bundle) => {
    S.crackedKey = await seal.decryptPrivateKey(bundle.encPrivKey, bundle.privIv, await seal.wrapKey(pw, bundle.saltWrap));
    S.cracked = pw;
    await readCrackedMail();
  },
  explainLoss: (n, ms) =>
    `Ninguna de las ${n} funciona. Tu navegador tarda ${Math.round(ms)} ms por intento, porque cada uno ` +
    'repite PBKDF2 310 000 veces. Con 1 000 tarjetas gráficas de gama alta, probar al azar todas las ' +
    `contraseñas como la de Bob llevaría ${humanYears(yearsToSearch(searchSpace(S.bobPassword)))}. ` +
    'Si fuera de diccionario, caería en segundos.',
}));

// ---------- step 5: Bob forgets, recovers with the code; you try to guess it ----------
let originalBobKey = null;

$('forgetBtn').addEventListener('click', async () => {
  S.bobKey = null; S.recovered = false;
  $('recoverBox').hidden = false;
  $('recInput').value = '';
  await renderBob(); renderVerdict();
});
$('noteBtn').addEventListener('click', () => { $('recInput').value = S.recCode; $('recInput').focus(); });
$('recoverBtn').addEventListener('click', async () => {
  const code = seal.normalizeRecoveryCode($('recInput').value);
  const status = $('bobStatus');
  try {
    S.bobKey = await seal.decryptPrivateKey(S.recBundle.encPrivKey, S.recBundle.privIv, await seal.wrapKey(code, S.recBundle.saltWrap));
    S.recovered = true;
    $('recoverBox').hidden = true;
    await renderBob();
    status.textContent = 'Ha vuelto a entrar con su código y conserva todos sus mensajes.';
  } catch {
    status.className = 'status bad';
    status.textContent = 'Ese código no abre nada. Comprueba que está completo.';
  }
  renderVerdict();
});

function randomCodes(n) { return Array.from({ length: n }, () => seal.normalizeRecoveryCode(seal.generateRecoveryCode())); }
$('attackRec').addEventListener('click', () => runAttack({
  button: $('attackRec'),
  out: $('recProgress'),
  guesses: randomCodes(25),
  getBundle: async () => S.recBundle,
  onWin: () => {}, // with 160 bits this does not happen
  explainLoss: (n, ms) =>
    `Ninguno de los ${n} funciona (${Math.round(ms)} ms por intento). El código tiene 160 bits aleatorios: ` +
    `con 1 000 tarjetas gráficas harían falta ${humanYears(yearsToSearch(2 ** 160))}.`,
}));

// ---------- steps ----------
function setAct(n) {
  S.act = n;
  $('lab').dataset.act = String(n);
  document.querySelectorAll('.act').forEach((b) => b.classList.toggle('active', Number(b.dataset.act) === n));
  $('actBrief').textContent = BRIEFS[n];
  if (n !== 3) $('mitm').checked = false;
  if (n !== 5) { S.bobKey = originalBobKey; S.recovered = false; $('recoverBox').hidden = true; }
  $('pwProgress').textContent = ''; $('recProgress').textContent = '';
  $('crackedBox').hidden = true;
  S.cracked = null; S.crackedKey = null;
  try { history.replaceState(null, '', `#paso-${n}`); } catch { /* sandboxed */ }
  pipeline();
}
document.querySelectorAll('.act').forEach((b) => b.addEventListener('click', () => setAct(Number(b.dataset.act))));
$('aliceText').addEventListener('input', schedule);

// ---------- boot ----------
async function boot() {
  try {
    const [bobPair, server] = await Promise.all([seal.generateIdentity(), makeIdentity()]);
    S.server = server;
    const bobPubB64 = await seal.exportPublicKey(bobPair.publicKey);
    S.bob = { pubB64: bobPubB64, pub: await seal.importPublicKey(bobPubB64), fp: await seal.fingerprint(bobPubB64) };
    // Bob's key is kept as raw bytes only so the demo can re-wrap it (see header).
    S.bobPkcs8 = await seal.exportPkcs8(bobPair.privateKey);
    originalBobKey = await seal.importPrivateKey(S.bobPkcs8);
    S.bobKey = originalBobKey;

    $('bobPw').value = randomPassword(12);
    await setBobPassword($('bobPw').value);
    S.recCode = seal.generateRecoveryCode();
    S.recBundle = await seal.secretBundle(seal.normalizeRecoveryCode(S.recCode), S.bobPkcs8);
    $('noteCode').textContent = S.recCode;

    $('aliceText').value = 'Bob: la llave está debajo de la maceta azul. No se lo digas a nadie.';
    $('booting').hidden = true;
    $('stage').hidden = false;
    const fromHash = Number((location.hash.match(/^#paso-([1-5])$/) || [])[1]);
    setAct(fromHash || 1);
  } catch {
    $('booting').textContent = 'Este navegador no permite usar Web Crypto aquí. Prueba con uno actualizado y por https.';
  }
}
boot();
