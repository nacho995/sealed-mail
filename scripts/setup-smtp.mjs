// Connects Sealed Mail to a real outgoing mail server, so mail to outside addresses is
// actually delivered without owning a domain. Asks for the secret without echoing it,
// checks it with the provider over TLS, and only then writes the SMTP settings into
// .env (file mode 600). Run it in your own terminal:
//
//   npm run setup:gmail       your own Gmail account, with an app password
//   npm run setup:sendgrid    SendGrid, with an API key and a verified single sender
//
// The secret is only ever typed here and stored in .env, which git ignores.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = process.env.ENV_FILE || path.join(root, '.env');
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Each provider: what to tell the user first, how to recognise its secret, and the SMTP
// settings that secret goes with. Both use port 587 with mandatory STARTTLS.
const PROVIDERS = {
  gmail: {
    name: 'Gmail',
    intro: [
      'Antes, en tu cuenta de Google:',
      '  1. Activa la verificación en dos pasos (myaccount.google.com/security).',
      '  2. Crea una contraseña de aplicación en myaccount.google.com/apppasswords',
      '     y cópiala: son 16 letras.',
      '',
      'Ojo: esa contraseña no sirve solo para enviar, también abre todo ese buzón.',
      'Quien lea el .env de este servidor podría leer tus correos de Gmail. Lo más',
      'seguro es usar una cuenta de Gmail creada solo para esto.',
    ],
    addressPrompt: 'Tu dirección de Gmail: ',
    secretPrompt: 'Contraseña de aplicación (no se verá al escribir): ',
    // Google shows it as four groups of four letters; spaces are only presentation.
    normalize: (s) => s.replace(/\s+/g, '').toLowerCase(),
    valid: (s) => /^[a-z]{16}$/.test(s),
    invalidMsg: 'Eso no parece una contraseña de aplicación de Google (son 16 letras).',
    rejectedMsg: 'Revisa la dirección y la contraseña de aplicación, y que la verificación en dos pasos esté activa.',
    settings: (address, secret) => ({ host: 'smtp.gmail.com', port: 587, user: address, pass: secret }),
  },
  sendgrid: {
    name: 'SendGrid',
    intro: [
      'Antes, en SendGrid:',
      '  1. Settings > Sender Authentication > Single Sender Verification: verifica una dirección tuya.',
      '  2. Settings > API Keys > Create API Key, con el permiso "Mail Send". Cópiala.',
    ],
    addressPrompt: 'Dirección que verificaste en SendGrid: ',
    secretPrompt: 'Clave de API de SendGrid (no se verá al escribir): ',
    normalize: (s) => s.trim(),
    valid: (s) => /^SG\.[\w-]{10,}\.[\w-]{10,}$/.test(s),
    invalidMsg: 'Eso no parece una clave de SendGrid (empiezan por "SG.").',
    rejectedMsg: 'Revisa la clave y su permiso "Mail Send".',
    settings: (_address, secret) => ({ host: 'smtp.sendgrid.net', port: 587, user: 'apikey', pass: secret }),
  },
};

const provider = PROVIDERS[process.argv[2]];
if (!provider) {
  console.error(`Uso: node scripts/setup-smtp.mjs <${Object.keys(PROVIDERS).join('|')}>`);
  process.exit(1);
}

// Line input that works the same typed in a terminal or piped in. Only a real
// terminal echoes keystrokes, so only there is the echo muted while the secret is typed.
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: Boolean(process.stdin.isTTY) });
let muted = false;
rl._writeToOutput = (s) => { if (!muted) rl.output.write(s); };
const queued = [];
const waiting = [];
let closed = false;
rl.on('line', (line) => { const w = waiting.shift(); if (w) w(line); else queued.push(line); });
rl.on('close', () => { closed = true; while (waiting.length) waiting.shift()(''); });
const nextLine = () => (queued.length ? Promise.resolve(queued.shift())
  : closed ? Promise.resolve('') : new Promise((resolve) => waiting.push(resolve)));

async function ask(q) {
  process.stdout.write(q);
  return nextLine();
}
async function askSecret(q) {
  process.stdout.write(q);
  muted = true;
  const answer = await nextLine();
  muted = false;
  process.stdout.write('\n');
  return answer;
}
function fail(msg) {
  console.error(`${msg} No he cambiado nada.`);
  process.exit(1);
}

console.log(`\nConectar Sealed Mail con ${provider.name}\n`);
console.log(provider.intro.join('\n') + '\n');

const address = (await ask(provider.addressPrompt)).trim().toLowerCase();
if (!EMAIL.test(address)) fail('Esa dirección no es válida.');
const secret = provider.normalize(await askSecret(provider.secretPrompt));
if (!provider.valid(secret)) fail(provider.invalidMsg);

const { host, port, user, pass } = provider.settings(address, secret);
const transportOptions = { host, port, secure: false, requireTLS: true, auth: { user, pass } };

// Log in to the relay over TLS without sending anything, before touching .env.
process.stdout.write(`Comprobando con ${provider.name}... `);
try {
  await nodemailer.createTransport(transportOptions).verify();
  console.log('correcto.');
} catch (err) {
  console.log('');
  fail(`${provider.name} lo ha rechazado (${err.responseCode || err.code || 'error'}). ${provider.rejectedMsg}`);
}

// Replace any previous outbound settings in .env, keep everything else.
const OUT_KEYS = ['SMTP_OUT_HOST', 'SMTP_OUT_PORT', 'SMTP_OUT_SECURE', 'SMTP_OUT_USER', 'SMTP_OUT_PASS', 'SMTP_OUT_FROM'];
const current = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
const kept = current.split('\n').filter((line) => !OUT_KEYS.some((k) => line.startsWith(`${k}=`)));
while (kept.length && kept[kept.length - 1] === '') kept.pop();
kept.push('', `# Outgoing mail through ${provider.name} (written by npm run setup:${process.argv[2]})`,
  `SMTP_OUT_HOST=${host}`, `SMTP_OUT_PORT=${port}`, `SMTP_OUT_USER=${user}`,
  `SMTP_OUT_PASS=${pass}`, `SMTP_OUT_FROM=${address}`, '');
fs.writeFileSync(envPath, kept.join('\n'), { mode: 0o600 });
fs.chmodSync(envPath, 0o600);
console.log(`Guardado en ${path.relative(root, envPath) || envPath} (solo legible por ti).`);

const test = (await ask(`\n¿Te mando un correo de prueba a ${address}? (s/n) `)).trim().toLowerCase();
if (['s', 'si', 'sí'].includes(test)) {
  try {
    await nodemailer.createTransport(transportOptions).sendMail({
      from: address, to: address, subject: 'Sealed Mail ya puede enviar correo',
      text: `Si lees esto, Sealed Mail está conectado a ${provider.name} y puede escribir a cualquier dirección.`,
    });
    console.log('Enviado. Míralo en tu bandeja (y en spam, por si acaso).');
  } catch (err) {
    const why = /verified Sender/i.test(err.response || '')
      ? 'esa dirección aún no está verificada en SendGrid (mira tu correo y pulsa el enlace de verificación)'
      : (err.response || err.message);
    console.error(`No se ha podido enviar: ${why}`);
  }
}
console.log(`\nListo. Reinicia la app (Ctrl+C y npm start) para que use ${provider.name}.`);
rl.close();
