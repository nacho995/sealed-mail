// Connects Sealed Mail to SendGrid so mail to outside addresses is really delivered.
// Asks for the API key without echoing it, writes the SMTP settings into .env (file
// mode 600), and checks with SendGrid that the key works. Run it in your own terminal:
//
//   npm run setup:sendgrid
//
// The key is only ever typed here and stored in .env, which git ignores.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = process.env.ENV_FILE || path.join(root, '.env');

// Line input that works the same typed in a terminal or piped in. Only a real
// terminal echoes keystrokes, so only there is the echo muted while the key is typed.
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
  return answer.trim();
}

console.log('\nConectar Sealed Mail con SendGrid\n');
console.log('Antes, en SendGrid:');
console.log('  1. Settings > Sender Authentication > Single Sender Verification: verifica una dirección tuya.');
console.log('  2. Settings > API Keys > Create API Key, con el permiso "Mail Send". Cópiala.\n');

const from = (await ask('Dirección que verificaste en SendGrid: ')).trim().toLowerCase();
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(from)) { console.error('Esa dirección no es válida.'); process.exit(1); }
const key = await askSecret('Clave de API de SendGrid (no se verá al escribir): ');
if (!/^SG\.[\w-]{10,}\.[\w-]{10,}$/.test(key)) {
  console.error('Eso no parece una clave de SendGrid (empiezan por "SG."). No he cambiado nada.');
  process.exit(1);
}

// Check the key with SendGrid before touching .env: log in to the SMTP relay over TLS
// without sending anything.
const settings = { host: 'smtp.sendgrid.net', port: 587, secure: false, requireTLS: true, auth: { user: 'apikey', pass: key } };
process.stdout.write('Comprobando la clave con SendGrid... ');
try {
  await nodemailer.createTransport(settings).verify();
  console.log('correcta.');
} catch (err) {
  console.log('');
  console.error(`SendGrid la ha rechazado (${err.responseCode || err.code || 'error'}). Revisa la clave y su permiso "Mail Send". No he cambiado nada.`);
  process.exit(1);
}

// Replace any previous outbound settings in .env, keep everything else.
const OUT_KEYS = ['SMTP_OUT_HOST', 'SMTP_OUT_PORT', 'SMTP_OUT_SECURE', 'SMTP_OUT_USER', 'SMTP_OUT_PASS', 'SMTP_OUT_FROM'];
const current = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
const kept = current.split('\n').filter((line) => !OUT_KEYS.some((k) => line.startsWith(`${k}=`)));
while (kept.length && kept[kept.length - 1] === '') kept.pop();
kept.push('', '# Outgoing mail through SendGrid (written by npm run setup:sendgrid)',
  'SMTP_OUT_HOST=smtp.sendgrid.net', 'SMTP_OUT_PORT=587', 'SMTP_OUT_USER=apikey',
  `SMTP_OUT_PASS=${key}`, `SMTP_OUT_FROM=${from}`, '');
fs.writeFileSync(envPath, kept.join('\n'), { mode: 0o600 });
fs.chmodSync(envPath, 0o600);
console.log(`Guardado en ${path.relative(root, envPath) || envPath} (solo legible por ti).`);

const test = (await ask(`\n¿Te mando un correo de prueba a ${from}? (s/n) `)).trim().toLowerCase();
if (test === 's' || test === 'si' || test === 'sí') {
  try {
    await nodemailer.createTransport(settings).sendMail({
      from, to: from, subject: 'Sealed Mail ya puede enviar correo',
      text: 'Si lees esto, Sealed Mail está conectado a SendGrid y puede escribir a cualquier dirección.',
    });
    console.log('Enviado. Míralo en tu bandeja (y en spam, por si acaso).');
  } catch (err) {
    const why = /verified Sender/i.test(err.response || '') ? 'esa dirección aún no está verificada en SendGrid (mira tu correo y pulsa el enlace de verificación)' : (err.response || err.message);
    console.error(`No se ha podido enviar: ${why}`);
  }
}
console.log('\nListo. Reinicia la app (Ctrl+C y npm start) para que use SendGrid.');
rl.close();
