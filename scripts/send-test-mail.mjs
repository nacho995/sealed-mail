// Simulates someone outside Sealed Mail (say, a Gmail user) writing to one of your
// addresses: it delivers an ordinary email to the app's inbound SMTP port, exactly as
// another mail server would.
//
//   npm run mail:test -- nombre@sealed.local ["Asunto"] ["Texto"]
import nodemailer from 'nodemailer';

const [to, subject = 'Hola desde fuera', text = 'Este correo viene de fuera de Sealed Mail.'] = process.argv.slice(2);
if (!to) {
  console.error('Uso: npm run mail:test -- nombre@sealed.local ["Asunto"] ["Texto"]');
  process.exit(1);
}
const from = process.env.FROM || 'amiga@gmail.com';
const port = Number(process.env.SMTP_IN_PORT) || 2525;

const transport = nodemailer.createTransport({ host: '127.0.0.1', port, secure: false, ignoreTLS: true });
try {
  await transport.sendMail({ from, to, subject, text });
  console.log(`Entregado: ${from} -> ${to} («${subject}»). Míralo en tu bandeja de entrada.`);
} catch (err) {
  console.error(`No se ha podido entregar: ${err.response || err.message}`);
  process.exit(1);
}
