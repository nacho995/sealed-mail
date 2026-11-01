// Pure helpers behind the demo's attack steps: no DOM, so tests/demo-math.mjs can
// check them in Node.

// Unbiased random password from a 62-symbol alphabet: bytes >= 248 are rejected so
// every symbol keeps the same probability (248 = 4 x 62).
export const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
export function randomPassword(len) {
  let out = '';
  while (out.length < len) {
    for (const b of crypto.getRandomValues(new Uint8Array(len))) {
      if (b < 248 && out.length < len) out += ALNUM[b % 62];
    }
  }
  return out;
}

// A short public list in the spirit of the usual "most common passwords" rankings,
// plus a few Spanish favourites.
export const COMMON_PASSWORDS = [
  '123456', '123456789', '12345678', 'password', 'qwerty', '12345', '1234567890', '111111', '1234567',
  'abc123', 'password1', 'iloveyou', '000000', 'qwerty123', 'admin', 'welcome', 'monkey', 'dragon',
  'football', 'letmein', 'sunshine', 'princess', 'contraseña', 'españa', 'barcelona', 'madrid',
  'realmadrid', 'tequiero', 'verano2023', 'verano2024', 'hola1234', 'qwertyuiop', '654321',
  'superman', 'starwars', 'pokemon', 'master', 'shadow', 'bob123', 'Bob1990!',
];

// Order-of-magnitude reference for an offline attacker: hashcat's PBKDF2-HMAC-SHA256
// benchmark on one RTX 4090, scaled to our 310 000 iterations, is in the tens of
// thousands of guesses per second. Used only for the "how long would it take" text.
export const GPU_GUESSES_PER_SEC = 3e4;
export const GPUS = 1000;
const SECONDS_PER_YEAR = 3.156e7;

// Naive search space if the password were random over the character classes it uses.
export function searchSpace(pw) {
  let alphabet = 0;
  if (/[a-z]/.test(pw)) alphabet += 26;
  if (/[A-Z]/.test(pw)) alphabet += 26;
  if (/[0-9]/.test(pw)) alphabet += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) alphabet += 33;
  return Math.pow(Math.max(alphabet, 1), pw.length);
}

// Expected years to find the secret: on average half the space, at GPUS x GPU rate.
export function yearsToSearch(space) {
  return space / 2 / (GPU_GUESSES_PER_SEC * GPUS) / SECONDS_PER_YEAR;
}

const numFmt = new Intl.NumberFormat('es', { maximumFractionDigits: 1 });
const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹';
export function humanYears(years) {
  if (years < 1 / 365) return 'menos de un día';
  if (years < 1) return `unos ${Math.round(years * 365)} días`;
  if (years < 1e6) return `unos ${numFmt.format(years)} años`;
  if (years < 1e9) return `unos ${numFmt.format(years / 1e6)} millones de años`;
  if (years < 1e12) return `unos ${numFmt.format(years / 1e9)} miles de millones de años`;
  const exp = String(Math.round(Math.log10(years))).replace(/\d/g, (d) => SUP[d]);
  return `unos 10${exp} años (el universo tiene unos 1,4·10¹⁰)`;
}
