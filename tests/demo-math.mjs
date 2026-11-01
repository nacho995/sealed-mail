// Unit tests for the demo's attack arithmetic (demo/attack-math.js): the numbers the
// demo shows visitors must be right, and the password generator must be unbiased.
//   node --test tests/demo-math.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ES module in a CommonJS package: load the exact file through a data: URL.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = fs.readFileSync(path.join(root, 'demo/attack-math.js'), 'utf8');
const m = await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));

test('randomPassword has the requested length and only uses the 62-symbol alphabet', () => {
  for (const len of [1, 12, 40]) {
    const pw = m.randomPassword(len);
    assert.equal(pw.length, len);
    assert.match(pw, /^[a-zA-Z0-9]+$/);
  }
});

test('randomPassword is not visibly biased (rejection sampling)', () => {
  // 62 000 symbols, ~1 000 per symbol expected. Modulo bias without rejection would
  // over-represent the first 8 symbols by ~25%; allow +-20% for sampling noise.
  const counts = new Map();
  for (const ch of m.randomPassword(62_000)) counts.set(ch, (counts.get(ch) || 0) + 1);
  assert.equal(counts.size, 62, 'every symbol appears');
  for (const [ch, n] of counts) assert.ok(n > 800 && n < 1200, `symbol ${ch} appeared ${n} times`);
});

test('searchSpace counts the character classes a password uses', () => {
  assert.equal(m.searchSpace('abc'), 26 ** 3);
  assert.equal(m.searchSpace('aB'), 52 ** 2);
  assert.equal(m.searchSpace('aB3'), 62 ** 3);
  assert.equal(m.searchSpace('a!'), (26 + 33) ** 2);
});

test('yearsToSearch matches the hand calculation shown in the README', () => {
  // 62^12 / 2 guesses at 3e4/s on each of 1 000 GPUs ~ 1.7 million years
  const years = m.yearsToSearch(62 ** 12);
  assert.ok(years > 1.6e6 && years < 1.8e6, `got ${years}`);
});

test('humanYears picks the right unit at every scale', () => {
  assert.equal(m.humanYears(0.0001), 'menos de un día');
  assert.equal(m.humanYears(0.5), 'unos 183 días');
  assert.match(m.humanYears(1.7e6), /^unos 1,7 millones de años$/);
  assert.match(m.humanYears(3e9), /miles de millones de años$/);
  // the 160-bit recovery code: ~7.7e32 years, rounded to 10^33
  assert.match(m.humanYears(m.yearsToSearch(2 ** 160)), /^unos 10³³ años/);
});

test('the dictionary contains the passwords the demo offers as weak examples', () => {
  for (const weak of ['123456', 'verano2024']) assert.ok(m.COMMON_PASSWORDS.includes(weak), weak);
});
