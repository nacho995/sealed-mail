// Assembles the static "play the server" demo into _site/ for GitHub Pages.
// The demo imports the app's crypto module and stylesheet unchanged, so what
// visitors attack is exactly the code the app ships.
//
//   node demo/build.mjs      -> _site/ (gitignored)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, '_site');
const copy = (from, to) => fs.cpSync(path.join(root, from), path.join(out, to), { recursive: true });

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out);
copy('demo/index.html', 'index.html');
copy('demo/demo.css', 'demo.css');
copy('demo/demo.js', 'demo.js');
copy('demo/attack-math.js', 'attack-math.js');
copy('public/css/styles.css', 'css/styles.css');
copy('public/js/crypto.js', 'js/crypto.js');
copy('public/fonts', 'fonts');
fs.writeFileSync(path.join(out, '.nojekyll'), ''); // serve files as-is, no Jekyll processing

console.log(`demo built into ${path.relative(root, out)}/`);
