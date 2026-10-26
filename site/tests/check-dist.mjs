// Checks the built site (dist/) without a browser: known values on known
// pages, exports, rendering leaks, and that every internal link resolves.
//   npm run build && npm run check
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const BASE = (process.env.BASE_PATH || '/').replace(/\/?$/, '/');
let failures = 0;
const fail = (msg) => { failures++; console.error(`FAIL ${msg}`); };
// <wbr> break hints are invisible; match on the text a reader sees
const read = (p) => readFileSync(join(DIST, p), 'utf8').replace(/<wbr>/g, '');

function expectPage(path, needles) {
  const file = join(path, 'index.html');
  if (!existsSync(join(DIST, file))) return fail(`${file} missing`);
  const html = read(file);
  for (const n of needles) if (!html.includes(n)) fail(`${file} lacks ${JSON.stringify(n)}`);
}

// known answers (all Sysmon-confirmed or parsed from the binary)
expectPage('', ['Cmd.Exe', 'pwsh.dll', 'psexec.c']);
expectPage('b/cmd.exe', ['Cmd.Exe', 'Sysmon-confirmed', "OriginalFileName: 'Cmd.Exe'"]);
expectPage('b/powershell.exe', ['PowerShell.EXE']);
expectPage('b/pwsh.exe', ['pwsh.dll', '.NET apphost']);
// a DLL name on a native Windows binary is not a .NET apphost
for (const n of ['w32tm.exe', 'msinfo32.exe', 'wmiadap.exe']) {
  expectPage(`b/${n}`, ['Names a DLL']);
  if (read(join('b', n, 'index.html')).includes('.NET apphost')) fail(`b/${n} is called a .NET apphost`);
}
expectPage('b/cmd.exe', ['rel="canonical"', 'Signature', 'logsource:']);
expectPage('', ['Data updated 20']);
expectPage('b/nltest.exe', ['nltestrk.exe', 'nltest.exe', 'Value changed across builds', 'in~ (&quot;nltestrk.exe&quot;, &quot;nltest.exe&quot;)']);
expectPage('b/tar.exe', ['bsdtar']);
expectPage('b/psexec.exe', ['psexec.c']);
expectPage('b/procmon.exe', ['Process Monitor']);
expectPage('b/mavinject.exe', ['mavinject32.exe', 'mavinject64.exe']);
expectPage('b/pcalua.exe', ['No observed build carries an OriginalFilename']);
expectPage('b/anydesk.exe', ['LOLRMM lists']);
expectPage('gotchas', ['Cmd.Exe.MUI', 'PowerShell.EXE.MUI', 'nltest.exe']);
expectPage('lookups', ['ofn_pairs.csv', 'join kind=leftanti', 'nltestrk.exe']);
// Windows binaries whose names LOLRMM tools reuse must not be labelled RMM
for (const n of ['svchost.exe', 'setup.exe', 'dwm.exe']) {
  expectPage(`b/${n}`, ['Name reused by an RMM tool']);
  if (read(join('b', n, 'index.html')).includes('cat-rmm')) fail(`b/${n} is labelled RMM`);
}
for (const gone of ['rename', 'search', 'exports']) {
  if (existsSync(join(DIST, gone, 'index.html'))) fail(`retired page /${gone}/ still built`);
}

const index = read('index.html');
const rows = (index.match(/<tr data-s=/g) || []).length;
if (rows < 1000) fail(`index has only ${rows} rows`);

// long names must carry break points, or they overflow multi-column lists (gotchas page)
const rawGotchas = readFileSync(join(DIST, 'gotchas', 'index.html'), 'utf8');
if (!rawGotchas.includes('microsoft.<wbr>data.<wbr>usageandqualityinsights.<wbr>')) fail('long names on /gotchas/ have no break points');

// exports
const csv = read('exports/ofn.csv');
for (const line of ['cmd.exe,Cmd.Exe,', 'psexec.exe,psexec.c,', 'nltest.exe,nltestrk.exe,']) {
  if (!csv.includes(line)) fail(`ofn.csv lacks ${line}`);
}
const pairs = read('exports/ofn_pairs.csv');
for (const line of ['original_filename,image_name', 'psexec.c,psexec.exe', 'nltestrk.exe,nltest.exe', 'pwsh.dll,pwsh.exe']) {
  if (!pairs.includes(line)) fail(`ofn_pairs.csv lacks ${line}`);
}
if (!read('exports/ofn_pairs.kql').includes('datatable(ofn: string, img: string)')) fail('ofn_pairs.kql malformed');
JSON.parse(read('exports/ofn.json'));
if (!existsSync(join(DIST, '404.html'))) fail('404.html missing');
const sitemap = read('sitemap.xml');
if (!sitemap.includes(`${BASE}b/cmd.exe/</loc>`) || (sitemap.match(/<url>/g) || []).length < rows) fail('sitemap.xml incomplete');

// every page: no rendering leaks, every internal link resolves
const pages = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (name.endsWith('.html')) pages.push(p);
  }
};
walk(DIST);
const broken = new Set();
for (const p of pages) {
  const html = readFileSync(p, 'utf8');
  for (const leak of ['>undefined<', '>NaN<', '[object Object]', '>null<']) {
    if (html.includes(leak)) fail(`${relative(DIST, p)} contains ${leak}`);
  }
  for (const [, url] of html.matchAll(/href="([^"#?]+)[^"]*"/g)) {
    if (!url.startsWith(BASE) || url.startsWith('//')) continue;
    const rel = decodeURIComponent(url.slice(BASE.length));
    const target = join(DIST, rel);
    const ok = rel === '' || existsSync(rel.endsWith('/') ? join(target, 'index.html') : target);
    if (!ok) broken.add(url);
  }
}
for (const b of [...broken].slice(0, 20)) fail(`broken link ${b}`);

console.log(`${pages.length} pages, ${rows} index rows checked; ${failures ? `${failures} failure(s)` : 'all good'}`);
process.exit(failures ? 1 : 0);
