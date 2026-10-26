import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildEntry, compareRelease, ownsRmm, pairsCsv, snippets, type Build, type Target } from '../src/lib/derive.ts';

const build = (sha: string, ofn: string | null, winver: string, extra: Partial<Build> = {}): Build => ({
  sha256: sha.repeat(64).slice(0, 64),
  machine: 'x64',
  original_filename: ofn,
  has_version_resource: true,
  fixed_file_version: '10.0.1.0',
  windows_versions: [winver],
  last_seen: '2025-01-01',
  sources: ['winbindex'],
  ...extra,
});

const entry = (name: string, builds: Build[], target?: Target, shared = new Map<string, string[]>()) =>
  buildEntry(name, { name, builds }, target, {}, {}, shared);

test('Windows releases sort chronologically, Win10 before Win11', () => {
  const order = ['11-26H1', '1507', '20H2', '11-21H2', '1809', '22H2'];
  assert.deepEqual([...order].sort(compareRelease), ['1507', '1809', '20H2', '22H2', '11-21H2', '11-26H1']);
});

test('drift is flagged and every value reaches every snippet', () => {
  const e = entry('nltest.exe', [build('a', 'nltestrk.exe', '1809'), build('b', 'nltest.exe', '11-26H1')]);
  assert.ok(e.flags.includes('drift'));
  for (const s of Object.values(e.snippets)) {
    assert.ok(s.includes('nltestrk.exe'));
    assert.ok(s.toLowerCase().includes('nltest.exe'));
  }
});

test('case-only drift collapses in snippets', () => {
  const e = entry('taskmgr.exe', [build('a', 'Taskmgr.exe', '1809'), build('b', 'taskmgr.exe', '11-26H1')]);
  assert.deepEqual(e.flags, ['case-drift']);
  assert.equal(e.snippets.kql.match(/askmgr\.exe/g)?.length, 2); // one OFN value + the FileName clause
});

test('apphost and differs-from-name', () => {
  const e = entry('pwsh.exe', [build('a', 'pwsh.dll', '1809')]);
  assert.ok(e.flags.includes('apphost') && e.flags.includes('differs-from-name'));
});

test('no OFN falls back to the image name', () => {
  const e = entry('pcalua.exe', [build('a', null, '11-24H2')]);
  assert.deepEqual(e.flags, ['no-ofn']);
  assert.ok(!e.snippets.kql.includes('OriginalFileName'));
  assert.ok(e.snippets.kql.includes('pcalua.exe'));
});

test('a LOLRMM file-name collision with a Microsoft binary is not an RMM', () => {
  const target: Target = { sources: ['lolrmm', 'sigma'], lolrmm: [{ tool: 'Overlord', claimed_original_filename: null }] };
  const e = entry('svchost.exe', [build('a', 'svchost.exe', '11-24H2', { company_name: 'Microsoft Corporation' })], target);
  assert.ok(!e.categories.includes('rmm'));
  assert.ok(e.flags.includes('rmm-name-collision'));
  assert.ok(e.gotchas.some((g) => g.includes('Overlord')));
});

test('a vendor build of the tool is the RMM, and its claim is checked', () => {
  const target: Target = { sources: ['lolrmm'], lolrmm: [{ tool: 'AnyDesk', claimed_original_filename: 'AnyDesk.exe' }] };
  const builds = [build('a', null, '', { sources: ['vendor'], product: 'AnyDesk', windows_versions: [] })];
  assert.ok(ownsRmm(builds, target.lolrmm!));
  const e = entry('anydesk.exe', builds, target);
  assert.deepEqual(e.categories, ['rmm']);
  assert.ok(e.flags.includes('lolrmm-mismatch'));
  assert.ok(!e.flags.includes('rmm-name-collision'));
});

test('sigma snippet escapes single quotes', () => {
  assert.ok(snippets("o'neil.exe", ["O'Neil.exe"]).sigma.includes("'O''Neil.exe'"));
});

test('csv quotes fields that need it', () => {
  assert.equal(pairsCsv([['a,b', 'c"d']]), 'original_filename,image_name\n"a,b","c""d"\n');
});
