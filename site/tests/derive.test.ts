import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildEntry,
  compareRelease,
  deriveAll,
  ofnCsv,
  ofnJson,
  ownsRmm,
  pairsCsv,
  releaseKey,
  signatureLabel,
  snippets,
  type Build,
  type Curated,
  type Target,
} from '../src/lib/derive.ts';

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

const entry = (name: string, builds: Build[], target?: Target, shared = new Map<string, string[]>(), curated: Curated = {}) =>
  buildEntry(name, { name, builds }, target, curated, {}, shared);

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

test('a DLL name on an .exe is not called a .NET apphost without evidence', () => {
  const e = entry('w32tm.exe', [build('a', 'w32time.dll', '1809')]);
  assert.deepEqual(e.flags, ['differs-from-name', 'dll-ofn']);
  assert.ok(e.gotchas.every((g) => !g.text.includes('.NET')));
});

test('apphost when curated or build data says so', () => {
  const curated = entry('pwsh.exe', [build('a', 'pwsh.dll', '1809')], undefined, undefined, { notes: 'x'.repeat(20), apphost: true });
  const data = entry('tool.exe', [build('a', 'tool.dll', '1809', { is_apphost: true })]);
  for (const e of [curated, data]) {
    assert.ok(e.flags.includes('apphost') && e.flags.includes('dll-ofn') && e.flags.includes('differs-from-name'));
    assert.ok(e.gotchas.some((g) => g.kind === 'apphost' && g.text.startsWith('.NET apphost')));
  }
});

test('a Sysmon mismatch is surfaced, not dropped', () => {
  const b = build('a', 'cmd.exe', '1809');
  const mismatch = { sysmon_version: '15.22', os_build: '10.0.26100', date: '2026-10-26', sysmon_value: 'Cmd.Exe.MUI', parsed_value: 'cmd.exe' };
  const e = buildEntry('cmd.exe', { name: 'cmd.exe', builds: [b] }, undefined, {}, {}, new Map(), { [b.sha256]: mismatch });
  assert.ok(e.flags.includes('sensor-mismatch'));
  assert.ok(e.gotchas[0].text.includes('`Cmd.Exe.MUI`'));
  assert.equal(e.builds[0].mismatch, true);
});

test('data date comes from the records, not the build clock', () => {
  const rec = (name: string, updated?: string) => ({ name, updated, builds: [build(name[0], name, '1809')] });
  const inp = { targets: {}, curated: {}, verified: {}, coverage: {}, sigmaRelease: null };
  assert.equal(deriveAll({ ...inp, records: [rec('a.exe', '2026-01-02'), rec('b.exe', '2026-03-04'), rec('c.exe')] }).stats.updated, '2026-03-04');
  assert.equal(deriveAll({ ...inp, records: [rec('a.exe')] }).stats.updated, null);
});

test('unknown release labels sort first instead of throwing', () => {
  assert.deepEqual(releaseKey('LTSC'), [10, 0]);
  assert.ok(compareRelease('LTSC', '1507') < 0);
});

test('signature label', () => {
  assert.equal(signatureLabel({ signing_status: 'Signed', signature_type: 'catalog' }), 'Signed (catalog)');
  assert.equal(signatureLabel({ signing_status: 'Unsigned' }), 'Unsigned');
  assert.equal(signatureLabel({ signing_status: 'Unknown' }), '');
  assert.equal(signatureLabel({}), '');
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
  assert.ok(e.gotchas.some((g) => g.text.includes('Overlord')));
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

test('double-quoted snippets escape backslashes and quotes', () => {
  const s = snippets('x.exe', ['a\\b"c.exe']);
  for (const key of ['kql', 'eql', 'splunk']) assert.ok(s[key].includes('"a\\\\b\\"c.exe"'), key);
});

test('sigma snippets are complete process_creation rules', () => {
  for (const s of [snippets('cmd.exe', ['Cmd.Exe']), snippets('pcalua.exe', [])]) {
    assert.ok(s.sigma.includes('logsource:\n  category: process_creation\n  product: windows\ndetection:'));
  }
});

test('splunk never groups by OriginalFilename, so builds without one still return', () => {
  for (const s of [snippets('taskmgr.exe', ['Taskmgr.exe']), snippets('pcalua.exe', [])]) {
    const by = s.splunk.split('\n').find((l) => l.trim().startsWith('by '))!;
    assert.ok(!by.includes('original_file_name'));
    assert.ok(by.includes('Processes.process_path'));
  }
});

test('a Sigma literal no build carries becomes a gotcha; a carried one does not', () => {
  const rec = { name: 'psexec.exe', builds: [build('a', 'psexec.c', '1809')] };
  const e = buildEntry('psexec.exe', rec, undefined, {}, {}, new Map(), {}, { value: 'PsExec.exe', rules: 2 });
  assert.ok(e.flags.includes('sigma-mismatch'));
  assert.ok(e.gotchas.some((g) => g.kind === 'sigma-mismatch' && g.text.includes('2 SigmaHQ rules') && g.text.includes('`psexec.c`')));
  const ok = buildEntry('wmic.exe', { name: 'wmic.exe', builds: [build('a', 'wmic.exe', '1809')] }, undefined, {}, {}, new Map(), {}, { value: 'WMIC.exe', rules: 11 });
  assert.ok(!ok.flags.includes('sigma-mismatch'));
});

test('deriveAll matches Sigma literals to names case-insensitively and merges case variants', () => {
  const inp = {
    records: [{ name: 'pcalua.exe', builds: [build('a', null, '1809')] }],
    targets: {}, curated: {}, verified: {}, coverage: {}, sigmaRelease: null,
    sigmaValues: { 'Pcalua.exe': 1, 'PCALUA.EXE': 1 },
  };
  const e = deriveAll(inp).entries[0];
  assert.ok(e.flags.includes('sigma-mismatch'));
  assert.ok(e.gotchas.some((g) => g.text.includes('2 SigmaHQ rules') && g.text.includes('no observed build')));
});

test('ofn.json URLs come from the caller, so the deployed base path is never lost', () => {
  const e = entry('cmd.exe', [build('a', 'Cmd.Exe', '1809')]);
  const out = JSON.parse(ofnJson([e], (slug) => `https://example.github.io/ofndb/b/${slug}/`));
  assert.equal(out[0].url, 'https://example.github.io/ofndb/b/cmd.exe/');
});

test('csv quotes fields that need it', () => {
  assert.equal(pairsCsv([['a,b', 'c"d']]), 'original_filename,image_name\n"a,b","c""d"\n');
});

test('csv defuses formula-leading values without touching normal ones', () => {
  assert.equal(pairsCsv([['=2+5', 'cmd.exe']]), "original_filename,image_name\n'=2+5,cmd.exe\n");
  assert.equal(pairsCsv([['cmd.exe', 'cmd.exe']]), 'original_filename,image_name\ncmd.exe,cmd.exe\n');
});

test('ownsRmm matches tool and product at token level, not by substring', () => {
  const vendor = (product: string): Build[] => [build('a', null, '', { sources: ['vendor'], product, windows_versions: [] })];
  assert.ok(ownsRmm(vendor('AnyDesk MSI'), [{ tool: 'AnyDesk', claimed_original_filename: null }]));
  // substring would own this: "netsupport manager".includes("net") — tokens must not
  assert.ok(!ownsRmm(vendor('Net Framework'), [{ tool: 'NetSupport Manager', claimed_original_filename: null }]));
  assert.ok(!ownsRmm(vendor(''), [{ tool: 'AnyDesk', claimed_original_filename: null }]));
});

test('sigma literals matching no record name or carried value become orphans', () => {
  const inp = {
    records: [{ name: 'psexec.exe', builds: [build('a', 'psexec.c', '1809')] }],
    targets: {}, curated: {}, verified: {}, coverage: {}, sigmaRelease: null,
    sigmaValues: { 'psexec.c': 3, 'psexec.exe': 2, 'PsExeSvc.exe': 2, 'psexesvc.exe': 1 },
  };
  const { sigmaOrphans } = deriveAll(inp);
  // carried value and record name both vouch; the orphan merges its case variants
  assert.deepEqual(sigmaOrphans, [{ value: 'PsExeSvc.exe', rules: 3, refs: [] }]);
});

test('Sigma rule refs merge across case variants and name the rules in the gotcha', () => {
  const rule = (title: string) => ({ id: null, title, path: `rules/windows/${title}.yml` });
  const inp = {
    records: [{ name: 'pcalua.exe', builds: [build('a', null, '1809')] }],
    targets: {}, curated: {}, verified: {}, coverage: {}, sigmaRelease: 'r2026-07-01',
    sigmaValues: { 'Pcalua.exe': 1, 'PCALUA.EXE': 2 },
    sigmaRules: { 'Pcalua.exe': [rule('A')], 'PCALUA.EXE': [rule('A'), rule('B')] },
  };
  const g = deriveAll(inp).entries[0].gotchas.find((x) => x.kind === 'sigma-mismatch')!;
  assert.ok(g.text.endsWith('Rules: "A", "B".'), g.text);
});

test('a padded value gets its own gotcha, not differs-from-name, and snippets match both spellings', () => {
  const padded = 'WEXTRACT.EXE            ';
  const rec = { name: 'wextract.exe', builds: [build('a', padded, '1809')] };
  const e = buildEntry('wextract.exe', rec, undefined, {}, { ['a'.repeat(64)]: { sysmon_version: '15', os_build: 'x', date: 'd' } }, new Map());
  assert.ok(e.flags.includes('padded-ofn') && !e.flags.includes('differs-from-name'));
  assert.ok(e.gotchas.some((g) => g.text.includes('padded with 12 spaces, and Sysmon logs the padding verbatim')));
  assert.ok(e.snippets.kql.includes(`"${padded}"`) && e.snippets.kql.includes('"WEXTRACT.EXE"'));
});

test('another language table with a different value is flagged', () => {
  const e = entry('x.exe', [build('a', 'x.exe', '1809', { other_table_original_filenames: ['y.exe'] })]);
  assert.ok(e.flags.includes('multi-table'));
  assert.ok(e.gotchas.some((g) => g.kind === 'multi-table' && g.text.includes('`y.exe`')));
});

test('ofn.csv has one row per value, empty for none', () => {
  const e = entry('setup.exe', [build('a', 'SETUP.EXE', '1809'), build('b', null, '1809')]);
  const rows = ofnCsv([e]).trim().split('\n');
  assert.equal(rows.length, 3);
  assert.ok(rows.some((r) => r.startsWith('setup.exe,SETUP.EXE,1,')));
  assert.ok(rows.some((r) => r.startsWith('setup.exe,,1,')));
});

test('a build from an RMM installer (source rmm) is categorized rmm', () => {
  const e = entry('tvnserver.exe', [build('a', 'tvnserver.exe', '', { sources: ['rmm'], windows_versions: [] })]);
  assert.ok(e.categories.includes('rmm'));
  const win = entry('svchost.exe', [build('a', 'svchost.exe', '1809', { sources: ['winbindex'] })]);
  assert.ok(!win.categories.includes('rmm'));
});
