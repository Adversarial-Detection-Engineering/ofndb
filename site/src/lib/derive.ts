// Everything the site shows is derived here from the committed data: categories,
// gotchas, query snippets, lookup pairs, export files. Pure functions with no fs
// and no Astro, so the build and `node --test` run the same code.

export interface Build {
  sha256: string;
  machine: string;
  original_filename: string | null;
  has_version_resource?: boolean;
  internal_name?: string | null;
  file_description?: string | null;
  company_name?: string | null;
  product_name?: string | null;
  fixed_file_version?: string | null;
  windows_versions?: string[];
  os_builds?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  sources: string[];
  download_url?: string;
  product?: string;
  vendor?: string;
  signing_status?: string;
  signature_type?: string;
  /** Set only when the build was identified as a .NET apphost launcher. */
  is_apphost?: boolean;
}
export interface DataRecord {
  name: string;
  updated?: string;
  builds: Build[];
  gaps?: unknown[];
}
export interface LolrmmClaim {
  tool: string;
  claimed_original_filename: string | null;
  description?: string | null;
  product?: string | null;
}
export interface Target {
  sources: string[];
  lolbas?: { url: string; category: string; paths: string[] };
  lolrmm?: LolrmmClaim[];
  sigma_rule_refs?: number;
}
export interface Curated {
  notes?: string;
  gotchas?: string[];
  /** Hand-verified: the .exe is a .NET apphost launcher. */
  apphost?: boolean;
}
export interface Verification {
  sysmon_version: string;
  os_build: string;
  date: string;
}
/** A build whose live Sysmon event logged a different value than the PE parses to. */
export interface Mismatch extends Verification {
  sysmon_value: string | null;
  parsed_value: string | null;
}
export interface Gotcha {
  /** The flag that produced it, or 'curated' for hand-written ones. */
  kind: string;
  text: string;
}
export interface Inputs {
  records: DataRecord[];
  targets: Record<string, Target>;
  curated: Record<string, Curated>;
  verified: Record<string, Verification>;
  mismatches?: Record<string, Mismatch>;
  coverage: { targets?: number; collected?: number };
  sigmaRelease: string | null;
}

export const CATEGORY_ORDER = ['lolbin', 'rmm', 'sysinternals', 'windows', 'thirdparty'];

// --- ordering helpers -------------------------------------------------------

/** '1507' -> Win10 Jul 2015, '20H2' -> Win10 2020 H2, '11-24H2' -> Win11 2024 H2. */
export function releaseKey(winver: string): [number, number] {
  const win11 = winver.startsWith('11-');
  const ver = win11 ? winver.slice(3) : winver;
  const major = win11 ? 11 : 10;
  let m = /^(\d\d)H([12])$/.exec(ver);
  if (m) return [major, Number(m[1]) * 12 + (m[2] === '1' ? 3 : 9)];
  m = /^(\d\d)(\d\d)$/.exec(ver);
  if (m) return [major, Number(m[1]) * 12 + Number(m[2])];
  return [major, 0];
}

const cmpTuple = (a: number[], b: number[]) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? -1) - (b[i] ?? -1);
    if (d) return d;
  }
  return 0;
};
export const compareRelease = (a: string, b: string) => cmpTuple(releaseKey(a), releaseKey(b));
export const releaseLabel = (w: string) => (w.startsWith('11-') ? `Win11 ${w.slice(3)}` : `Win10 ${w}`);
const versionKey = (v?: string | null) => (v ? v.split('.').map(Number) : []);
export const compareVersion = (a?: string | null, b?: string | null) => cmpTuple(versionKey(a), versionKey(b));
/** Code-point order, like Python's default string sort. */
const cmpStr = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** De-duplicate case-insensitively, keeping the first spelling seen. */
export function distinctCi(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (!seen.has(v.toLowerCase())) {
      seen.add(v.toLowerCase());
      out.push(v);
    }
  }
  return out;
}

// --- snippets -------------------------------------------------------------------

const dq = (v: string) => '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
const sq = (v: string) => "'" + v.replace(/'/g, "''") + "'";
const jsq = (v: string) => "'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";

/**
 * Copy-paste queries per platform. `values` are distinct non-null OFNs, most common first.
 * Every backend gets a case-insensitive comparison, so case variants collapse; the page
 * shows the exact spellings.
 */
export function snippets(name: string, values: string[]): Record<string, string> {
  const vals = distinctCi(values);
  const img = name;
  const logsource = ['logsource:', '  category: process_creation', '  product: windows'];
  // OFN rides along as an output column, never a `by` key: builds without one must not drop out
  const splunkBy = '    by Processes.dest Processes.process_name Processes.process_path Processes.process';
  if (vals.length) {
    // list of maps = OR: image name, or OriginalFilename (survives renaming)
    const sigma = [...logsource, 'detection:', '  selection:', `    - Image|endswith: ${sq('\\' + img)}`];
    if (vals.length === 1) sigma.push(`    - OriginalFileName: ${sq(vals[0])}`);
    else sigma.push('    - OriginalFileName:', ...vals.map((v) => `        - ${sq(v)}`));
    sigma.push('  condition: selection');
    const splOfn = vals.map((v) => `Processes.original_file_name=${dq(v)}`).join(' OR ');
    return {
      sigma: sigma.join('\n'),
      splunk: [
        '| tstats summariesonly=false count values(Processes.original_file_name) as original_file_name',
        '    from datamodel=Endpoint.Processes',
        `    where (${splOfn} OR Processes.process_name=${dq(img)})`,
        splunkBy,
        '| rename Processes.* as *',
      ].join('\n'),
      kql: [
        'DeviceProcessEvents',
        `| where ProcessVersionInfoOriginalFileName in~ (${vals.map(dq).join(', ')})`,
        `    or FileName =~ ${dq(img)}`,
      ].join('\n'),
      eql: [
        'process where event.type == "start" and',
        `  (process.pe.original_file_name in~ (${vals.map(dq).join(', ')}) or`,
        `   process.name : ${dq(img)})`,
      ].join('\n'),
      cribl: `[${vals.map((v) => jsq(v.toLowerCase())).join(', ')}].includes(String(OriginalFileName || '').toLowerCase())`,
    };
  }
  return {
    sigma: [
      '# No OriginalFilename in any observed build: match on the image instead',
      ...logsource,
      'detection:',
      '  selection:',
      `    Image|endswith: ${sq('\\' + img)}`,
      '  condition: selection',
    ].join('\n'),
    splunk: [
      '| tstats summariesonly=false count from datamodel=Endpoint.Processes',
      `    where Processes.process_name=${dq(img)}`,
      splunkBy,
      '| rename Processes.* as *',
    ].join('\n'),
    kql: `DeviceProcessEvents\n| where FileName =~ ${dq(img)}`,
    eql: `process where event.type == "start" and process.name : ${dq(img)}`,
    cribl: `String(Image || '').toLowerCase().endsWith(${dq('\\' + img.toLowerCase())})`,
  };
}

// --- entries ----------------------------------------------------------------------

/**
 * An entry is an RMM only if one of its builds IS that tool (collected from the tool's
 * vendor download). LOLRMM lists generic file names (svchost.exe, setup.exe, dwm.exe)
 * that some agents reuse; a Microsoft build with a colliding name is not the RMM.
 */
export function ownsRmm(builds: Build[], claims: LolrmmClaim[]): boolean {
  const tools = claims.map((c) => c.tool.toLowerCase());
  return builds.some((b) => {
    if (!b.sources.includes('vendor')) return false;
    const product = (b.product ?? '').toLowerCase();
    return product !== '' && tools.some((t) => product.includes(t) || t.includes(product));
  });
}

export function categorize(target: Target | undefined, builds: Build[]): string[] {
  const cats = new Set<string>();
  const srcs = new Set(target?.sources ?? []);
  const buildSrcs = new Set(builds.flatMap((b) => b.sources));
  if (srcs.has('lolbas')) cats.add('lolbin');
  if (srcs.has('lolrmm') && ownsRmm(builds, target?.lolrmm ?? [])) cats.add('rmm');
  if (srcs.has('sysinternals') || buildSrcs.has('sysinternals')) cats.add('sysinternals');
  if ((buildSrcs.has('winbindex') || buildSrcs.has('local')) && !cats.has('sysinternals')) cats.add('windows');
  if (!cats.size) cats.add('thirdparty');
  return CATEGORY_ORDER.filter((c) => cats.has(c));
}

export interface ValueSummary {
  value: string | null;
  builds: number;
  machines: string[];
  min_version: string | null;
  max_version: string | null;
  first_release: string | null;
  last_release: string | null;
  releases: number;
  first_seen: string | null;
  last_seen: string | null;
  sources: string[];
  verified_builds: number;
  provenance: 'sensor-verified' | 'parsed';
}

const uniqSorted = (xs: string[], cmp: (a: string, b: string) => number = cmpStr) => [...new Set(xs)].sort(cmp);
export const slugOf = (name: string) => name.toLowerCase().replace(/[^a-z0-9._-]/g, '-');

export function buildEntry(
  name: string,
  rec: DataRecord,
  target: Target | undefined,
  curated: Curated,
  verified: Record<string, Verification>,
  shared: Map<string, string[]>,
  mismatches: Record<string, Mismatch> = {},
) {
  const builds = rec.builds.filter((b) => 'original_filename' in b);
  builds.sort((a, b) => cmpStr(b.last_seen ?? '', a.last_seen ?? '') || compareVersion(b.fixed_file_version, a.fixed_file_version));

  const groups = new Map<string | null, Build[]>();
  for (const b of builds) {
    const rows = groups.get(b.original_filename) ?? [];
    rows.push(b);
    groups.set(b.original_filename, rows);
  }

  const values: ValueSummary[] = [];
  for (const [value, rows] of groups) {
    const winvers = uniqSorted(rows.flatMap((r) => r.windows_versions ?? []), compareRelease);
    const versions = uniqSorted(rows.map((r) => r.fixed_file_version).filter((v): v is string => !!v), compareVersion);
    const dates = rows.flatMap((r) => [r.first_seen, r.last_seen]).filter((d): d is string => !!d).sort(cmpStr);
    const nVerified = rows.filter((r) => r.sha256 in verified).length;
    values.push({
      value,
      builds: rows.length,
      machines: uniqSorted(rows.map((r) => r.machine)),
      min_version: versions[0] ?? null,
      max_version: versions.at(-1) ?? null,
      first_release: winvers.length ? releaseLabel(winvers[0]) : null,
      last_release: winvers.length ? releaseLabel(winvers.at(-1)!) : null,
      releases: winvers.length,
      first_seen: dates[0] ?? null,
      last_seen: dates.at(-1) ?? null,
      sources: uniqSorted(rows.flatMap((r) => r.sources)),
      verified_builds: nVerified,
      provenance: nVerified ? 'sensor-verified' : 'parsed',
    });
  }
  values.sort((a, b) => b.builds - a.builds || cmpStr(a.value ?? '', b.value ?? ''));

  const primary = builds.find((b) => b.original_filename)?.original_filename ?? null;
  const realValues = values.map((v) => v.value).filter((v): v is string => !!v);
  const distinct = distinctCi(realValues);
  const flags = new Set<string>();
  const gotchas: Gotcha[] = [];
  const add = (kind: string, text: string) => {
    flags.add(kind);
    gotchas.push({ kind, text });
  };

  const mismatched = builds.filter((b) => b.sha256 in mismatches);
  if (mismatched.length) {
    const m = mismatches[mismatched[0].sha256];
    const show = (v: string | null) => (v ? `\`${v}\`` : 'no value');
    add(
      'sensor-mismatch',
      `Sysmon ${m.sysmon_version} logged ${show(m.sysmon_value)} for ${mismatched.length > 1 ? `${mismatched.length} builds` : 'one build'}, ` +
        `but the PE parses to ${show(m.parsed_value)}. Match both until this is explained.`,
    );
  }
  if (!realValues.length) {
    add(
      'no-ofn',
      'No OriginalFilename in any observed build, so Sysmon logs `-` and OriginalFileName rules can\'t match it. ' +
        'Anchor on the image path, hash or signer instead.',
    );
  } else if (groups.has(null)) {
    const n = groups.get(null)!.length;
    add('partial-no-ofn', `${n} observed build${n > 1 ? 's' : ''} carry no OriginalFilename at all.`);
  }
  if (distinct.length > 1) {
    const parts = values
      .filter((v) => v.value)
      .map((v) => {
        const span = !v.first_release
          ? `v${v.min_version}`
          : v.first_release === v.last_release
            ? v.first_release
            : `${v.first_release} → ${v.last_release}`;
        return `\`${v.value}\` (${v.machines.join(', ')}; ${span})`;
      });
    add('drift', `OriginalFilename changed across builds: ${parts.join('; ')}. Match every value.`);
  } else if (new Set(realValues).size > 1) {
    add(
      'case-drift',
      `Casing differs across builds (${uniqSorted(realValues).map((v) => `\`${v}\``).join(', ')}). ` +
        'Case-sensitive comparisons (Elastic KQL on keyword fields, `==` in KQL/EQL) miss some builds.',
    );
  }
  // A DLL name on an .exe is a fact; ".NET apphost" is one explanation of it, asserted only by
  // build data or a curated note. Most Windows cases are plain native binaries.
  const dll = name.endsWith('.exe') ? distinct.find((v) => v.toLowerCase().endsWith('.dll')) : undefined;
  if (dll && (curated.apphost || builds.some((b) => b.is_apphost))) {
    flags.add('dll-ofn');
    add(
      'apphost',
      `.NET apphost: \`${name}\` is a native launcher that copies its version resource from \`${dll}\`, ` +
        'so OriginalFilename names the DLL.',
    );
  } else if (dll) {
    add('dll-ofn', `OriginalFilename names a DLL (\`${dll}\`), not an executable. Rules expecting \`.exe\` values miss it.`);
  }
  if (distinct.length && distinct.every((v) => v.toLowerCase() !== name.toLowerCase())) {
    add('differs-from-name', `OriginalFilename doesn't match the file name: a rule using \`OriginalFileName: ${name}\` never fires.`);
  }
  const others = uniqSorted(distinct.flatMap((v) => shared.get(v.toLowerCase()) ?? []).filter((n) => n !== name));
  if (others.length) {
    add(
      'shared',
      'Same OriginalFilename as ' +
        others.slice(0, 12).map((o) => `\`${o}\``).join(', ') +
        (others.length > 12 ? ` and ${others.length - 12} more` : '') +
        ", so OriginalFilename alone can't tell them apart.",
    );
  }
  const claims = target?.lolrmm ?? [];
  if (claims.length && ownsRmm(builds, claims)) {
    const lower = new Set(distinct.map((v) => v.toLowerCase()));
    const claim = claims.find((c) => c.claimed_original_filename && !lower.has(c.claimed_original_filename.toLowerCase()));
    if (claim) {
      add(
        'lolrmm-mismatch',
        `LOLRMM lists \`${claim.claimed_original_filename}\` for ${claim.tool}; parsed builds show ${distinct.map((v) => `\`${v}\``).join(', ') || 'none'}.`,
      );
    }
  } else if (claims.length) {
    const tools = uniqSorted(claims.map((c) => c.tool));
    add(
      'rmm-name-collision',
      `LOLRMM lists ${tools.join(', ')} as shipping a file named \`${name}\`. That's a different binary reusing the name; ` +
        'this page covers the one parsed below. Rename detection on OriginalFilename separates them.',
    );
  }
  gotchas.push(...(curated.gotchas ?? []).map((text) => ({ kind: 'curated', text })));

  const latest = builds[0];
  const verRows = builds.map((b) => verified[b.sha256]).filter((v): v is Verification => !!v);
  const cats = categorize(target, builds);
  const lolbas = target?.lolbas;
  return {
    name,
    slug: slugOf(name),
    categories: cats,
    category: cats[0],
    primary,
    values,
    distinct_values: distinct,
    flags: [...flags].sort(),
    gotchas,
    notes: curated.notes ?? null,
    description: latest?.file_description ?? null,
    company: latest?.company_name ?? null,
    product: latest?.product_name ?? null,
    internal_names: uniqSorted(builds.map((b) => b.internal_name).filter((n): n is string => !!n)),
    verified: verRows.length > 0,
    verification: verRows.length ? verRows.reduce((a, b) => (b.date > a.date ? b : a)) : null,
    lolbas: lolbas?.url ? { url: lolbas.url, category: lolbas.category } : null,
    lolrmm_tools: uniqSorted(claims.map((c) => c.tool)),
    sigma_rule_refs: target?.sigma_rule_refs ?? 0,
    build_count: builds.length,
    gap_count: rec.gaps?.length ?? 0,
    snippets: snippets(name, distinct),
    builds: builds.map((b) => ({
      sha256: b.sha256,
      machine: b.machine,
      original_filename: b.original_filename,
      version: b.fixed_file_version ?? null,
      releases: [...(b.windows_versions ?? [])].sort(compareRelease).map(releaseLabel),
      last_seen: b.last_seen ?? null,
      sources: b.sources,
      download_url: b.download_url ?? null,
      verified: b.sha256 in verified,
      mismatch: b.sha256 in mismatches,
      product: b.product ?? null,
      os_builds: b.os_builds ?? [],
      signature: signatureLabel(b),
    })),
  };
}

/** 'Signed (catalog)', 'Unsigned', or '' when the build carries no signing data. */
export function signatureLabel(b: Pick<Build, 'signing_status' | 'signature_type'>): string {
  if (!b.signing_status || b.signing_status === 'Unknown') return '';
  return b.signature_type && b.signing_status === 'Signed' ? `Signed (${b.signature_type})` : b.signing_status;
}

export type Entry = ReturnType<typeof buildEntry>;

export function deriveAll(inp: Inputs) {
  // OFN (lowercase) -> binary names that carry it; drives "shared" gotchas and the pairs lookup
  const shared = new Map<string, string[]>();
  for (const rec of inp.records) {
    for (const v of new Set(rec.builds.map((b) => b.original_filename).filter((v): v is string => !!v))) {
      const names = shared.get(v.toLowerCase()) ?? [];
      if (!names.includes(rec.name)) names.push(rec.name);
      shared.set(v.toLowerCase(), names);
    }
  }
  const entries = inp.records
    .filter((rec) => rec.builds.some((b) => 'original_filename' in b))
    .map((rec) =>
      buildEntry(rec.name, rec, inp.targets[rec.name], inp.curated[rec.name] ?? {}, inp.verified, shared, inp.mismatches),
    )
    .sort((a, b) => cmpStr(a.name, b.name));
  // the newest record date, so a redeploy of unchanged data doesn't look like fresh data
  const updated = inp.records.map((r) => r.updated).filter((d): d is string => !!d).sort(cmpStr).at(-1) ?? null;

  const pairs: [string, string][] = [];
  for (const [ofn, names] of shared) for (const n of names) pairs.push([ofn, n]);
  pairs.sort((a, b) => cmpStr(a[0], b[0]) || cmpStr(a[1], b[1]));

  const count = (xs: string[]) => xs.reduce<Record<string, number>>((m, x) => ((m[x] = (m[x] ?? 0) + 1), m), {});
  const stats = {
    updated,
    entries: entries.length,
    builds: entries.reduce((n, e) => n + e.build_count, 0),
    verified_entries: entries.filter((e) => e.verified).length,
    mismatched_entries: entries.filter((e) => e.flags.includes('sensor-mismatch')).length,
    categories: count(entries.flatMap((e) => e.categories)),
    flags: count(entries.flatMap((e) => e.flags)),
    sysmon_versions: uniqSorted(Object.values(inp.verified).map((v) => v.sysmon_version)),
    sigma_release: inp.sigmaRelease,
    targets: inp.coverage.targets ?? null,
    targets_collected: inp.coverage.collected ?? null,
    pairs: pairs.length,
  };
  return { entries, stats, pairs };
}

// --- export files -------------------------------------------------------------------

const csvField = (v: string | number) => {
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const csv = (rows: (string | number)[][]) => rows.map((r) => r.map(csvField).join(',')).join('\n') + '\n';

export function ofnJson(entries: Entry[]): string {
  const summary = entries.map((e) => ({
    name: e.name,
    category: e.category,
    original_filenames: e.values.map((v) => v.value),
    primary: e.primary,
    sensor_verified: e.verified,
    flags: e.flags,
    url: `/b/${e.slug}/`,
  }));
  return JSON.stringify(summary, null, 1) + '\n';
}

export function ofnCsv(entries: Entry[]): string {
  const rows: (string | number)[][] = [
    ['image_name', 'original_filename', 'builds', 'machines', 'min_version', 'max_version', 'first_release', 'last_release', 'provenance', 'category'],
  ];
  for (const e of entries) {
    for (const v of e.values) {
      rows.push([
        e.name, v.value ?? '', v.builds, v.machines.join('|'), v.min_version ?? '', v.max_version ?? '',
        v.first_release ?? '', v.last_release ?? '', v.provenance, e.category,
      ]);
    }
  }
  return csv(rows);
}

export const pairsCsv = (pairs: [string, string][]) => csv([['original_filename', 'image_name'], ...pairs]);

export const pairsKql = (pairs: [string, string][]) =>
  '// OriginalFilename -> expected image name (both lowercase). Generated; do not edit.\n' +
  `let ofn_pairs = datatable(ofn: string, img: string) [\n${pairs.map(([o, i]) => `    ${dq(o)}, ${dq(i)}`).join(',\n')}\n];\n`;
