// Reads the committed data at build time and derives the site from it, once.
// npm scripts run from site/, so the data lives at ../data unless OFNDB_DATA says otherwise.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { deriveAll, type Curated, type DataRecord, type Inputs, type Mismatch, type SigmaRule, type Verification } from './derive';

const DATA = resolve(process.env.OFNDB_DATA ?? join(process.cwd(), '..', 'data'));

const json = (path: string) => JSON.parse(readFileSync(path, 'utf8'));

function loadInputs(): Inputs {
  const genDir = join(DATA, 'generated');
  const records: DataRecord[] = readdirSync(genDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => json(join(genDir, f)));

  const curated: Record<string, Curated> = {};
  const curDir = join(DATA, 'curated');
  if (existsSync(curDir)) {
    for (const f of readdirSync(curDir).filter((f) => f.endsWith('.yml'))) {
      curated[f.slice(0, -4)] = parseYaml(readFileSync(join(curDir, f), 'utf8')) ?? {};
    }
  }

  // a mismatch is a finding, so it's shown on the page rather than dropped
  const verified: Record<string, Verification> = {};
  const mismatches: Record<string, Mismatch> = {};
  const sysmonPath = join(DATA, 'validation', 'sysmon.json');
  if (existsSync(sysmonPath)) {
    for (const r of json(sysmonPath)) {
      if (!r.parsed) continue;
      const v = { sysmon_version: r.sysmon_version, os_build: r.os_build, date: r.verified };
      if (r.match) verified[r.sha256] = v;
      else mismatches[r.sha256] = { ...v, sysmon_value: r.sysmon_original_filename, parsed_value: r.parsed_original_filename };
    }
  }

  const covPath = join(DATA, 'coverage.json');
  const sigmaPath = join(DATA, 'sources', 'sigma_original_filenames.json');
  const sigmaSrc = existsSync(sigmaPath) ? json(sigmaPath) : null;
  // The collector keeps only exact (unmodified) OriginalFileName values, comments and quotes
  // stripped. A leading backslash stays on purpose: as an exact value it never matches, and
  // that is worth showing.
  const sigmaValues: Record<string, number> = sigmaSrc?.values ?? {};
  const sigmaRules: Record<string, SigmaRule[]> = sigmaSrc?.rules ?? {};
  return {
    records,
    targets: json(join(DATA, 'targets.json')).targets,
    curated,
    verified,
    mismatches,
    coverage: existsSync(covPath) ? json(covPath).summary : {},
    sigmaRelease: sigmaSrc?.sigma_release ?? null,
    sigmaValues,
    sigmaRules,
  };
}

let cached: ReturnType<typeof deriveAll> | undefined;

export function siteData() {
  cached ??= deriveAll(loadInputs());
  return cached;
}
