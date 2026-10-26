// Every committed data file must match its schema. CI runs this on every PR.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse as parseYaml } from 'yaml';
import { slugOf } from '../src/lib/derive.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
// load every schema first so cross-file $refs resolve
const SCHEMAS = readdirSync(join(ROOT, 'schema')).filter((f) => f.endsWith('.json'));
for (const f of SCHEMAS) ajv.addSchema(json(join(ROOT, 'schema', f)));
const compile = (name: string) => ajv.getSchema(`https://ofndb/schema/${name}`)!;
const genDir = join(ROOT, 'data', 'generated');
const records = readdirSync(genDir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({ f, rec: json(join(genDir, f)) }));

test('generated records match the schema and their file names', () => {
  const validate = compile('generated-record.schema.json');
  const bad: string[] = [];
  for (const { f, rec } of records) {
    if (!validate(rec)) bad.push(`${f}: ${ajv.errorsText(validate.errors).slice(0, 200)}`);
    else if (`${rec.name}.json` !== f) bad.push(`${f}: name ${rec.name} doesn't match file name`);
  }
  assert.deepEqual(bad.slice(0, 5), [], `${bad.length} invalid records`);
});

test("each record's original_filenames summary agrees with its builds", () => {
  const bad: string[] = [];
  for (const { f, rec } of records) {
    const fromBuilds = new Map<string | null, number>();
    for (const b of rec.builds) if ('original_filename' in b) fromBuilds.set(b.original_filename, (fromBuilds.get(b.original_filename) ?? 0) + 1);
    const summary = new Map<string | null, number>(rec.original_filenames.map((s: { value: string | null; builds: number }) => [s.value, s.builds]));
    const same = fromBuilds.size === summary.size && [...fromBuilds].every(([v, n]) => summary.get(v) === n);
    if (!same) bad.push(f);
  }
  assert.deepEqual(bad.slice(0, 5), [], `${bad.length} records whose summary disagrees with their builds`);
});

test('curated notes match the schema and point at a real record', () => {
  const validate = compile('curated.schema.json');
  const dir = join(ROOT, 'data', 'curated');
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.yml'))) {
    const data = parseYaml(readFileSync(join(dir, f), 'utf8'));
    assert.ok(validate(data), `${f}: ${ajv.errorsText(validate.errors)}`);
    assert.ok(existsSync(join(genDir, `${f.slice(0, -4)}.json`)), `${f}: no generated record`);
  }
});

for (const [file, schema] of [
  ['targets.json', 'targets.schema.json'],
  ['coverage.json', 'coverage.schema.json'],
  ['validation/sysmon.json', 'sysmon-validation.schema.json'],
  ['sources/sigma_original_filenames.json', 'sigma-original-filenames.schema.json'],
]) {
  test(`data/${file} matches ${schema}`, () => {
    const validate = compile(schema);
    assert.ok(validate(json(join(ROOT, 'data', file))), ajv.errorsText(validate.errors).slice(0, 500));
  });
}

test('binary pages get distinct slugs', () => {
  const seen = new Map<string, string>();
  for (const { rec } of records) {
    const slug = slugOf(rec.name);
    assert.ok(!seen.has(slug), `${rec.name} and ${seen.get(slug)} share slug ${slug}`);
    seen.set(slug, rec.name);
  }
});
