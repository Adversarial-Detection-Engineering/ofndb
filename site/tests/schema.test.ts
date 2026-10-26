// Every committed data file must match its schema. CI runs this on every PR.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse as parseYaml } from 'yaml';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const compile = (name: string) => ajv.compile(json(join(ROOT, 'schema', name)));

test('generated records match the schema and their file names', () => {
  const validate = compile('generated-record.schema.json');
  const dir = join(ROOT, 'data', 'generated');
  const bad: string[] = [];
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.json'))) {
    const rec = json(join(dir, f));
    if (!validate(rec)) bad.push(`${f}: ${ajv.errorsText(validate.errors).slice(0, 200)}`);
    else if (`${rec.name}.json` !== f) bad.push(`${f}: name ${rec.name} doesn't match file name`);
  }
  assert.deepEqual(bad.slice(0, 5), [], `${bad.length} invalid records`);
});

test('curated notes match the schema and point at a real record', () => {
  const validate = compile('curated.schema.json');
  const dir = join(ROOT, 'data', 'curated');
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.yml'))) {
    const data = parseYaml(readFileSync(join(dir, f), 'utf8'));
    assert.ok(validate(data), `${f}: ${ajv.errorsText(validate.errors)}`);
    assert.ok(existsSync(join(ROOT, 'data', 'generated', `${f.slice(0, -4)}.json`)), `${f}: no generated record`);
  }
});
