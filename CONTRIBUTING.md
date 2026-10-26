# Contributing

## Report a wrong or missing value

Open an issue with:

- the binary's **SHA256** and where it came from (Windows build, product version, download URL);
- what your sensor logged: Sysmon EID 1 `OriginalFileName`, MDE `ProcessVersionInfoOriginalFileName`, Elastic `process.pe.original_file_name`, and so on.

Real sensor data that disagrees with ofndb is the most valuable report this project gets. Requests for binaries that aren't covered yet are welcome too; include a download source if there is one.

## Add context for a binary

Notes live in `data/curated/<lowercase file name>.yml`, and pull requests are welcome:

```yaml
notes: >-
  One or two sentences a detection engineer needs, for example why the value
  is what it is or which builds differ.
gotchas:
  - Optional extra bullet points shown under the auto-generated ones.
```

Gotchas the data already proves (drift across builds, no value, .NET apphost, shared values, LOLRMM disagreement) are generated automatically, so don't repeat them. CI validates the file against `schema/curated.schema.json`.

## Don't edit `data/generated/`

Those records are produced by the collection pipeline from the binaries themselves. Hand edits are rejected; open an issue with evidence instead.

## Work on the site

```
cd site && npm install && npm test && npm run build && npm run check && npm run preview
```

All derived content (gotchas, snippets, exports) comes from `site/src/lib/derive.ts`. Its tests are in `site/tests/derive.test.ts`.
