# ofndb

The `OriginalFileName` that Sysmon, Microsoft Defender and Elastic log for LOLBins, Windows binaries, Sysinternals and admin tools. Each value is read from the binary itself and confirmed against live Sysmon events.

**Site:** https://adversarial-detection-engineering.github.io/ofndb/

## Why

Detection rules key on OriginalFileName because it survives renaming, but the usual ways of looking it up give the wrong answer. Explorer, `(Get-Item x).VersionInfo` and .NET `FileVersionInfo` all return the localized MUI value:

| binary | Explorer / .NET | what Sysmon logs |
|---|---|---|
| cmd.exe | `Cmd.Exe.MUI` | `Cmd.Exe` |
| powershell.exe | `PowerShell.EXE.MUI` | `PowerShell.EXE` |
| pwsh.exe | | `pwsh.dll` (.NET apphost) |
| nltest.exe | | `nltestrk.exe` through 25H2, `nltest.exe` on 26H1 |
| psexec.exe | | `psexec.c` |
| pcalua.exe | | none: Sysmon logs `-` |

## What's here

| path | contents |
|---|---|
| `data/generated/<name>.json` | Every parsed build of a binary: SHA256, architecture, version strings, OriginalFilename, Windows releases, source |
| `data/validation/sysmon.json` | Sysmon ground truth: the OriginalFileName Sysmon logged for each exact build (by SHA256) |
| `data/curated/<name>.yml` | Hand-written notes on binaries that need context |
| `data/targets.json` | Binary names gathered from LOLBAS, LOLRMM, Sysinternals and SigmaHQ, with the claims those projects make |
| `data/COVERAGE.md` | What's covered, and why anything isn't |
| `schema/` | JSON Schemas every data file is validated against |
| `site/` | The static site (Astro). It derives gotchas, query snippets and lookup exports from `data/` at build time |

Downloads (CSV, JSON, KQL datatable, rename-detection lookup) are on the site's [Lookups](https://adversarial-detection-engineering.github.io/ofndb/lookups/) page.

## How values are produced

- **Raw PE parsing.** Every value comes from the PE's own `RT_VERSION` resource, never from Windows version APIs.
- **Windows built-ins.** Every build Winbindex knows of is downloaded from the Microsoft symbol server and kept only when its SHA256 matches.
- **Sysinternals and vendor tools.** Downloaded from their official sources.
- **Ground truth.** In a disposable Windows Sandbox running Sysmon, every target is created suspended and killed before it executes. Sysmon's logged OriginalFileName is then compared with the parsed value: 0 mismatches so far.

## Run the site locally

```
cd site
npm install
npm test            # derivation logic + schema validation of all data
npm run build && npm run check
npm run preview
```

## License

The site code is under the [MIT License](LICENSE). The data (`data/` and all exports) is under [CC BY 4.0](data/LICENSE.md): use it in your detections and products, and credit ofndb.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable report is sensor evidence: a value your Sysmon or EDR logged that differs from this database.
