# Coverage (2026-10-29)

Generated. Do not edit.

| | count |
|---|---|
| targets | 1369 |
| collected (≥1 parsed build) | 505 |
| Sysmon-verified (≥1 build) | 505 |
| Sysmon mismatches | 0 |
| parsed builds | 5090 |
| Sysmon-verified builds (all records) | 5778 of 5818 |
| extra records (host binaries not in any target source) | 538 |

## By source

| source | targets | collected |
|---|---|---|
| lolbas | 245 | 158 |
| lolrmm | 291 | 5 |
| sysinternals | 151 | 151 |
| sigma | 1003 | 457 |
| curated | 42 | 42 |

## Why targets are missing

| reason | count |
|---|---|
| third-party tool: not collected yet | 484 |
| RMM tool: not collected yet | 256 |
| Microsoft product outside Windows (Office/VS/SQL/SDK): not collected yet | 66 |
| no file extension (non-Windows binary) | 14 |
| not published on the Microsoft symbol server (Edge/Store app) | 10 |
| script, no PE (OFN applies to its host process) | 10 |
| wildcard pattern (LOLRMM), not a concrete filename | 8 |
| not a PE file (installer/package) | 8 |
| Windows file not in Winbindex (base-release only or optional feature): not collected yet | 5 |
| in Winbindex, but no build could be verified (symbol server collisions) | 3 |

## OriginalFilename differs across builds (14)

Any difference counts here: a different value, casing only, or some builds with none. The site splits these into
"value changed", "casing changed" and "some builds lack OriginalFilename".

- `changepk.exe`: `changepk.exe`, `changepkey.exe`
- `configsecuritypolicy.exe`: `ConfigSecurityPolicy.exe`, `ConfiguSecurityPolicy.exe`
- `mavinject.exe`: `mavinject32.exe`, `mavinject64.exe`
- `msconfig.exe`: `MSCONFIG.EXE`, `msconfig.EXE`
- `nltest.exe`: `nltest.exe`, `nltestrk.exe`
- `pnputil.exe`: `PnPutil.exe`, `pnputil.exe`
- `runexehelper.exe`: none, `RunExeHelper.exe`
- `schtasks.exe`: `schtasks.exe`, `sctasks.exe`
- `setup.exe`: none, `SETUP.EXE`, `isetup.exe`
- `setupapi.dll`: `SETUPAPI.DLL`, `setupapi.dll`
- `shell32.dll`: `SHELL32.DLL`, `shell32.dll`
- `syncappvpublishingserver.exe`: none, `SyncAppvPublishingServer.exe`, `syncappvpublishingserver.exe`
- `sysmon.exe`: none, `sysmon.exe`
- `taskmgr.exe`: `Taskmgr.exe`, `taskmgr.exe`

## No OriginalFilename in any build (11)

`anydesk.exe`, `ldmdump.exe`, `openconsole.exe`, `pcalua.exe`, `reghide.exe`, `rootkitrevealer.exe`, `scp.exe`, `sftp.exe`, `ssh-shellhost.exe`, `ssh.exe`, `sysmon64.exe`
