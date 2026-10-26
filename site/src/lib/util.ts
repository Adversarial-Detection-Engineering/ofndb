export const SITE_NAME = 'ofndb';

/** Base path with exactly one trailing slash, e.g. "/" or "/ofndb/". */
export const base = import.meta.env.BASE_URL.replace(/\/?$/, '/');

export const href = (path = '') => base + path.replace(/^\//, '');

export const CATEGORY_LABELS: Record<string, string> = {
  lolbin: 'LOLBin',
  rmm: 'RMM',
  sysinternals: 'Sysinternals',
  windows: 'Windows',
  thirdparty: 'Third-party',
};

export const FLAG_LABELS: Record<string, string> = {
  drift: 'Value changed across builds',
  'case-drift': 'Casing changed across builds',
  'no-ofn': 'No OriginalFilename',
  'partial-no-ofn': 'Some builds lack OriginalFilename',
  'differs-from-name': 'Differs from file name',
  apphost: '.NET apphost',
  'dll-ofn': 'Names a DLL',
  'sensor-mismatch': 'Sysmon logged a different value',
  'sigma-mismatch': 'Sigma rules use a value no build carries',
  shared: 'Shared with other binaries',
  'lolrmm-mismatch': 'LOLRMM value disagrees',
  'rmm-name-collision': 'Name reused by an RMM tool',
};

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);

/** Escape, then render `code` spans. Gotchas and notes use only backticks. */
export const md = (s: string) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');

/** Escape, then allow line breaks after . _ - so long file names wrap at sensible points. */
export const wbr = (s: string) => esc(s).replace(/([._-])/g, '$1<wbr>');

export const PLATFORMS = [
  { key: 'sigma', label: 'Sigma', hint: 'process_creation logsource. Sigma string matching is case-insensitive.' },
  {
    key: 'splunk',
    label: 'Splunk CIM',
    hint: 'Endpoint.Processes data model. On raw Sysmon events the field is OriginalFileName.',
  },
  { key: 'kql', label: 'Defender KQL', hint: 'Microsoft Defender XDR advanced hunting. in~ and =~ are case-insensitive.' },
  {
    key: 'eql',
    label: 'Elastic EQL',
    hint: 'ECS process.pe.original_file_name is a keyword field: in~ is case-insensitive, Kibana KQL is not.',
  },
  {
    key: 'cribl',
    label: 'Cribl Stream',
    hint: "Filter expression (JavaScript) for events carrying Sysmon's OriginalFileName field.",
  },
] as const;
