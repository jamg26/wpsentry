import type { ScanDetail, Finding } from './api.ts';

function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function generateScanCSV(scan: ScanDetail): void {
  const findings: Finding[] = scan.report?.results.flatMap((r) => r.findings) ?? [];

  const headers = ['Severity', 'Type', 'URL', 'Description', 'Remediation', 'Evidence'];
  const rows = findings.map((f) => [
    f.severity,
    f.type,
    f.url,
    f.description,
    f.remediation ?? '',
    f.evidence ?? '',
  ]);

  const csv = [
    headers.map(escapeCSV).join(','),
    ...rows.map((row) => row.map(escapeCSV).join(',')),
  ].join('\r\n');

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `jwp-scan-${scan.id}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
