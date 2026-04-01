import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ScanDetail, Finding, ModuleResult } from './api.ts';

// ── Colors ──────────────────────────────────────────────────────────────────
const NAVY = [30, 41, 59] as const;       // #1e293b
const WHITE = [255, 255, 255] as const;
const LIGHT_GRAY = [241, 245, 249] as const;
const MID_GRAY = [148, 163, 184] as const;
const DARK_TEXT = [15, 23, 42] as const;
const SUB_TEXT = [100, 116, 139] as const;

const SEVERITY_COLORS: Record<string, readonly [number, number, number]> = {
  CRITICAL: [239, 68, 68],
  HIGH: [249, 115, 22],
  MEDIUM: [234, 179, 8],
  LOW: [59, 130, 246],
  INFO: [100, 116, 139],
};

type RGB = readonly [number, number, number];

// ── Helpers ─────────────────────────────────────────────────────────────────
function computeDuration(started?: string | null, completed?: string | null): string {
  if (!started || !completed) return 'N/A';
  const ms = new Date(completed).getTime() - new Date(started).getTime();
  if (ms < 0) return 'N/A';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function overallRisk(by: ScanDetail['by_severity']): { label: string; color: RGB } {
  if (by.critical > 0) return { label: 'CRITICAL', color: SEVERITY_COLORS.CRITICAL };
  if (by.high > 0)     return { label: 'HIGH', color: SEVERITY_COLORS.HIGH };
  if (by.medium > 0)   return { label: 'MEDIUM', color: SEVERITY_COLORS.MEDIUM };
  if (by.low > 0)      return { label: 'LOW', color: SEVERITY_COLORS.LOW };
  if (by.info > 0)     return { label: 'INFO', color: SEVERITY_COLORS.INFO };
  return { label: 'CLEAN', color: [34, 197, 94] };
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  });
}

const MARGIN = 20;
const PAGE_W = 210;
const CONTENT_W = PAGE_W - MARGIN * 2;

// ── Footer ──────────────────────────────────────────────────────────────────
function addFooter(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    doc.setDrawColor(...MID_GRAY);
    doc.setLineWidth(0.3);
    doc.line(MARGIN, pageH - 15, PAGE_W - MARGIN, pageH - 15);

    doc.setFontSize(7);
    doc.setTextColor(...SUB_TEXT);
    doc.setFont('helvetica', 'normal');
    doc.text('WPSentry — Security Assessment Report', MARGIN, pageH - 10);
    doc.text('Confidential', PAGE_W / 2, pageH - 10, { align: 'center' });
    doc.text(`Page ${i} of ${pageCount}`, PAGE_W - MARGIN, pageH - 10, { align: 'right' });
  }
}

// Ensures enough space for content; adds a new page if needed.
function ensureSpace(doc: jsPDF, y: number, needed: number): number {
  const pageH = doc.internal.pageSize.getHeight();
  if (y + needed > pageH - 22) {
    doc.addPage();
    return MARGIN + 5;
  }
  return y;
}

// ── Word-wrap helper (splits text to fit a given width) ─────────────────────
function wrapText(doc: jsPDF, text: string, maxWidth: number): string[] {
  return doc.splitTextToSize(text, maxWidth) as string[];
}

// ── Main Export ─────────────────────────────────────────────────────────────
export function generateScanPDF(scan: ScanDetail): void {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageH = doc.internal.pageSize.getHeight();
  const risk = overallRisk(scan.by_severity);
  const duration = computeDuration(scan.started_at, scan.completed_at);
  const totalFindings = scan.findings_count;
  const modulesRun = scan.report?.summary.total_modules ?? 0;

  // ════════════════════════════════════════════════════════════════════════
  // PAGE 1: Cover / Executive Summary
  // ════════════════════════════════════════════════════════════════════════

  // Header bar
  doc.setFillColor(...NAVY);
  doc.rect(0, 0, PAGE_W, 58, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(...WHITE);
  doc.text('JWP Security Assessment Report', MARGIN, 28);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(11);
  doc.setTextColor(200, 210, 225);
  const targetLines = wrapText(doc, scan.target, CONTENT_W);
  doc.text(targetLines, MARGIN, 40);

  doc.setFontSize(8);
  doc.setTextColor(160, 175, 195);
  doc.text(`Generated ${formatDate(new Date().toISOString())}`, MARGIN, 52);

  // ── Risk level banner ──
  let y = 70;
  doc.setFillColor(...risk.color);
  doc.roundedRect(MARGIN, y, CONTENT_W, 18, 3, 3, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...WHITE);
  doc.text(`Overall Risk Level: ${risk.label}`, PAGE_W / 2, y + 11.5, { align: 'center' });

  // ── Risk meter bar ──
  y += 26;
  const meterH = 6;
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
  const counts = [scan.by_severity.critical, scan.by_severity.high, scan.by_severity.medium, scan.by_severity.low, scan.by_severity.info];
  const total = counts.reduce((a, b) => a + b, 0) || 1;

  doc.setFillColor(226, 232, 240);
  doc.roundedRect(MARGIN, y, CONTENT_W, meterH, 2, 2, 'F');

  let barX = MARGIN;
  for (let i = 0; i < severities.length; i++) {
    if (counts[i] === 0) continue;
    const w = (counts[i] / total) * CONTENT_W;
    const c = SEVERITY_COLORS[severities[i]];
    doc.setFillColor(...c);
    doc.rect(barX, y, w, meterH, 'F');
    barX += w;
  }

  // Labels under meter
  y += meterH + 4;
  doc.setFontSize(6.5);
  for (let i = 0; i < severities.length; i++) {
    const x = MARGIN + (i * CONTENT_W) / 5;
    const c = SEVERITY_COLORS[severities[i]];
    doc.setFillColor(...c);
    doc.circle(x + 2, y + 1, 1.5, 'F');
    doc.setTextColor(...DARK_TEXT);
    doc.setFont('helvetica', 'normal');
    doc.text(`${severities[i]}: ${counts[i]}`, x + 5, y + 2.5);
  }

  // ── Summary stats table ──
  y += 14;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...NAVY);
  doc.text('Executive Summary', MARGIN, y);
  y += 6;

  autoTable(doc, {
    startY: y,
    margin: { left: MARGIN, right: MARGIN },
    head: [['Metric', 'Value']],
    body: [
      ['Target URL', scan.target],
      ['Scan Date', formatDate(scan.created_at)],
      ['Completion Time', scan.completed_at ? formatDate(scan.completed_at) : 'N/A'],
      ['Scan Duration', duration],
      ['Total Modules Run', String(modulesRun)],
      ['Total Findings', String(totalFindings)],
      ['Critical', String(scan.by_severity.critical)],
      ['High', String(scan.by_severity.high)],
      ['Medium', String(scan.by_severity.medium)],
      ['Low', String(scan.by_severity.low)],
      ['Info', String(scan.by_severity.info)],
    ],
    styles: { font: 'helvetica', fontSize: 9, cellPadding: 3 },
    headStyles: { fillColor: [...NAVY], textColor: [...WHITE], fontStyle: 'bold' },
    alternateRowStyles: { fillColor: [...LIGHT_GRAY] },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 55 } },
  });

  // ════════════════════════════════════════════════════════════════════════
  // FINDINGS DETAIL
  // ════════════════════════════════════════════════════════════════════════
  const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const allFindings = (scan.report?.results.flatMap((r) => r.findings) ?? [])
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));

  if (allFindings.length > 0) {
    doc.addPage();
    y = MARGIN;

    // Section header bar
    doc.setFillColor(...NAVY);
    doc.rect(0, 0, PAGE_W, 20, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(...WHITE);
    doc.text('Detailed Findings', MARGIN, 13.5);

    y = 28;

    allFindings.forEach((finding: Finding, idx: number) => {
      y = ensureSpace(doc, y, 45);

      // If at top of a new page (after ensureSpace added one), add section header
      if (y < 30) {
        doc.setFillColor(...NAVY);
        doc.rect(0, 0, PAGE_W, 20, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(14);
        doc.setTextColor(...WHITE);
        doc.text('Detailed Findings (continued)', MARGIN, 13.5);
        y = 28;
      }

      const sevColor = SEVERITY_COLORS[finding.severity] ?? MID_GRAY;

      // Finding header with severity accent
      doc.setFillColor(...sevColor);
      doc.rect(MARGIN, y, 3, 8, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(...DARK_TEXT);
      doc.text(`Finding #${idx + 1}`, MARGIN + 6, y + 5.5);

      // Severity badge
      const badgeText = finding.severity;
      const badgeW = doc.getTextWidth(badgeText) + 8;
      const badgeX = PAGE_W - MARGIN - badgeW;
      doc.setFillColor(...sevColor);
      doc.roundedRect(badgeX, y, badgeW, 7, 1.5, 1.5, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...WHITE);
      doc.text(badgeText, badgeX + badgeW / 2, y + 5, { align: 'center' });

      y += 12;

      // Type
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...SUB_TEXT);
      doc.text('TYPE', MARGIN, y);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(...DARK_TEXT);
      doc.text(finding.type, MARGIN + 22, y);
      y += 6;

      // URL
      y = ensureSpace(doc, y, 10);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...SUB_TEXT);
      doc.text('URL', MARGIN, y);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(59, 130, 246);
      const urlLines = wrapText(doc, finding.url, CONTENT_W - 22);
      doc.text(urlLines, MARGIN + 22, y);
      y += urlLines.length * 4 + 3;

      // Description
      y = ensureSpace(doc, y, 14);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(...SUB_TEXT);
      doc.text('DESCRIPTION', MARGIN, y);
      y += 4;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(...DARK_TEXT);
      const descLines = wrapText(doc, finding.description, CONTENT_W);
      for (const line of descLines) {
        y = ensureSpace(doc, y, 5);
        doc.text(line, MARGIN, y);
        y += 4;
      }
      y += 2;

      // Replication steps
      if (finding.replication_steps && finding.replication_steps.length > 0) {
        y = ensureSpace(doc, y, 14);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...SUB_TEXT);
        doc.text('REPLICATION STEPS', MARGIN, y);
        y += 5;

        finding.replication_steps.forEach((step, si) => {
          y = ensureSpace(doc, y, 5);
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8.5);
          doc.setTextColor(...DARK_TEXT);
          const stepLines = wrapText(doc, `${si + 1}. ${step}`, CONTENT_W - 5);
          for (const sl of stepLines) {
            y = ensureSpace(doc, y, 4.5);
            doc.text(sl, MARGIN + 3, y);
            y += 4;
          }
        });
        y += 2;
      }

      // Evidence
      if (finding.evidence) {
        y = ensureSpace(doc, y, 18);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(...SUB_TEXT);
        doc.text('EVIDENCE', MARGIN, y);
        y += 5;

        doc.setFillColor(241, 245, 249);
        const evLines = wrapText(doc, finding.evidence, CONTENT_W - 8);
        const evHeight = evLines.length * 3.8 + 6;
        y = ensureSpace(doc, y, evHeight + 2);
        doc.roundedRect(MARGIN, y - 2, CONTENT_W, evHeight, 1.5, 1.5, 'F');
        doc.setFont('courier', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        for (const el of evLines) {
          doc.text(el, MARGIN + 4, y + 2);
          y += 3.8;
        }
        y += 5;
      }

      // Remediation
      if (finding.remediation) {
        y = ensureSpace(doc, y, 18);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(34, 197, 94);
        doc.text('REMEDIATION', MARGIN, y);
        y += 5;

        doc.setFillColor(240, 253, 244);
        const remLines = wrapText(doc, finding.remediation, CONTENT_W - 8);
        const remHeight = remLines.length * 4 + 6;
        y = ensureSpace(doc, y, remHeight + 2);
        doc.roundedRect(MARGIN, y - 2, CONTENT_W, remHeight, 1.5, 1.5, 'F');
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8.5);
        doc.setTextColor(22, 101, 52);
        for (const rl of remLines) {
          doc.text(rl, MARGIN + 4, y + 2);
          y += 4;
        }
        y += 5;
      }

      // Separator
      y = ensureSpace(doc, y, 6);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.3);
      doc.line(MARGIN, y, PAGE_W - MARGIN, y);
      y += 8;
    });
  }

  // ════════════════════════════════════════════════════════════════════════
  // MODULE SUMMARY
  // ════════════════════════════════════════════════════════════════════════
  if (scan.report?.results && scan.report.results.length > 0) {
    doc.addPage();

    doc.setFillColor(...NAVY);
    doc.rect(0, 0, PAGE_W, 20, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.setTextColor(...WHITE);
    doc.text('Module Summary', MARGIN, 13.5);

    const moduleRows = scan.report.results.map((r: ModuleResult) => {
      let status = 'Clean';
      if (r.errors.length > 0 && r.findings.length > 0) status = 'Vulnerable (with errors)';
      else if (r.findings.length > 0) status = 'Vulnerable';
      else if (r.errors.length > 0) status = 'Error';
      const dur = r.duration_ms < 1000 ? `${r.duration_ms}ms` : `${(r.duration_ms / 1000).toFixed(1)}s`;
      return [r.module, status, String(r.findings.length), dur];
    });

    autoTable(doc, {
      startY: 28,
      margin: { left: MARGIN, right: MARGIN },
      head: [['Module', 'Status', 'Findings', 'Duration']],
      body: moduleRows,
      styles: { font: 'helvetica', fontSize: 8.5, cellPadding: 3 },
      headStyles: { fillColor: [...NAVY], textColor: [...WHITE], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [...LIGHT_GRAY] },
      columnStyles: {
        0: { cellWidth: 55 },
        1: { cellWidth: 45 },
        2: { cellWidth: 25, halign: 'center' },
        3: { cellWidth: 25, halign: 'right' },
      },
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 1) {
          const val = data.cell.raw as string;
          if (val.startsWith('Vulnerable')) {
            data.cell.styles.textColor = [...SEVERITY_COLORS.HIGH];
            data.cell.styles.fontStyle = 'bold';
          } else if (val === 'Error') {
            data.cell.styles.textColor = [...SEVERITY_COLORS.CRITICAL];
            data.cell.styles.fontStyle = 'bold';
          } else {
            data.cell.styles.textColor = [34, 197, 94];
          }
        }
      },
    });

    // Errors section
    const modulesWithErrors = scan.report.results.filter((r: ModuleResult) => r.errors.length > 0);
    if (modulesWithErrors.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      y = (doc as any).lastAutoTable?.finalY ?? 60;
      y += 10;
      y = ensureSpace(doc, y, 30);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(...SEVERITY_COLORS.CRITICAL);
      doc.text('Module Errors', MARGIN, y);
      y += 6;

      modulesWithErrors.forEach((r: ModuleResult) => {
        y = ensureSpace(doc, y, 10);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8.5);
        doc.setTextColor(...DARK_TEXT);
        doc.text(r.module, MARGIN, y);
        y += 4;

        r.errors.forEach((err: string) => {
          y = ensureSpace(doc, y, 5);
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(...SUB_TEXT);
          const errLines = wrapText(doc, `• ${err}`, CONTENT_W - 5);
          for (const el of errLines) {
            y = ensureSpace(doc, y, 4);
            doc.text(el, MARGIN + 3, y);
            y += 3.8;
          }
        });
        y += 3;
      });
    }
  }

  // ── Disclaimer ──
  const lastPage = doc.getNumberOfPages();
  doc.setPage(lastPage);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  y = (doc as any).lastAutoTable?.finalY ?? pageH - 50;
  y = Math.max(y + 15, pageH - 45);
  y = ensureSpace(doc, y, 20);

  doc.setFillColor(248, 250, 252);
  doc.roundedRect(MARGIN, y, CONTENT_W, 16, 2, 2, 'F');
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(7);
  doc.setTextColor(...SUB_TEXT);
  const disclaimer = 'This report was generated automatically by WPSentry. Findings should be validated by a qualified security professional before taking remediation actions. This report is confidential and intended solely for the recipient.';
  const discLines = wrapText(doc, disclaimer, CONTENT_W - 8);
  discLines.forEach((line: string, i: number) => {
    doc.text(line, MARGIN + 4, y + 5 + i * 3.2);
  });

  // ── Add footers to all pages ──
  addFooter(doc);

  // ── Download ──
  const filename = `jwp-security-report-${scan.target.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_')}-${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
}
