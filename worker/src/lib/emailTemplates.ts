// Email templates for WPSentry transactional emails
// All templates use inline styles for maximum email client compatibility
// Design system: dark bg #0f172a, card bg #1e293b, brand #10b981/#34d399, slate text palette

interface TemplateResult {
  subject: string;
  html: string;
  text: string;
}

// Hidden preheader text (shows in inbox preview before opening)
function preheader(text: string): string {
  return `<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;color:#0f172a;line-height:1px;max-width:0px;opacity:0">${text}&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;</div>`;
}

function baseHtml(content: string, preheaderText = ''): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>WPSentry</title>
</head>
<body style="margin:0;padding:0;background-color:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased">
  ${preheaderText ? preheader(preheaderText) : ''}
  <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#0f172a">
    <tr>
      <td align="center" style="padding:40px 20px">
        <table width="600" cellpadding="0" cellspacing="0" role="presentation" style="max-width:600px;width:100%">

          <!-- Header / Logo -->
          <tr>
            <td style="padding-bottom:28px">
              <table cellpadding="0" cellspacing="0" role="presentation">
                <tr>
                  <td style="background:linear-gradient(135deg,rgba(16,185,129,0.12),rgba(16,185,129,0.04));border:1px solid rgba(16,185,129,0.25);border-radius:10px;width:36px;height:36px;text-align:center;vertical-align:middle">
                    <span style="font-size:18px;line-height:36px">🛡️</span>
                  </td>
                  <td style="padding-left:10px;vertical-align:middle">
                    <span style="font-size:18px;font-weight:700;color:#e2e8f0;letter-spacing:-0.3px">WP<span style="color:#34d399">Sentry</span></span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main card -->
          <tr>
            <td style="background-color:#1e293b;border:1px solid #334155;border-radius:16px;padding:36px 32px">
              ${content}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding-top:28px">
              <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
                <tr>
                  <td style="border-top:1px solid #1e293b;padding-top:20px;text-align:center">
                    <p style="margin:0 0 6px;font-size:12px;color:#475569">
                      <a href="https://wpsentry.link" style="color:#34d399;text-decoration:none;font-weight:500">WPSentry</a>
                      &nbsp;·&nbsp; WordPress Security Scanner
                    </p>
                    <p style="margin:0 0 4px;font-size:11px;color:#334155">
                      You received this because you have a WPSentry account at <strong style="color:#475569">wpsentry.link</strong>
                    </p>
                    <p style="margin:0;font-size:11px;color:#334155">
                      <a href="https://wpsentry.link/settings?tab=notifications" style="color:#475569;text-decoration:underline">Manage email preferences</a>
                      &nbsp;·&nbsp;
                      <a href="https://wpsentry.link/settings?tab=notifications" style="color:#475569;text-decoration:underline">Unsubscribe</a>
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function ctaButton(href: string, label: string, color = '#059669'): string {
  return `<table cellpadding="0" cellspacing="0" role="presentation" style="margin-top:28px">
    <tr>
      <td style="background-color:${color};border-radius:8px">
        <a href="${href}" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;letter-spacing:0.1px">${label}</a>
      </td>
    </tr>
  </table>`;
}

function divider(): string {
  return `<div style="border-top:1px solid #334155;margin:24px 0"></div>`;
}

function metaRow(label: string, value: string): string {
  return `<tr>
    <td style="padding:8px 0;font-size:12px;color:#64748b;width:110px;vertical-align:top">${label}</td>
    <td style="padding:8px 0;font-size:13px;color:#cbd5e1;font-weight:500;vertical-align:top">${value}</td>
  </tr>`;
}

// ── Template 1: Welcome ───────────────────────────────────────────────────

export function welcomeEmail(email: string): TemplateResult {
  const html = baseHtml(`
    <!-- Hero -->
    <div style="text-align:center;padding-bottom:28px;border-bottom:1px solid #334155;margin-bottom:28px">
      <div style="display:inline-block;background:linear-gradient(135deg,rgba(16,185,129,0.12),rgba(16,185,129,0.04));border:1px solid rgba(16,185,129,0.25);border-radius:14px;padding:16px;margin-bottom:20px">
        <span style="font-size:36px">🛡️</span>
      </div>
      <h1 style="margin:0 0 10px;font-size:24px;font-weight:700;color:#e2e8f0;letter-spacing:-0.5px">Welcome to WPSentry</h1>
      <p style="margin:0;font-size:15px;color:#94a3b8;line-height:1.6">Your WordPress security scanner is ready.<br>Let's find what's hiding on your sites.</p>
    </div>

    <!-- Feature list -->
    <p style="margin:0 0 16px;font-size:13px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">What WPSentry detects</p>
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      <tr>
        <td style="padding:8px 0;vertical-align:top;width:28px;font-size:16px">🔴</td>
        <td style="padding:8px 0;font-size:14px;color:#cbd5e1">Critical vulnerabilities &amp; sensitive data exposure</td>
      </tr>
      <tr>
        <td style="padding:8px 0;vertical-align:top;font-size:16px">🔌</td>
        <td style="padding:8px 0;font-size:14px;color:#cbd5e1">Outdated plugins, themes &amp; WordPress core</td>
      </tr>
      <tr>
        <td style="padding:8px 0;vertical-align:top;font-size:16px">⚙️</td>
        <td style="padding:8px 0;font-size:14px;color:#cbd5e1">Security misconfigurations &amp; missing headers</td>
      </tr>
      <tr>
        <td style="padding:8px 0;vertical-align:top;font-size:16px">👤</td>
        <td style="padding:8px 0;font-size:14px;color:#cbd5e1">User enumeration &amp; information disclosure</td>
      </tr>
      <tr>
        <td style="padding:8px 0;vertical-align:top;font-size:16px">💉</td>
        <td style="padding:8px 0;font-size:14px;color:#cbd5e1">Injection vulnerabilities: SQLi, XSS, XXE, SSRF</td>
      </tr>
    </table>

    ${divider()}

    <!-- Free tier callout -->
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#0f172a;border:1px solid #334155;border-radius:10px">
      <tr>
        <td style="padding:16px 20px">
          <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">Your Free Plan</p>
          <p style="margin:0;font-size:16px;font-weight:700;color:#e2e8f0">5 scans / day &nbsp;·&nbsp; 50 scans / month</p>
          <p style="margin:6px 0 0;font-size:12px;color:#64748b">122 security modules &nbsp;·&nbsp; Full vulnerability reports &nbsp;·&nbsp; API access</p>
        </td>
      </tr>
    </table>

    ${ctaButton('https://wpsentry.link/scans/new', 'Start Your First Scan →')}

    <p style="margin:20px 0 0;font-size:12px;color:#475569">Scanning: <strong style="color:#64748b;font-family:monospace">${email}</strong></p>
  `, 'Your WordPress security scanner is ready — 122 modules, 5 scans/day free.');

  const text = `Welcome to WPSentry 🛡️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Your account (${email}) is ready.

WPSentry scans your WordPress sites for:
  • Critical vulnerabilities & exposed credentials
  • Outdated plugins, themes & WordPress core
  • Security misconfigurations & missing headers
  • User enumeration & information disclosure
  • SQLi, XSS, XXE, SSRF injection vulnerabilities

Free Plan: 5 scans/day · 50 scans/month · 122 modules

Start scanning → https://wpsentry.link/scans/new`;

  return { subject: 'Your WPSentry account is ready', html, text };
}

// ── Template 2: Scan Complete ─────────────────────────────────────────────

export function scanCompleteEmail(opts: {
  email: string;
  target: string;
  scanId: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount?: number;
  infoCount?: number;
  duration: string;
}): TemplateResult {
  const { target, scanId, totalFindings, criticalCount, highCount, mediumCount, duration } = opts;
  const lowCount = opts.lowCount ?? 0;
  const reportUrl = `https://wpsentry.link/scans/${scanId}`;
  const shortTarget = target.replace(/^https?:\/\//, '').replace(/\/$/, '');

  const criticalBanner = criticalCount > 0
    ? `<div style="background:#450a0a;border:1px solid #7f1d1d;border-radius:8px;padding:14px 18px;margin-bottom:20px">
        <p style="margin:0;font-size:13px;font-weight:600;color:#fca5a5">⚠️&nbsp; Critical vulnerabilities found — immediate action recommended</p>
       </div>`
    : totalFindings === 0
      ? `<div style="background:#052e16;border:1px solid #166534;border-radius:8px;padding:14px 18px;margin-bottom:20px">
          <p style="margin:0;font-size:13px;font-weight:600;color:#86efac">✅&nbsp; No significant issues found — your site looks healthy</p>
         </div>`
      : '';

  type SeverityRow = [string, number, string, string];
  const severityRows: SeverityRow[] = [
    ['CRITICAL', criticalCount, '#ef4444', '#7f1d1d'],
    ['HIGH',     highCount,     '#f97316', '#7c2d12'],
    ['MEDIUM',   mediumCount,   '#eab308', '#713f12'],
    ['LOW',      lowCount,      '#64748b', '#1e293b'],
  ];

  const severityTable = totalFindings > 0 ? `
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="margin-top:16px">
      ${severityRows.filter(([, count]) => count > 0).map(([label, count, color, bg]) => `
      <tr>
        <td style="padding:6px 0;width:90px">
          <span style="display:inline-block;background:${bg};border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;color:${color};letter-spacing:0.05em">${label}</span>
        </td>
        <td style="padding:6px 0">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
            <tr>
              <td style="background:#0f172a;border-radius:99px;height:6px;overflow:hidden">
                <div style="background:${color};width:${Math.min(100, Math.round((count / Math.max(totalFindings, 1)) * 100))}%;height:6px;border-radius:99px"></div>
              </td>
              <td style="width:36px;text-align:right;font-size:13px;font-weight:600;color:#e2e8f0;padding-left:10px">${count}</td>
            </tr>
          </table>
        </td>
      </tr>`).join('')}
    </table>` : '';

  const html = baseHtml(`
    <!-- Title -->
    <h1 style="margin:0 0 6px;font-size:22px;font-weight:700;color:#e2e8f0;letter-spacing:-0.3px">Scan Complete</h1>
    <p style="margin:0 0 24px;font-size:13px;color:#64748b">
      <span style="color:#34d399;font-family:monospace">${shortTarget}</span>
      &nbsp;·&nbsp; ${duration}
    </p>

    ${criticalBanner}

    <!-- Stats row -->
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#0f172a;border:1px solid #334155;border-radius:10px;margin-bottom:24px">
      <tr>
        <td style="padding:20px 24px;border-right:1px solid #334155;text-align:center;width:50%">
          <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">Total Findings</p>
          <p style="margin:0;font-size:36px;font-weight:700;color:${totalFindings === 0 ? '#4ade80' : criticalCount > 0 ? '#ef4444' : '#e2e8f0'}">${totalFindings}</p>
        </td>
        <td style="padding:20px 24px;text-align:center;width:50%">
          <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">Scan Duration</p>
          <p style="margin:0;font-size:22px;font-weight:700;color:#e2e8f0">${duration}</p>
        </td>
      </tr>
    </table>

    ${severityTable}

    ${divider()}

    <!-- Meta -->
    <table cellpadding="0" cellspacing="0" role="presentation" style="margin-bottom:4px">
      ${metaRow('Target', shortTarget)}
      ${metaRow('Scan ID', `<span style="font-family:monospace;font-size:12px">${scanId}</span>`)}
    </table>

    ${ctaButton(reportUrl, 'View Full Report →')}
  `, `${totalFindings} finding${totalFindings !== 1 ? 's' : ''} on ${shortTarget} · ${criticalCount > 0 ? `${criticalCount} CRITICAL` : 'scan complete'}`);

  const text = `Scan Complete — ${shortTarget}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target:   ${target}
Duration: ${duration}
Findings: ${totalFindings}

  CRITICAL : ${criticalCount}
  HIGH     : ${highCount}
  MEDIUM   : ${mediumCount}
  LOW      : ${lowCount}

View full report → ${reportUrl}`;

  return {
    subject: totalFindings === 0
      ? `Scan complete: ${shortTarget} — no issues detected`
      : criticalCount > 0
        ? `Security scan results: ${criticalCount} critical issue${criticalCount !== 1 ? 's' : ''} on ${shortTarget}`
        : `Scan complete: ${shortTarget} — ${totalFindings} issue${totalFindings !== 1 ? 's' : ''} found`,
    html,
    text,
  };
}

// ── Template 3: Critical Alert ────────────────────────────────────────────

export function criticalAlertEmail(opts: {
  email: string;
  target: string;
  scanId: string;
  criticalCount: number;
  findings: Array<{ type: string; url: string; description: string }>;
}): TemplateResult {
  const { target, scanId, criticalCount, findings } = opts;
  const reportUrl = `https://wpsentry.link/scans/${scanId}`;
  const shortTarget = target.replace(/^https?:\/\//, '').replace(/\/$/, '');

  const findingRows = findings.slice(0, 5).map((f, i) => {
    const shortUrl = f.url.length > 65 ? f.url.slice(0, 62) + '…' : f.url;
    const shortDesc = (f.description ?? '').length > 130 ? f.description.slice(0, 127) + '…' : (f.description ?? 'See full report for details.');
    return `<tr>
      <td style="padding:14px 0;${i > 0 ? 'border-top:1px solid #3f0a0a;' : ''}vertical-align:top">
        <p style="margin:0 0 3px;font-size:11px;font-weight:700;color:#f87171;letter-spacing:0.07em;text-transform:uppercase">${f.type.replace(/_/g, ' ')}</p>
        <p style="margin:0 0 5px;font-size:11px;color:#475569;font-family:monospace;word-break:break-all">${shortUrl}</p>
        <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.5">${shortDesc}</p>
      </td>
    </tr>`;
  }).join('');

  const html = baseHtml(`
    <!-- Alert banner -->
    <div style="background:#450a0a;border:1px solid #991b1b;border-radius:10px;padding:18px 20px;margin-bottom:28px;text-align:center">
      <p style="margin:0 0 4px;font-size:28px">🚨</p>
      <p style="margin:0 0 4px;font-size:18px;font-weight:700;color:#fca5a5">${criticalCount} Critical Vulnerabilit${criticalCount !== 1 ? 'ies' : 'y'} Found</p>
      <p style="margin:0;font-size:13px;color:#ef4444;font-family:monospace">${shortTarget}</p>
    </div>

    <h2 style="margin:0 0 6px;font-size:16px;font-weight:600;color:#e2e8f0">Review recommended</h2>
    <p style="margin:0 0 20px;font-size:13px;color:#94a3b8;line-height:1.6">The following critical vulnerabilities were detected during your scan. These findings may require attention. Review the full report for remediation guidance.</p>

    ${divider()}

    <!-- Findings list -->
    <p style="margin:0 0 12px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">Critical Findings ${findings.length > 5 ? `(showing 5 of ${findings.length})` : ''}</p>
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      ${findingRows || `<tr><td style="padding:12px 0;font-size:13px;color:#94a3b8">See full report for details.</td></tr>`}
    </table>

    ${divider()}

    <p style="margin:0 0 4px;font-size:13px;color:#94a3b8">View the complete report with remediation guidance:</p>
    ${ctaButton(reportUrl, 'View & Remediate →', '#dc2626')}
  `, `🚨 ${criticalCount} critical vulnerabilit${criticalCount !== 1 ? 'ies' : 'y'} detected on ${shortTarget} — immediate action required`);

  const findingsList = findings.slice(0, 5)
    .map((f) => `  • ${f.type.replace(/_/g, ' ')}: ${f.url}`)
    .join('\n');

  const text = `🚨 Critical Vulnerabilities Found — ${shortTarget}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${criticalCount} critical issue${criticalCount !== 1 ? 's' : ''} detected. Immediate action required.

${findingsList}
${findings.length > 5 ? `\n  ...and ${findings.length - 5} more. See full report.` : ''}

View full report & remediation → ${reportUrl}`;

  return {
    subject: `Security alert: ${criticalCount} critical issue${criticalCount !== 1 ? 's' : ''} detected on ${shortTarget}`,
    html,
    text,
  };
}

// ── Template 4: Password Reset ────────────────────────────────────────────

export function passwordResetEmail(opts: {
  email: string;
  resetToken: string;
  expiresInMinutes: number;
}): TemplateResult {
  const { email, resetToken, expiresInMinutes } = opts;
  const resetUrl = `https://wpsentry.link/reset-password?token=${resetToken}`;

  const html = baseHtml(`
    <div style="text-align:center;padding-bottom:24px;border-bottom:1px solid #334155;margin-bottom:24px">
      <div style="font-size:40px;margin-bottom:12px">🔑</div>
      <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#e2e8f0;letter-spacing:-0.3px">Reset your password</h1>
      <p style="margin:0;font-size:14px;color:#94a3b8">For your WPSentry account: <strong style="color:#cbd5e1">${email}</strong></p>
    </div>

    <p style="margin:0 0 20px;font-size:14px;color:#94a3b8;line-height:1.6;text-align:center">Click the button below to set a new password. This link will expire in <strong style="color:#e2e8f0">${expiresInMinutes} minutes</strong>.</p>

    <div style="text-align:center">
      ${ctaButton(resetUrl, 'Reset Password →')}
    </div>

    ${divider()}

    <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px 16px">
      <p style="margin:0;font-size:12px;color:#64748b;line-height:1.6">🔒 <strong style="color:#94a3b8">Security notice:</strong> If you didn't request a password reset, you can safely ignore this email. Your password will not change. If you're concerned about unauthorized access, please update your password and contact <a href="mailto:abuse@wpsentry.link" style="color:#34d399;text-decoration:none">abuse@wpsentry.link</a>.</p>
    </div>
  `, `Reset your WPSentry password — link expires in ${expiresInMinutes} minutes`);

  const text = `Reset your WPSentry password
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Account: ${email}

Click the link below to reset your password.
This link expires in ${expiresInMinutes} minutes.

→ ${resetUrl}

If you didn't request this, ignore this email — your password will not change.`;

  return { subject: 'Reset your WPSentry password', html, text };
}

// ── Template 5: API Key Created ───────────────────────────────────────────

export function apiKeyCreatedEmail(opts: {
  email: string;
  keyPreview: string;
}): TemplateResult {
  const { email, keyPreview } = opts;

  const html = baseHtml(`
    <h1 style="margin:0 0 6px;font-size:22px;font-weight:700;color:#e2e8f0;letter-spacing:-0.3px">New API key created</h1>
    <p style="margin:0 0 24px;font-size:14px;color:#94a3b8">A new API key has been generated for your WPSentry account.</p>

    <!-- Key display -->
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#0f172a;border:1px solid #334155;border-radius:10px;margin-bottom:20px">
      <tr>
        <td style="padding:16px 20px">
          <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.08em">Key Prefix</p>
          <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#34d399;font-family:'Courier New',Courier,monospace;letter-spacing:1px">${keyPreview}<span style="color:#475569">••••••••••••••••</span></p>
          <p style="margin:0;font-size:12px;color:#475569">Account: ${email}</p>
        </td>
      </tr>
    </table>

    <!-- Security alert -->
    <div style="background:#172554;border:1px solid #1d4ed8;border-radius:10px;padding:16px 20px;margin-bottom:8px">
      <p style="margin:0 0 6px;font-size:13px;font-weight:600;color:#93c5fd">🔐 Didn't create this key?</p>
      <p style="margin:0;font-size:13px;color:#60a5fa;line-height:1.6">Contact <a href="mailto:abuse@wpsentry.link" style="color:#34d399;font-weight:600;text-decoration:none">abuse@wpsentry.link</a> immediately and revoke all API keys from your settings. Someone may have accessed your account.</p>
    </div>

    ${ctaButton('https://wpsentry.link/settings', 'Manage API Keys →')}
  `, `A new API key (${keyPreview}…) was created for your WPSentry account`);

  const text = `New API key created — WPSentry
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Account: ${email}
Key prefix: ${keyPreview}…

If you created this key, no action needed.

⚠️  If you DIDN'T create this key:
Contact abuse@wpsentry.link immediately and revoke all keys:
→ https://wpsentry.link/settings`;

  return { subject: 'New API key created for your WPSentry account', html, text };
}

// ── Template 6: Email Verification ───────────────────────────────────────

export function verifyEmailTemplate(opts: {
  email: string;
  verifyToken: string;
}): TemplateResult {
  const { email, verifyToken } = opts;
  const verifyUrl = `https://wpsentry.link/verify-email?token=${verifyToken}`;

  const html = baseHtml(`
    <div style="text-align:center;padding-bottom:24px;border-bottom:1px solid #334155;margin-bottom:24px">
      <div style="font-size:40px;margin-bottom:12px">✉️</div>
      <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#e2e8f0;letter-spacing:-0.3px">Confirm your email</h1>
      <p style="margin:0;font-size:14px;color:#94a3b8">One click and you're ready to scan</p>
    </div>

    <p style="margin:0 0 8px;font-size:14px;color:#94a3b8;text-align:center">Click below to verify <strong style="color:#cbd5e1">${email}</strong> and activate your WPSentry account.</p>
    <p style="margin:0 0 24px;font-size:12px;color:#475569;text-align:center">This link expires in <strong style="color:#64748b">24 hours</strong>.</p>

    <div style="text-align:center">
      ${ctaButton(verifyUrl, 'Verify Email Address →')}
    </div>

    ${divider()}

    <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px 16px">
      <p style="margin:0;font-size:12px;color:#475569;line-height:1.6">Can't click the button? Copy this link into your browser:<br>
      <span style="color:#34d399;font-family:monospace;font-size:11px;word-break:break-all">${verifyUrl}</span></p>
    </div>
  `, `Verify your email to start scanning with WPSentry`);

  const text = `Verify your WPSentry email
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Click the link below to verify ${email} (expires in 24 hours):

→ ${verifyUrl}

If you didn't create a WPSentry account, ignore this email.`;

  return { subject: 'Verify your WPSentry email address', html, text };
}
