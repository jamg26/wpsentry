// Email delivery — supports Resend and Brevo (via REST API).
// Cloudflare Workers cannot make raw TCP/SMTP connections, so Brevo is called via its HTTP API.
//
// Switch provider via EMAIL_PROVIDER env var: "resend" (default) | "brevo"
// Resend:  wrangler secret put RESEND_API_KEY
// Brevo:   wrangler secret put BREVO_API_KEY  (Settings → API Keys in Brevo dashboard)

import type { Env } from '../types.js';

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

async function sendViaResend(env: Env, payload: EmailPayload): Promise<boolean> {
  if (!env.RESEND_API_KEY) {
    console.warn('[email] RESEND_API_KEY not set — skipping');
    return false;
  }

  const from = env.EMAIL_FROM ?? env.RESEND_FROM ?? 'WPSentry <noreply@wpsentry.link>';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [payload.to],
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
      headers: {
        'List-Unsubscribe': '<https://wpsentry.link/settings?tab=notifications>',
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
        'X-Entity-Ref-ID': crypto.randomUUID(),
      },
    }),
  });

  if (!res.ok) {
    console.error(`[email/resend] error ${res.status}: ${await res.text()}`);
    return false;
  }
  return true;
}

async function sendViaBrevo(env: Env, payload: EmailPayload): Promise<boolean> {
  if (!env.BREVO_API_KEY) {
    console.warn('[email] BREVO_API_KEY not set — skipping');
    return false;
  }

  const fromRaw = env.EMAIL_FROM ?? 'WPSentry <noreply@wpsentry.link>';
  // Parse "Name <email>" format into Brevo's sender object
  const match = fromRaw.match(/^(.*?)\s*<(.+?)>$/);
  const sender = match
    ? { name: match[1].trim(), email: match[2].trim() }
    : { email: fromRaw.trim() };

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': env.BREVO_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      sender,
      to: [{ email: payload.to }],
      subject: payload.subject,
      htmlContent: payload.html,
      textContent: payload.text,
    }),
  });

  if (!res.ok) {
    console.error(`[email/brevo] error ${res.status}: ${await res.text()}`);
    return false;
  }
  return true;
}

export async function sendEmail(env: Env, payload: EmailPayload): Promise<boolean> {
  const provider = (env.EMAIL_PROVIDER ?? 'resend').toLowerCase();
  try {
    if (provider === 'brevo') return await sendViaBrevo(env, payload);
    return await sendViaResend(env, payload);
  } catch (err) {
    console.error(`[email/${provider}] Failed to send:`, err);
    return false;
  }
}

