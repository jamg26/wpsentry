// Email delivery via Resend REST API
// Docs: https://resend.com/docs/api-reference/emails/send-email
// Set secret: wrangler secret put RESEND_API_KEY

import type { Env } from '../types.js';

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(env: Env, payload: EmailPayload): Promise<boolean> {
  if (!env.RESEND_API_KEY) {
    console.warn('[email] RESEND_API_KEY not set — skipping email delivery');
    return false;
  }

  const from = env.RESEND_FROM ?? 'WPSentry <noreply@wpsentry.link>';

  try {
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
          'List-Unsubscribe': `<https://wpsentry.link/settings?tab=notifications>`,
          'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
          'X-Entity-Ref-ID': crypto.randomUUID(),
        },
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error(`[email] Resend error ${res.status}: ${err}`);
      return false;
    }

    return true;
  } catch (err) {
    console.error('[email] Failed to send:', err);
    return false;
  }
}
