// Analytics Engine event helpers

import type { Env } from '../types.js';

type EventName =
  | 'scan_created'
  | 'scan_completed'
  | 'scan_failed'
  | 'auth_signup'
  | 'auth_login'
  | 'rate_limit_hit'
  | 'error';

interface EventData {
  user_id?: string;
  target_domain?: string;
  scan_id?: string;
  status?: string;
  module_count?: number;
  findings_count?: number;
  duration_ms?: number;
  error?: string;
}

export function trackEvent(env: Env, event: EventName, data: EventData = {}): void {
  try {
    env.ANALYTICS.writeDataPoint({
      blobs: [
        event,
        data.user_id ?? '',
        data.target_domain ?? '',
        data.scan_id ?? '',
        data.status ?? '',
        data.error ?? '',
      ],
      doubles: [
        data.module_count ?? 0,
        data.findings_count ?? 0,
        data.duration_ms ?? 0,
      ],
      indexes: [event],
    });
  } catch {
    // Never let analytics failures affect the main request
  }
}
