// AI-powered remediation generator using Ollama Cloud.
// Batches all unique finding types into a single API call.
// Falls back to the static remediation on rate-limit (429) or any other error.

import type { Finding } from '../types.js';

const OLLAMA_API_URL = 'https://ollama.com/v1/chat/completions';
const MODEL = 'gemma4:31b-cloud';

function buildPrompt(findings: Finding[]): string {
  // Deduplicate by type, keep one representative finding per type
  const byType = new Map<string, Finding>();
  for (const f of findings) {
    if (!byType.has(f.type)) byType.set(f.type, f);
  }

  const items = [...byType.values()].map((f) => ({
    type: f.type,
    severity: f.severity,
    description: f.description,
    evidence_snippet: f.evidence ? f.evidence.slice(0, 150) : undefined,
  }));

  return `You are a WordPress security expert. The following vulnerabilities were found during a security scan.

For each finding, write clear, actionable remediation instructions targeted at a WordPress site owner or developer.
Instructions should be specific, practical, and concise (2-4 sentences or bullet points max).

Return ONLY a valid JSON object with the finding type as the key and the remediation string as the value.
Do NOT include any explanation, markdown, or extra text outside the JSON.

Findings:
${JSON.stringify(items, null, 2)}`;
}

/**
 * Strips reasoning tokens (<think>…</think>) and markdown code fences,
 * then returns the first JSON object found in the string.
 */
function extractJSON(raw: string): string | null {
  // Remove <think>…</think> blocks (reasoning models like Qwen3)
  let text = raw.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

  // Unwrap markdown code fences: ```json … ``` or ``` … ```
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) text = fence[1].trim();

  // Find the outermost JSON object
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;

  return text.slice(start, end + 1);
}

/**
 * Returns null on daily rate-limit exhaustion so the caller can fall back to static text.
 * Retries once with a 3-second delay on temporary overload (429 with retry-after or transient errors).
 */
async function fetchAIRemediations(
  apiKey: string,
  findings: Finding[],
): Promise<Map<string, string> | null> {
  const prompt = buildPrompt(findings);

  const doRequest = async (): Promise<Response> => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 30_000);
    try {
      return await fetch(OLLAMA_API_URL, {
        method: 'POST',
        signal: ac.signal,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: MODEL,
          messages: [{ role: 'user', content: prompt }],
          response_format: { type: 'json_object' },
          temperature: 0.3,
        }),
      });
    } finally {
      clearTimeout(timer);
    }
  };

  let res: Response;
  try {
    res = await doRequest();
  } catch (err) {
    console.error('[ai-remediation] fetch failed:', err);
    return null;
  }

  if (res.status === 429) {
    const body = await res.text().catch(() => '');
    const lower = body.toLowerCase();
    const isTemporary =
      lower.includes('temporarily') ||
      lower.includes('retry shortly') ||
      lower.includes('upstream');
    const isDailyLimit = !isTemporary && (lower.includes('daily') || lower.includes('quota'));

    if (isDailyLimit) {
      console.warn(
        '[ai-remediation] daily limit reached, falling back to static remediations:',
        body,
      );
      return null;
    }

    // Temporary overload — wait and retry once
    console.warn('[ai-remediation] 429 (transient), retrying once after 3s. Response:', body);
    await new Promise((r) => setTimeout(r, 3000));
    try {
      res = await doRequest();
    } catch (err) {
      console.error('[ai-remediation] retry fetch failed:', err);
      return null;
    }
    if (!res.ok) {
      console.error('[ai-remediation] retry failed:', res.status, await res.text().catch(() => ''));
      return null;
    }
  }

  if (!res.ok) {
    console.error('[ai-remediation] API error:', res.status, await res.text().catch(() => ''));
    return null;
  }

  try {
    const json = (await res.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const raw = json.choices?.[0]?.message?.content;
    if (!raw) {
      console.error('[ai-remediation] empty content in response:', JSON.stringify(json).slice(0, 300));
      return null;
    }

    const content = extractJSON(raw);
    if (!content) {
      console.error('[ai-remediation] could not extract JSON from response:', raw.slice(0, 300));
      return null;
    }

    const parsed = JSON.parse(content) as Record<string, unknown>;
    const map = new Map<string, string>();
    for (const [type, remediation] of Object.entries(parsed)) {
      if (typeof remediation === 'string' && remediation.trim()) {
        map.set(type, remediation.trim());
      }
    }
    console.log(`[ai-remediation] enhanced ${map.size} finding type(s)`);
    return map;
  } catch (err) {
    console.error('[ai-remediation] failed to parse AI response:', err);
    return null;
  }
}

/**
 * Enhances the remediation field of each finding using AI-generated instructions.
 * Falls back to the original static remediation if the API is unavailable or rate-limited.
 */
export async function enhanceRemediationsWithAI(
  findings: Finding[],
  apiKey: string | undefined,
): Promise<Finding[]> {
  if (!apiKey || findings.length === 0) return findings;

  const aiMap = await fetchAIRemediations(apiKey, findings);

  // If AI call failed entirely, return findings unchanged
  if (!aiMap) return findings;

  return findings.map((f) => {
    const aiRemediation = aiMap.get(f.type);
    if (!aiRemediation) return f;
    return { ...f, remediation: aiRemediation, remediation_ai: true };
  });
}
