# WPSentry — Agents Guide

## AI Inference Configuration

The scanner uses Ollama Cloud for AI-powered remediation suggestions.

- **Provider**: Ollama Cloud (`https://ollama.com/v1/chat/completions`)
- **Model**: `gemma4:31b-cloud`
- **Config file**: `worker/src/lib/ai-remediation.ts` (constants `OLLAMA_API_URL` and `MODEL`)

### Changing the AI provider or model

1. Edit `OLLAMA_API_URL` and `MODEL` in `worker/src/lib/ai-remediation.ts`
2. Update the `OLLAMA_API_KEY` env var:
   - **Local dev**: Set in `worker/.dev.vars` (gitignored)
   - **Production**: `wrangler secret put OLLAMA_API_KEY`
3. If switching to a non-Ollama provider, adjust the request headers in `fetchAIRemediations()` — Ollama Cloud uses an OpenAI-compatible API, so most providers will work with minimal changes (just update `Authorization: Bearer <key>`).

### API key safety

- **Never** commit API keys to git. `.dev.vars` is gitignored — use it for local secrets only.
- For production, always use `wrangler secret put` — secrets are stored encrypted in Cloudflare and never appear in code.
- The `.dev.vars.example` file is the template for new developers — it contains only placeholder values.