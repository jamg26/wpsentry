#!/usr/bin/env bash
# jwp-scan.sh — WPSentry CI/CD helper
#
# Usage:
#   WPS_API_KEY=wps_live_... ./jwp-scan.sh https://your-site.com
#   WPS_API_KEY=wps_live_... ./jwp-scan.sh https://your-site.com --fail-on high
#
# Options:
#   --fail-on <severity>   Exit 1 if findings at this severity or above exist.
#                          Values: critical (default) | high | medium
#   --timeout <seconds>    Max seconds to wait for scan completion (default: 360)
#   --tag <value>          Tag to attach to the scan (repeatable)
#
# Exit codes:
#   0  Scan completed, no findings at or above --fail-on severity
#   1  Scan completed, findings found at or above --fail-on severity
#   2  Scan failed or timed out
#   3  API error (bad key, rate limit, etc.)

set -euo pipefail

WORKER_URL="https://api.wpsentry.link"
TARGET=""
FAIL_ON="critical"
TIMEOUT=360
TAGS=()

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    http*) TARGET="$1"; shift ;;
    --fail-on) FAIL_ON="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --tag) TAGS+=("$2"); shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Usage: WPS_API_KEY=<key> $0 <target-url> [--fail-on critical|high|medium] [--tag value]" >&2
  exit 2
fi

if [[ -z "${WPS_API_KEY:-}" ]]; then
  echo "Error: WPS_API_KEY environment variable is required." >&2
  exit 3
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
api() {
  curl -sf -H "Authorization: Bearer $WPS_API_KEY" "$@"
}

# Build tags JSON array
TAGS_JSON="[]"
if [[ ${#TAGS[@]} -gt 0 ]]; then
  TAGS_JSON=$(printf '%s\n' "${TAGS[@]}" | jq -R . | jq -s .)
fi

# ── 1. Trigger scan ───────────────────────────────────────────────────────────
echo "→ Triggering scan for $TARGET …"
# By using this script, you certify you have explicit written authorization to scan the target.
# See Terms of Service: https://wpsentry.link/terms
RESPONSE=$(api -X POST \
  -H "Content-Type: application/json" \
  -d "{\"target\":\"$TARGET\",\"tags\":$TAGS_JSON,\"authorization_confirmed\":true}" \
  "$WORKER_URL/scans") || {
    echo "✗ Failed to create scan. Check your API key and target URL." >&2
    exit 3
  }

HTTP_STATUS=$(echo "$RESPONSE" | jq -r '.error // empty')
if [[ -n "$HTTP_STATUS" ]]; then
  if echo "$RESPONSE" | jq -e '.error == "rate_limit"' > /dev/null 2>&1; then
    RESET=$(echo "$RESPONSE" | jq -r '.reset_daily_at')
    REMAINING=$(echo "$RESPONSE" | jq -r '.daily_remaining')
    echo "✗ Rate limit reached ($REMAINING scans remaining today). Resets at $RESET" >&2
    exit 3
  fi
  echo "✗ API error: $(echo "$RESPONSE" | jq -r '.message // .error')" >&2
  exit 3
fi

SCAN_ID=$(echo "$RESPONSE" | jq -r '.id')
echo "  Scan ID: $SCAN_ID"

# ── 2. Poll for completion ────────────────────────────────────────────────────
echo "→ Waiting for scan to complete (timeout: ${TIMEOUT}s) …"
INTERVAL=10
ELAPSED=0
STATUS="queued"

while [[ "$STATUS" != "completed" && "$STATUS" != "failed" ]]; do
  if [[ $ELAPSED -ge $TIMEOUT ]]; then
    echo "✗ Scan timed out after ${TIMEOUT}s. Scan ID: $SCAN_ID" >&2
    exit 2
  fi

  sleep $INTERVAL
  ELAPSED=$((ELAPSED + INTERVAL))

  POLL=$(api "$WORKER_URL/scans/$SCAN_ID") || { echo "✗ Poll request failed." >&2; exit 2; }
  STATUS=$(echo "$POLL" | jq -r '.status')
  COMPLETED=$(echo "$POLL" | jq -r '.by_severity.critical // "?"')
  echo "  [${ELAPSED}s] status=$STATUS  critical=$COMPLETED"
done

if [[ "$STATUS" == "failed" ]]; then
  ERROR=$(echo "$POLL" | jq -r '.error_message // "unknown error"')
  echo "✗ Scan failed: $ERROR" >&2
  exit 2
fi

# ── 3. Evaluate results ───────────────────────────────────────────────────────
CRITICAL=$(echo "$POLL" | jq '.by_severity.critical')
HIGH=$(echo "$POLL" | jq '.by_severity.high')
MEDIUM=$(echo "$POLL" | jq '.by_severity.medium')
LOW=$(echo "$POLL" | jq '.by_severity.low')
TOTAL=$(echo "$POLL" | jq '.findings_count')

echo ""
echo "┌─ Scan Results ────────────────────────────────────────┐"
echo "│  Target:   $TARGET"
echo "│  Scan ID:  $SCAN_ID"
echo "│  Total:    $TOTAL findings"
echo "│  Critical: $CRITICAL  High: $HIGH  Medium: $MEDIUM  Low: $LOW"
echo "└───────────────────────────────────────────────────────┘"
echo "  View full report: https://wpsentry.link/scans/$SCAN_ID"
echo ""

# Determine exit code based on --fail-on threshold
case $FAIL_ON in
  critical) FAIL_COUNT=$CRITICAL ;;
  high)     FAIL_COUNT=$((CRITICAL + HIGH)) ;;
  medium)   FAIL_COUNT=$((CRITICAL + HIGH + MEDIUM)) ;;
  *)
    echo "✗ Unknown --fail-on value: $FAIL_ON (use: critical, high, medium)" >&2
    exit 2
    ;;
esac

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "✗ FAILED — $FAIL_COUNT finding(s) at or above '$FAIL_ON' severity." >&2
  exit 1
fi

echo "✓ PASSED — No findings at or above '$FAIL_ON' severity."
exit 0
