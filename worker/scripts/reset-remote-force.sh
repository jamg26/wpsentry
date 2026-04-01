#!/bin/bash
# Full factory reset of all remote Cloudflare resources (no confirmation prompt).
# Usage: npm run reset:remote:force  (from worker/)
set -e

ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?Error: CLOUDFLARE_ACCOUNT_ID env var is not set. Run: export CLOUDFLARE_ACCOUNT_ID=<your-id>}"

echo "🗑  Force-resetting ALL remote resources (no confirmation)..."
echo ""

# ── 1/4  D1 ───────────────────────────────────────────────────────────────────
echo "🗑  [1/4] Clearing D1 database..."
CLOUDFLARE_ACCOUNT_ID=$ACCOUNT_ID npx wrangler d1 execute jwp-db --remote --command "
  DELETE FROM usage;
  DELETE FROM api_keys;
  DELETE FROM scans;
  DELETE FROM users;
" 2>&1
echo "✅  D1 cleared."
echo ""

# ── 2/4  KV ───────────────────────────────────────────────────────────────────
echo "🗑  [2/4] Clearing KV namespaces..."

clear_kv() {
  local ns_id="$1"
  local ns_name="$2"
  echo "  Clearing ${ns_name} (${ns_id})..."

  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
    # Fast path: REST API — paginated list then bulk delete (up to 10 000 keys/request)
    ACCOUNT_ID="$ACCOUNT_ID" NS_ID="$ns_id" NS_NAME="$ns_name" \
    CF_TOKEN="$CLOUDFLARE_API_TOKEN" python3 - <<'PYEOF'
import os, json, sys, urllib.request, urllib.error

account_id = os.environ["ACCOUNT_ID"]
ns_id      = os.environ["NS_ID"]
ns_name    = os.environ["NS_NAME"]
token      = os.environ["CF_TOKEN"]
base       = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}"
headers    = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

def cf_request(method, url, body=None):
    req = urllib.request.Request(url, method=method,
          data=json.dumps(body).encode() if body is not None else None,
          headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"    HTTP error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)

all_keys = []
cursor = None
while True:
    url = f"{base}/keys?limit=1000" + (f"&cursor={cursor}" if cursor else "")
    res = cf_request("GET", url)
    batch = [k["name"] for k in res.get("result", [])]
    all_keys.extend(batch)
    cursor = (res.get("result_info") or {}).get("cursor")
    if not cursor or not batch:
        break

if not all_keys:
    print("    (empty, skipping)")
    sys.exit(0)

print(f"    Deleting {len(all_keys)} keys via API...")
for i in range(0, len(all_keys), 10000):
    cf_request("DELETE", f"{base}/bulk", all_keys[i:i + 10000])
print(f"    ✅ {ns_name} cleared.")
PYEOF
  else
    # Slow path: wrangler CLI, key by key (no API token available)
    local keys
    keys=$(CLOUDFLARE_ACCOUNT_ID=$ACCOUNT_ID npx wrangler kv key list \
      --namespace-id "$ns_id" --remote 2>/dev/null \
      | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for k in data:
        print(k['name'])
except Exception:
    pass
" 2>/dev/null || true)

    if [ -z "$keys" ]; then
      echo "    (empty, skipping)"
      return
    fi

    local count
    count=$(printf '%s\n' "$keys" | grep -c . 2>/dev/null || echo 0)
    echo "    Deleting ${count} keys via wrangler (may be slow for large namespaces)..."
    while IFS= read -r key; do
      [ -z "$key" ] && continue
      CLOUDFLARE_ACCOUNT_ID=$ACCOUNT_ID npx wrangler kv key delete "$key" \
        --namespace-id "$ns_id" --remote 2>/dev/null || true
    done <<< "$keys"
    echo "    ✅ ${ns_name} cleared."
  fi
}

clear_kv "${SESSIONS_KV_ID:?Error: SESSIONS_KV_ID env var is not set. Find it with: wrangler kv namespace list}" "SESSIONS_KV"
clear_kv "${RATELIMIT_KV_ID:?Error: RATELIMIT_KV_ID env var is not set. Find it with: wrangler kv namespace list}" "RATELIMIT_KV"
echo "✅  KV namespaces cleared."
echo ""

# ── 3/4  R2 ───────────────────────────────────────────────────────────────────
echo "🗑  [3/4] Clearing R2 bucket (jwp-scan-reports)..."

# Resolve API token: explicit env var → wrangler stored oauth_token
_r2_token="${CLOUDFLARE_API_TOKEN:-}"
if [ -z "$_r2_token" ]; then
  _r2_token=$(python3 -c "
import re, os
for p in ['$HOME/.config/.wrangler/config/default.toml', '$HOME/.wrangler/config/default.toml']:
    try:
        m = re.search(r'oauth_token\s*=\s*\"([^\"]+)\"', open(p).read())
        if m: print(m.group(1)); break
    except: pass
" 2>/dev/null || true)
fi

if [ -n "$_r2_token" ]; then
  ACCOUNT_ID="$ACCOUNT_ID" CF_TOKEN="$_r2_token" python3 - <<'PYEOF'
import os, json, sys, urllib.request, urllib.error, urllib.parse

account_id = os.environ["ACCOUNT_ID"]
token      = os.environ["CF_TOKEN"]
bucket     = "jwp-scan-reports"
base       = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/r2/buckets/{bucket}"
headers    = {"Authorization": f"Bearer {token}"}

def cf_get(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  HTTP error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)

def cf_delete(url):
    req = urllib.request.Request(url, method="DELETE", headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"  DELETE failed HTTP {e.code}: {e.read().decode()}", file=sys.stderr)

total = 0
cursor = None
while True:
    url = f"{base}/objects?limit=1000" + (f"&cursor={cursor}" if cursor else "")
    res = cf_get(url)
    result  = res.get("result") or {}
    objects = result.get("objects") if isinstance(result, dict) else result
    objects = objects or []
    if not objects:
        break
    for obj in objects:
        cf_delete(f"{base}/objects/{urllib.parse.quote(obj['key'], safe='')}")
        total += 1
    cursor = (result.get("cursor") if isinstance(result, dict) else None) \
             or (res.get("result_info") or {}).get("cursor")
    if not cursor:
        break

if total == 0:
    print("  (bucket empty, skipping)")
else:
    print(f"  Deleted {total} objects.")
PYEOF
else
  echo "  ⚠️  No API token found (CLOUDFLARE_API_TOKEN not set and no wrangler auth stored)."
  echo "     Run 'npx wrangler login' or set CLOUDFLARE_API_TOKEN, then re-run."
  echo "     Or empty the bucket manually: https://dash.cloudflare.com/${ACCOUNT_ID}/r2/default/buckets/jwp-scan-reports"
fi
echo "✅  R2 step complete."
echo ""

# ── 4/4  Queues ───────────────────────────────────────────────────────────────
echo "⚠️  [4/4] Queues: wrangler has no 'purge queue' command."
echo "   Messages in jwp-scan-jobs and jwp-scan-jobs-dlq expire naturally (≤4 days)."
echo "   To force-clear: temporarily disable the queue consumer in wrangler.toml,"
echo "   deploy, wait a few minutes, then re-enable and redeploy."
echo ""
echo "🎉  Full remote reset complete."
echo "    Run 'npm run db:migrate:remote' to re-apply the schema if needed."
