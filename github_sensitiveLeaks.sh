#!/bin/bash

# Usage: ./scan_repos.sh "meesho.com"
QUERY="${1:-meesho.com}"
OUTPUT_DIR="./trufflehog_results"
mkdir -p "$OUTPUT_DIR"

echo "[*] Fetching repos for query: $QUERY"

# Fetch repo URLs from GitHub search API (up to 100 results)
REPOS=$(curl -s "https://api.github.com/search/repositories?q=${QUERY}&per_page=100" \
  -H "Authorization: token Your github token" \
  -H "Accept: application/vnd.github.v3+json" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    print(item['clone_url'])
")

if [ -z "$REPOS" ]; then
  echo "[-] No repos found or API rate limited"
  exit 1
fi

TOTAL=$(echo "$REPOS" | wc -l)
echo "[*] Found $TOTAL repos. Starting TruffleHog scans..."
echo "----------------------------------------"

COUNT=0
FINDINGS=0

while IFS= read -r REPO_URL; do
  COUNT=$((COUNT + 1))
  REPO_NAME=$(basename "$REPO_URL" .git)
  echo "[*] [$COUNT/$TOTAL] Scanning: $REPO_URL"

  RESULT=$(trufflehog github --repo "$REPO_URL" --json 2>/dev/null)
  
  VERIFIED=$(echo "$RESULT" | grep -c '"verified":true' 2>/dev/null || echo 0)
  UNVERIFIED=$(echo "$RESULT" | grep -c '"verified":false' 2>/dev/null || echo 0)

  if [ "$VERIFIED" -gt 0 ] || [ "$UNVERIFIED" -gt 0 ]; then
    FINDINGS=$((FINDINGS + 1))
    echo "[!!!] SECRETS FOUND in $REPO_URL"
    echo "[!!!] Verified: $VERIFIED | Unverified: $UNVERIFIED"
    echo "$RESULT" > "$OUTPUT_DIR/${REPO_NAME}_secrets.json"
    echo "[*] Saved to $OUTPUT_DIR/${REPO_NAME}_secrets.json"
  else
    echo "[-] Clean: $REPO_URL"
  fi

  echo "----------------------------------------"
  # Small delay to avoid GitHub rate limiting
  sleep 2

done <<< "$REPOS"

echo ""
echo "[*] Scan complete."
echo "[*] Total repos scanned: $COUNT"
echo "[*] Repos with findings: $FINDINGS"
echo "[*] Results saved in: $OUTPUT_DIR"
