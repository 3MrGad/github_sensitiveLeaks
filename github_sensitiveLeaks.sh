
#!/usr/bin/env bash
set -uo pipefail

# Usage:
# export GITHUB_TOKEN="your_token"
# ./scan_repos.sh 'org:YOUR_ORG security'
#
# Scans repositories within an authorized GitHub scope.

OUTPUT_DIR="./trufflehog_results"
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 '<authorized GitHub search query>'"
    echo "Example: $0 'org:YOUR_ORG security'"
    exit 1
fi

QUERY="$1"

for cmd in curl python3 trufflehog; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[-] Required command not found: $cmd"
        exit 1
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

API_URL="https://api.github.com/search/repositories"

echo "[*] Searching authorized repository scope..."

CURL_ARGS=(
    -fsS -G "$API_URL"
    --data-urlencode "q=$QUERY"
    --data-urlencode "per_page=100"
    -H "Accept: application/vnd.github+json"
)

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_ARGS+=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

if ! curl "${CURL_ARGS[@]}" > "$TMP_DIR/search.json"; then
    echo "[-] GitHub API request failed."
    echo "    Check your query, network, token, and API rate limit."
    exit 1
fi

# Extract repository metadata and create collision-resistant filenames.
python3 - "$TMP_DIR/search.json" "$TMP_DIR/repos.tsv" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

if "items" not in data:
    print("GitHub API error:", data.get("message", "Unexpected response"))
    sys.exit(1)

with open(sys.argv[2], "w", encoding="utf-8") as out:
    for repo in data["items"]:
        name = repo["full_name"]
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        print(f'{name}\t{repo["clone_url"]}\t{safe_name}', file=out)
PY

if [[ ! -f "$TMP_DIR/repos.tsv" ]]; then
    echo "[-] Failed to parse GitHub API response."
    exit 1
fi

TOTAL=$(wc -l < "$TMP_DIR/repos.tsv")
if (( TOTAL == 0 )); then
    echo "[-] No repositories found in the authorized scope."
    exit 0
fi

echo "[*] Found $TOTAL repositories (maximum 100 per request)."

SCANNED=0
FAILED=0
WITH_FINDINGS=0

while IFS=$'\t' read -r FULL_NAME REPO_URL SAFE_NAME; do
    [[ -z "$REPO_URL" ]] && continue

    SCANNED=$((SCANNED + 1))
    RESULT_FILE="$TMP_DIR/result.jsonl"
    ERROR_FILE="$TMP_DIR/error.log"

    echo
    echo "[*] [$SCANNED/$TOTAL] Scanning $FULL_NAME"

    # Compatible with the command syntax in the original script.
    if ! trufflehog github --repo "$REPO_URL" --json \
        > "$RESULT_FILE" 2> "$ERROR_FILE"; then
        echo "[-] Scan failed: $FULL_NAME"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Count JSON records; do not print detected secret values.
    read -r VERIFIED UNVERIFIED RECORDS < <(
        python3 - "$RESULT_FILE" <<'PY'
import json
import sys

verified = unverified = records = 0

with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(item, dict):
            continue

        # Ignore non-finding progress records.
        if not any(k in item for k in ("DetectorName", "DetectorType", "Raw", "RawV2")):
            continue

        records += 1
        value = item.get("Verified", item.get("verified", False))
        if value is True:
            verified += 1
        else:
            verified += 0
            unverified += 1

print(verified, unverified, records)
PY
    )

    if (( RECORDS > 0 )); then
        WITH_FINDINGS=$((WITH_FINDINGS + 1))
        DEST="$OUTPUT_DIR/${SAFE_NAME}_findings.jsonl"
        cp "$RESULT_FILE" "$DEST"
        chmod 600 "$DEST"
        echo "[!] Potential findings: $RECORDS"
        echo "    Verified: $VERIFIED | Unverified: $UNVERIFIED"
        echo "    Details saved locally: $DEST"
    else
        echo "[+] No finding records reported."
    fi

    sleep 2
done < "$TMP_DIR/repos.tsv"

echo
echo "========== Summary =========="
echo "Repositories processed: $SCANNED"
echo "Repositories with findings: $WITH_FINDINGS"
echo "Failed scans: $FAILED"
echo "Output directory: $OUTPUT_DIR"
echo "=============================="
