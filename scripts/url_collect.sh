#!/usr/bin/env bash
# url_collect.sh — Collect all URLs for a set of live subdomains
# Phase 2 of bounty-recon: wayback + gau + katana crawl
#
# Input:  $1 = file of live hosts (from httpx output)
#         $2 = output file for all collected URLs
# Usage:  bash url_collect.sh live_hosts.txt all_urls.txt

set -euo pipefail
export PATH="$HOME/.recon-tools/bin:$PATH"

LIVE_FILE="${1:?Usage: url_collect.sh <live_hosts.txt> <all_urls.txt>}"
OUT_FILE="${2:?}"
WORKDIR="/tmp/br_urls_$$"
mkdir -p "$WORKDIR"
> "$OUT_FILE"

echo "[*] Collecting URLs from $(wc -l < "$LIVE_FILE") live hosts..."

# Strip protocol for gau/waybackurls
grep -oP 'https?://\K[^/]+' "$LIVE_FILE" | sort -u > "$WORKDIR/domains.txt"

# 1. Wayback Machine
echo "[*] Wayback Machine..."
while read -r domain; do
    waybackurls "$domain" 2>/dev/null >> "$WORKDIR/wayback.txt" || true
done < "$WORKDIR/domains.txt"
wc -l < "$WORKDIR/wayback.txt" | xargs -I{} echo "  [+] wayback: {} URLs"

# 2. GAU (Wayback + CommonCrawl + AlienVault + URLScan)
echo "[*] GAU..."
cat "$WORKDIR/domains.txt" | gau --threads 5 2>/dev/null >> "$WORKDIR/gau.txt" || true
wc -l < "$WORKDIR/gau.txt" | xargs -I{} echo "  [+] gau: {} URLs"

# 3. Katana active crawler (JS-aware)
echo "[*] Katana crawler..."
katana -list "$LIVE_FILE" -jc -jsl -xhr -d 3 -c 20 \
    -silent -o "$WORKDIR/katana.txt" 2>/dev/null || true
wc -l < "$WORKDIR/katana.txt" | xargs -I{} echo "  [+] katana: {} URLs"

# 4. Merge + deduplicate
cat "$WORKDIR/wayback.txt" "$WORKDIR/gau.txt" "$WORKDIR/katana.txt" 2>/dev/null \
    | grep -v "\.css\|\.js\|\.png\|\.jpg\|\.gif\|\.ico\|\.woff\|\.ttf\|\.svg" \
    | sort -u > "$OUT_FILE"

echo "[+] Total unique URLs: $(wc -l < "$OUT_FILE")"
