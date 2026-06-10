#!/usr/bin/env bash
# bounty-recon run_all.sh — Full end-to-end pipeline: recon → vuln scan → report
#
# Usage: bash run_all.sh "OrgName" "domain1.com,domain2.com" [collab_host]
# Output: ~/Desktop/<OrgName>_bounty_report.md

set -euo pipefail
export PATH="$HOME/.recon-tools/bin:$PATH"
source ~/.recon-tools/activate.sh 2>/dev/null || true

ORG="${1:?Usage: run_all.sh <OrgName> <domains> [collab_host]}"
DOMAINS="${2:?Provide comma-separated domains}"
COLLAB="${3:-}"

# ── Per-run output dir on Desktop: <Org>_<timestamp> (reports + full log) ─────
TS="$(date +%Y%m%d_%H%M%S)"
RUNDIR="$HOME/Desktop/${ORG// /_}_${TS}"
mkdir -p "$RUNDIR"
LOG="$RUNDIR/run.log"
# Mirror EVERYTHING (stdout+stderr, every phase + tool) into the run log while
# still printing to the console — single file for debugging a run end-to-end.
exec > >(tee -a "$LOG") 2>&1

# Diagnosis: if any command trips set -e, log exactly where before exiting.
set -o errtrace
trap 'rc=$?; echo "[FATAL] run_all.sh aborted at line ${LINENO} (exit ${rc})"' ERR

OUTPUT="$RUNDIR/${ORG// /_}_bounty_report.md"

V2_SCRIPTS="$HOME/.claude/skills/subdomain-recon/scripts"
BR_SCRIPTS="$HOME/.claude/skills/bounty-recon/scripts"
WD="/tmp/br_$$"
mkdir -p "$WD"

# On Ctrl-C / kill: take down backgrounded children so scanners don't keep
# running detached against the target, and salvage any findings gathered so far
# into the run dir so an interrupted scan still leaves output + the full log.
cleanup() {
    pkill -P $$ 2>/dev/null || true
    if [ -f "$WD/findings.json" ]; then
        cp "$WD/findings.json" "$RUNDIR/findings_partial.json" 2>/dev/null || true
        echo "[!] Saved partial findings → $RUNDIR/findings_partial.json"
    fi
}
trap 'echo; echo "[!] Interrupted — salvaging…"; cleanup; exit 130' INT TERM

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
banner() { echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
ok()     { echo -e "${GREEN}[✓]${NC} $*"; }
info()   { echo -e "    $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }

# Kill leftover processes
pkill -9 -f "$HOME/.recon-tools/bin/httpx" 2>/dev/null || true
pkill -9 -f "$HOME/.recon-tools/bin/puredns" 2>/dev/null || true
sleep 1

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║        bounty-recon pipeline         ║"
echo "  ║  recon → vulns → report              ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"
echo "  Org:     $ORG"
echo "  Domains: $DOMAINS"
echo "  Output:  $OUTPUT"
[ -n "$COLLAB" ] && echo "  Collab:  $COLLAB (SSRF/blind XSS enabled)"
echo ""

# ── Tools check + auto-install (portable; skips what's already present) ────────
# bounty-recon reuses subdomain-recon for enumeration, so it needs both toolsets.
# If anything is missing we run the relevant installer(s) once, then continue;
# tools that still can't install just degrade rather than block the run.
TOOLS_DIR="$HOME/.recon-tools"
SUB_BINS=(subfinder httpx dnsx puredns alterx uncover asnmap mapcidr)   # enumeration
BR_BINS=(nuclei dalfox ffuf naabu gf qsreplace gowitness katana gau waybackurls \
         trufflehog jsluice kr crlfuzz sourcemapper cdncheck tlsx)  # scanning
have() { [ -f "$TOOLS_DIR/bin/$1" ] || command -v "$1" &>/dev/null; }
missing_from() { local g; local m=(); for g in "$@"; do have "$g" || m+=("$g"); done; echo "${m[*]:-}"; }

# Attempt-marker: only invoke an installer when its missing set CHANGES, so an
# optional tool that won't install on this host doesn't trigger a slow reinstall
# on every run. Self-heals if a previously-present tool later goes missing.
SUB_MARKER="$TOOLS_DIR/.install_attempted_sub"
BR_MARKER="$TOOLS_DIR/.install_attempted_br"
SUB_MISSING="$(missing_from "${SUB_BINS[@]}")"
BR_MISSING="$(missing_from "${BR_BINS[@]}")"

if [ -z "$SUB_MISSING" ]; then
    rm -f "$SUB_MARKER" 2>/dev/null || true
elif [ "$SUB_MISSING" != "$(cat "$SUB_MARKER" 2>/dev/null || true)" ]; then
    warn "Enumeration tools missing: $SUB_MISSING — installing…"
    bash "$V2_SCRIPTS/install_tools.sh" || warn "subdomain-recon installer reported errors — continuing"
    missing_from "${SUB_BINS[@]}" > "$SUB_MARKER" 2>/dev/null || true
else
    warn "Enumeration tools unavailable (install already attempted): $SUB_MISSING — degraded"
fi

if [ -z "$BR_MISSING" ]; then
    rm -f "$BR_MARKER" 2>/dev/null || true
elif [ "$BR_MISSING" != "$(cat "$BR_MARKER" 2>/dev/null || true)" ]; then
    warn "Scanning tools missing: $BR_MISSING — installing…"
    bash "$BR_SCRIPTS/install_tools.sh" || warn "bounty-recon installer reported errors — continuing"
    missing_from "${BR_BINS[@]}" > "$BR_MARKER" 2>/dev/null || true
else
    warn "Scanning tools unavailable (install already attempted): $BR_MISSING — degraded"
fi

source "$TOOLS_DIR/activate.sh" 2>/dev/null || true
export PATH="$TOOLS_DIR/bin:$PATH"
[ -z "$SUB_MISSING$BR_MISSING" ] && ok "all required tools present" \
    || ok "tool check complete (any still-missing tools will degrade gracefully)"
echo ""

# ── Phase 1: Subdomain recon (via subdomain-recon scripts — not modified) ─────
banner "Phase 1 — Subdomain Recon (subdomain-recon)"
python3 "$V2_SCRIPTS/passive_enum.py" \
  --domains "$DOMAINS" --output "$WD/subdomains.txt"
ok "Passive: $(grep -cv '^#' "$WD/subdomains.txt" 2>/dev/null || echo 0) subdomains"

# Advanced techniques in parallel
info "Running 25 advanced techniques..."
> "$WD/advanced.txt"
pids=()
for domain in $(echo "$DOMAINS" | tr ',' '\n'); do
  python3 "$V2_SCRIPTS/advanced_techniques.py" \
    --domain "$domain" --org "$ORG" \
    --output "$WD/adv_${domain}.txt" 2>/dev/null &
  pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
cat "$WD"/adv_*.txt >> "$WD/advanced.txt" 2>/dev/null || true

# Merge + cache. `|| true`: empty results make grep exit 1 (not a failure here).
cat "$WD/subdomains.txt" "$WD/advanced.txt" 2>/dev/null \
  | grep -v "^#\|^\*\.\|^$" | tr '[:upper:]' '[:lower:]' | grep "\." \
  | sort -u > "$WD/all_subdomains.txt" || true
[ -f "$WD/all_subdomains.txt" ] || : > "$WD/all_subdomains.txt"

# Persistent cache
CACHE="$HOME/.recon-cache/$(echo "$ORG" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_')_subdomains.txt"
mkdir -p "$HOME/.recon-cache"
[ -f "$CACHE" ] && cat "$CACHE" >> "$WD/all_subdomains.txt" && sort -u "$WD/all_subdomains.txt" -o "$WD/all_subdomains.txt"
cp "$WD/all_subdomains.txt" "$CACHE"
ok "Total subdomains: $(wc -l < "$WD/all_subdomains.txt")"

# ── Phase 2: Live probe ───────────────────────────────────────────────────────
banner "Phase 2 — Live Probe + Screenshots"
"$HOME/.recon-tools/bin/httpx" \
  -l "$WD/all_subdomains.txt" \
  -threads 300 -timeout 5 \
  -status-code -title \
  2>/dev/null | tee "$WD/live.txt" | wc -l | xargs -I{} echo "  Live hosts: {}"

# Screenshots (optional — gowitness)
if command -v gowitness &>/dev/null || [ -f "$HOME/.recon-tools/bin/gowitness" ]; then
  mkdir -p "$WD/screenshots"
  "$HOME/.recon-tools/bin/gowitness" file \
    -f "$WD/live.txt" \
    --screenshot-path "$WD/screenshots/" \
    --no-http --threads 10 2>/dev/null || true
  ok "Screenshots: $(ls "$WD/screenshots/"*.png 2>/dev/null | wc -l)"
fi
ok "Live hosts: $(wc -l < "$WD/live.txt")"

# ── Phase 3: URL collection ───────────────────────────────────────────────────
banner "Phase 3 — URL Collection"
python3 "$BR_SCRIPTS/url_collect.py" --live "$WD/live.txt" --output "$WD/urls.txt" \
  || warn "URL collection had errors — continuing"
touch "$WD/urls.txt"
ok "URLs collected: $(wc -l < "$WD/urls.txt")"

# ── Phase 3.5: GitHub repo discovery (for Phase G TruffleHog scan) ───────────
banner "Phase 3.5 — GitHub Repo Recon (for verified-secret scan)"
# Pivots: official org repos (CONFIRMED) + repos by authors who commit with the
# company email domain (LIKELY) + repos by public org members (LIKELY).
# Discovery uses `gh api` (no extra token needed). The downstream TruffleHog
# scan needs GITHUB_TOKEN — phase_secrets() sources it from `gh auth token`
# automatically if the env var isn't set.
if command -v gh &>/dev/null && gh auth status &>/dev/null; then
  python3 "$BR_SCRIPTS/github_recon.py" \
    --org "$ORG" \
    --domains "$DOMAINS" \
    --output "$WD/github_repos.json" \
    || warn "github_recon ended early — Phase G will scan JS files only"
  if [ -f "$WD/github_repos.json" ]; then
      GH_TOTAL=$(python3 -c "import json; print(json.load(open('$WD/github_repos.json')).get('total',0))" 2>/dev/null || echo 0)
      ok "GitHub repo candidates: $GH_TOTAL"
  fi
else
  warn "gh CLI not authenticated — skipping GitHub repo discovery. Phase G will only scan harvested JS."
  echo '{"repos": [], "total": 0}' > "$WD/github_repos.json"
fi
GITHUB_REPOS_ARG="--github-repos $WD/github_repos.json"

# ── Phase 4: Vulnerability scanning ──────────────────────────────────────────
banner "Phase 4 — Vulnerability Scanning (9 automated phases)"
COLLAB_ARG=""
[ -n "$COLLAB" ] && COLLAB_ARG="--collab $COLLAB"

# NON-FATAL: vuln_scan checkpoints findings.json after every phase, so even if it
# ends early the report (Phase 5) must still run on whatever was gathered.
python3 "$BR_SCRIPTS/vuln_scan.py" \
  --live  "$WD/live.txt" \
  --urls  "$WD/urls.txt" \
  --domain "$(echo "$DOMAINS" | cut -d, -f1)" \
  --org   "$ORG" \
  --out   "$WD/findings.json" \
  $COLLAB_ARG \
  $GITHUB_REPOS_ARG \
  || warn "vuln scan ended early — reporting findings gathered so far"

# Guarantee a findings file exists so report generation never crashes.
[ -f "$WD/findings.json" ] || echo '{"domain":"","org":"","total":0,"findings":[]}' > "$WD/findings.json"

TOTAL=$(python3 -c "import json; d=json.load(open('$WD/findings.json')); print(d['total'])" 2>/dev/null || echo 0)
ok "Findings: $TOTAL"

# ── Phase 5: Report generation ────────────────────────────────────────────────
banner "Phase 5 — Report"
python3 "$BR_SCRIPTS/report.py" \
  --findings "$WD/findings.json" \
  --org "$ORG" \
  --output "$OUTPUT"

# Append subdomain counts to report
{
  echo ""
  echo "---"
  echo "## Subdomain Summary"
  echo ""
  echo "Total discovered: $(wc -l < "$WD/all_subdomains.txt") | Live: $(wc -l < "$WD/live.txt") | URLs collected: $(wc -l < "$WD/urls.txt")"
  echo ""
  echo "| Domain | Subdomain Count |"
  echo "|--------|----------------|"
  for d in $(echo "$DOMAINS" | tr ',' '\n'); do
    c=$(grep -cE "(^|\.)${d//./\\.}$" "$WD/all_subdomains.txt" 2>/dev/null || echo 0)
    echo "| $d | $c |"
  done
} >> "$OUTPUT"

# ── Phase 6: PDF report ───────────────────────────────────────────────────────
banner "Phase 6 — PDF Report"
PDF_OUT="${OUTPUT%.md}.pdf"
python3 "$BR_SCRIPTS/pdf_report.py" \
  --markdown "$OUTPUT" \
  --output "$PDF_OUT" 2>/dev/null \
  && ok "PDF: $PDF_OUT" \
  || warn "PDF generation failed — markdown report still available"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  DONE${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Org:         $ORG"
echo "  Subdomains:  $(wc -l < "$WD/all_subdomains.txt")"
echo "  Live hosts:  $(wc -l < "$WD/live.txt")"
echo "  Findings:    $TOTAL"
echo -e "  Report (MD): ${GREEN}$OUTPUT${NC}"
echo -e "  Report (PDF):${GREEN}$PDF_OUT${NC}"
echo -e "  Log:         ${GREEN}$LOG${NC}"
echo ""
echo -e "  ${GREEN}✔ Reports and full log saved in: $RUNDIR${NC}"
echo ""

# Show finding counts by severity
python3 -c "
import json
d = json.load(open('$WD/findings.json'))
sev = {}
for f in d['findings']: sev[f['severity']] = sev.get(f['severity'],0) + 1
icons = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵'}
for s in ['critical','high','medium','low']:
    if sev.get(s): print(f'  {icons[s]} {s.capitalize():10}: {sev[s]}')
" 2>/dev/null || true
echo ""
