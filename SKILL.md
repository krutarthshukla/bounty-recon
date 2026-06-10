---
name: bounty-recon
owner: Krutarth Shukla
email: krutarth.ce@gmail.com
description: >
  End-to-end bug bounty recon → vulnerability hunting pipeline. Starts with subdomain-recon
  enumeration, then a GitHub repo recon pass (official org + employee personal repos via email-domain
  pivot), then a 22-phase vulnerability scan: Nuclei critical/high CVEs, XSS (dalfox), SSRF,
  CORS misconfig, open redirect, sensitive file exposure, TruffleHog v3 verified secret scanning
  (JS + GitHub), SQLi screening, port scan, JWT attacks, host-header injection, GraphQL deep test,
  SSTI, mass assignment, vhost discovery, shadow APIs, NoSQL injection, JSLuice AST-based JS
  analysis, Kiterunner API shadow-route discovery, CRLF injection, 403/401 access-control bypass,
  source-map exposure, and Azure/GCP cloud asset enum. Generates a HackerOne-style markdown report.
  Use for: "bounty recon <org>", "find vulns in <org>", "bug bounty scan <org>",
  "hunt bugs in <org>", "run bounty-recon on <org>".
  ONLY run against targets with explicit bug bounty scope or written authorization.
---

# bounty-recon

**What it does:** Subdomain enumeration (via subdomain-recon) → URL collection → GitHub repo
recon (official org + employee personal repos via email-domain pivot) → 22-phase vulnerability
scan (incl. TruffleHog verified secret scanning across JS + GitHub repos) → HackerOne-style report.

**Scope reminder:** Only run against programs with an active bug bounty scope or explicit written
authorization. Running against out-of-scope targets is illegal.

---


## When invoked, Claude does ALL of this automatically

Just say **"bounty recon <org>"** and Claude runs the full pipeline:

```bash
# Single command — runs everything and saves report to Desktop
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh   "<OrgName>"   "domain1.com,domain2.com,..."   [your.collab.host]  # optional — enables blind XSS + SSRF detection

# PDF report generated automatically alongside the markdown report
python3 -c "
import subprocess, sys
subprocess.run(['pip3', 'install', 'md2pdf', '-q'])
" && md2pdf ~/Desktop/<OrgName>_bounty_report.md      --output ~/Desktop/<OrgName>_bounty_report.pdf 2>/dev/null || python3 -c "
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import re, os
# Fallback PDF generation if md2pdf unavailable
src = open(os.path.expanduser('~/Desktop/<OrgName>_bounty_report.md')).read()
print('PDF: use install_tools.sh to install md2pdf')
"
```

**Output on Desktop:**
-  — detailed HackerOne-style markdown report
-  — PDF version for sharing

## Phase 0 — Install

```bash
bash ~/.claude/skills/bounty-recon/scripts/install_tools.sh
source ~/.recon-tools/activate.sh
```

New tools over subdomain-recon:

**Core scanning:** `nuclei` (templates updated), `dalfox` (XSS), `ffuf` (fuzzer),
`naabu` (port scan), `feroxbuster`, `subjack`, `baddns`, `sqlmap`, `gowitness`,
`arjun`, `corsy`.

**URL collection / filtering:** `gau`, `waybackurls`, `katana`, `hakrawler`, `gf`,
`qsreplace`, `kxss`, `unfurl`, `anew`, `httprobe`.

**Modern recon stack (2025-2026):**
- `trufflehog` v3 — verified-only secret scanning (replaces regex). Live-fires
  candidates against provider APIs (AWS, GitHub, Slack, Stripe, …) before flagging.
- `jsluice` — BishopFox AST-based JS analyzer for endpoints + secret candidates.
- `kr` (kiterunner) — Assetnote API content discovery with 800k+ Swagger-scraped
  routes; content-type-aware fuzzing finds shadow REST endpoints.
- `cdncheck`, `tlsx` — ProjectDiscovery: CDN fingerprinting + TLS/cert intel.
- `cloud_enum` — Multi-cloud public asset hunter (Azure storage/vaults, GCP buckets,
  Firebase RTDB). Closes the gap S3Scanner doesn't cover.
- `s3scanner` — S3 bucket enum (also installed).
- `sourcemapper` — Recovers original TS/JSX source from leaked `.js.map` files.
- `crlfuzz` — CRLF injection at scale.
- `bypass-403` — 403/401 access-control bypass kit.
- `x8` — Hidden parameter discovery (body/query/headers; better than arjun for headers).
- `graphw00f` / `clairvoyance` / `graphql-cop` — GraphQL deep test (engine fingerprint,
  schema recovery when introspection is off, batching/DoS/CSRF audits).

---

## Phase 1 — Subdomain Recon (calls subdomain-recon — no modifications)

```bash
ORG="<OrgName>"
DOMAINS="<domain1.com,domain2.com,...>"

python3 ~/.claude/skills/subdomain-recon/scripts/passive_enum.py \
  --domains "$DOMAINS" --output /tmp/br_passive.txt

# Advanced techniques (25 techniques from subdomain-recon)
for domain in $(echo "$DOMAINS" | tr ',' '\n'); do
  python3 ~/.claude/skills/subdomain-recon/scripts/advanced_techniques.py \
    --domain "$domain" --org "$ORG" \
    --output "/tmp/br_adv_${domain}.txt" 2>/dev/null &
done; wait
cat /tmp/br_adv_*.txt >> /tmp/br_passive.txt 2>/dev/null || true

sort -u /tmp/br_passive.txt -o /tmp/br_subdomains.txt
echo "Subdomains: $(wc -l < /tmp/br_subdomains.txt)"
```

---

## Phase 2 — Live Probe + Screenshot

```bash
# Find live hosts
"$HOME/.recon-tools/bin/httpx" -l /tmp/br_subdomains.txt \
  -threads 300 -timeout 5 -status-code -title -tech-detect \
  2>/dev/null | tee /tmp/br_live.txt | wc -l

# Screenshot all live hosts (visual recon — spot admin panels, login pages)
"$HOME/.recon-tools/bin/gowitness" file \
  -f /tmp/br_live.txt \
  --screenshot-path /tmp/br_screenshots/ \
  --no-http 2>/dev/null || true
echo "Screenshots: $(ls /tmp/br_screenshots/*.png 2>/dev/null | wc -l)"
```

---

## Phase 3 — URL Collection

```bash
bash ~/.claude/skills/bounty-recon/scripts/url_collect.sh \
  /tmp/br_live.txt /tmp/br_urls.txt
echo "Total URLs: $(wc -l < /tmp/br_urls.txt)"
```

Sources: Wayback Machine, GAU (Wayback+CommonCrawl+AlienVault+URLScan), Katana active crawler

---

## Phase 3.5 — GitHub Repo Recon (for verified-secret scan)

Developers leak company secrets into GitHub all the time — often in **personal**
repos where they checked in a config file with a company email. This phase
discovers candidate repos to scan in Phase G:

| Tier | Source | Confidence |
|------|--------|------------|
| `CONFIRMED` | Repo under the resolved official GitHub org | Highest |
| `LIKELY` | Personal repo whose author committed with a company-domain email, OR who is a public member of the official org | High |
| `POSSIBLE` | Personal repo mentioning the company name/domain in code (currently surfaced only when explicit search expands the set) | Medium |

```bash
python3 ~/.claude/skills/bounty-recon/scripts/github_recon.py \
  --org    "$ORG" \
  --domains "$DOMAINS" \
  --output /tmp/br_github_repos.json \
  [--org-handle <official_github_org_login>]   # optional, skips search
```

Discovery uses the `gh` CLI's existing auth (no extra `GITHUB_TOKEN` needed).
TruffleHog (Phase G) auto-sources `GITHUB_TOKEN` from `gh auth token` when
the env var isn't set.

---

## Phase 4 — Vulnerability Scanning (22 phases automated)

```bash
python3 ~/.claude/skills/bounty-recon/scripts/vuln_scan.py \
  --live          /tmp/br_live.txt \
  --urls          /tmp/br_urls.txt \
  --domain        "$(echo $DOMAINS | cut -d, -f1)" \
  --org           "$ORG" \
  --out           /tmp/br_findings.json \
  --github-repos  /tmp/br_github_repos.json  \  # from Phase 3.5
  [--collab       YOUR.COLLABORATOR.HOST]      # enables SSRF + blind XSS detection
```

**22 automated phases (A–W):**

| Phase | Technique | Finds |
|-------|-----------|-------|
| A | **Nuclei** critical/high templates | CVEs, exposed panels, default creds, takeovers |
| B | **XSS** (gf + dalfox) | Reflected, stored, DOM XSS |
| C | **SSRF** (gf + qsreplace + collab) | Server-Side Request Forgery |
| D | **CORS** (origin reflection test) | Credential-bearing cross-origin access |
| E | **Open Redirect** (gf + qsreplace) | Phishing enablers |
| F | **Sensitive files** (ffuf-style) | .git, .env, /admin, /actuator, swagger |
| G | **Secrets** (TruffleHog v3, verified-only) | Live API keys / tokens / DB creds in JS bundles + GitHub repos discovered in Phase 3.5 |
| H | **SQLi screening** (gf + error detection) | SQL injection candidates |
| I | **Port scan** (naabu) | Exposed DBs, Redis, SSH, VNC |
| J | **JWT attacks** | alg:none, RS256↔HS256 confusion, kid injection, weak secret |
| K | **Host header injection** | Password reset poisoning, cache poisoning |
| L | **GraphQL** | Introspection, mutation auth bypass, batching |
| M | **SSTI** | Polyglot → per-engine RCE confirmation |
| N | **Mass assignment** | `is_admin:true` / `role:admin` accepted in API PUT/PATCH |
| O | **VHost discovery** | Host-header fuzzing finds apps not in DNS |
| P | **Content discovery** | feroxbuster with Assetnote wordlists |
| Q | **Shadow APIs** | Old `/v1/` endpoints still live after `/v2/` ships |
| R | **JSLuice** (AST JS analysis) | Endpoints + secret candidates inside minified bundles |
| S | **Kiterunner** (API shadow-route discovery) | Undocumented REST endpoints via 800k+ Swagger-scraped routes |
| T | **CRLF injection** (crlfuzz) | Header injection → cache poisoning / response splitting |
| U | **403/401 bypass** | Path tricks + header bypasses on gated endpoints |
| V | **Source-map exposure** | Leaked `.js.map` files = full original-source disclosure |
| W | **Cloud public-asset enum** (cloud_enum) | Open Azure storage/blobs/vaults + GCP buckets/Firebase RTDB |

---

## Phase 5 — Manual-Assist Hunting (IDOR/Auth/Business Logic)

These require human review — automation detects candidates, you validate:

```bash
# Find IDOR candidates (numeric IDs in URLs)
cat /tmp/br_urls.txt | grep -E '/[0-9]+' | \
  grep -v "\.js\|\.css\|\.png" | sort -u > /tmp/br_idor_candidates.txt
echo "IDOR candidates: $(wc -l < /tmp/br_idor_candidates.txt)"

# Find auth endpoints
cat /tmp/br_urls.txt | grep -iE "login|auth|token|session|oauth|sso|jwt|password" \
  | sort -u > /tmp/br_auth_endpoints.txt

# Parameter discovery on interesting endpoints
"$HOME/.recon-tools/bin/katana" -list /tmp/br_live.txt \
  -jc -jsl -xhr -f qparam -d 3 -silent 2>/dev/null \
  | sort -u > /tmp/br_params.txt
echo "Parameters discovered: $(wc -l < /tmp/br_params.txt)"
```

**High-value bug classes to manually test (top payers on HackerOne):**
- IDOR/BOLA — change user IDs in requests, test cross-account access
- Auth bypass — test JWT alg=none, password reset flows, SSO misconfigs
- Business logic — bypass rate limits, negative values, skip payment steps
- Mass assignment — submit extra JSON fields that shouldn't be writable
- GraphQL — introspection → hidden mutations → privilege escalation

---

## Phase 6 — Report Generation

```bash
python3 ~/.claude/skills/bounty-recon/scripts/report.py \
  --findings /tmp/br_findings.json \
  --org "$ORG" \
  --output ~/Desktop/${ORG}_bounty_report.md

# Also show critical/high count
python3 -c "
import json
d = json.load(open('/tmp/br_findings.json'))
for s in ['critical','high','medium']:
    c = sum(1 for f in d['findings'] if f['severity']==s)
    if c: print(f'{s}: {c}')
"
```

---

## Key Flags

```bash
# Enable blind XSS + SSRF with collaborator
python3 vuln_scan.py ... --collab interact.sh
```

All vulnerability phases always run — there is no skip switch.

---

## Bug Bounty Tips (from top hunters)

- **Acquisition targets = highest ROI** — integration seams have permission model gaps
- **Nuclei -as flag** = auto-selects templates based on tech fingerprint
- **Auth-aware testing** = most paying bugs (IDOR, BOLA, SSRF) only exist after login
- **gf + qsreplace pipeline** = scalable parameter fuzzing across thousands of URLs
- **Validate before reporting** = if you can't reproduce it manually, don't submit
- **Impact-first reports** = "An attacker can steal all user PII" beats "XSS found"
- **Custom Nuclei templates** = find bugs others miss on the same target

---

## Scope & Ethics

- Only run against targets with active bug bounty programs or written authorization
- Read the full scope — respect out-of-scope assets strictly
- No destructive testing (no real `sqlmap --dump`, no DoS payloads). The SQLi phase only screens for error signatures — it never dumps data
- Rate-limit your scans — `--rate-limit 100` in nuclei is default
