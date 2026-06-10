# bounty-recon

Point it at a target, and it goes from "here's an org and some domains" to "here's a list of things worth looking at" — enumerating the attack surface, collecting URLs, pivoting through GitHub to find leaked secrets in both the official org and employees' personal repos, running a batch of automated vulnerability checks, and writing up what it found as a HackerOne-style report (Markdown and PDF). The methodology follows the usual Jason Haddix / NahamSec playbook, and it leans on `subdomain-recon` for the enumeration stage.

Where most point-and-shoot scanners stop at Nuclei templates, this chains the whole workflow in one run and covers classes those tools usually miss — JWT attacks, GraphQL deep tests, SSTI, mass assignment, host-header injection, shadow/legacy APIs, CRLF injection, 403/401 access-control bypass, source-map exposure, and multi-cloud public-asset enumeration. Secrets are scanned with TruffleHog v3 **verified-only** (each candidate is test-fired against its provider's API), so you're not wading through unverified regex noise that HackerOne closes as N/A. JSLuice extracts endpoints + inline secret candidates from minified JS via AST parsing. Kiterunner brute-forces REST routes using Assetnote's 800k+ Swagger-scraped wordlist. The pipeline then flags likely attack *chains* (e.g. SSRF → cloud metadata → IAM keys).

> ⚠️ **Only run this where you're allowed to.** That means an active bug-bounty scope or written authorization. Scanning things outside scope can land you in real trouble.

## How to use it

This is a Claude Code skill, so the easiest way to run it is to just ask, in plain English:

- `bounty recon Acme`
- `bug bounty scan acme.com`
- `find vulns in acme.com, acme.io`

Give it an **org name** and it discovers and validates the owned roots before scanning everything; give it one or more **domains** and it scans exactly those. Mode is detected from your input — you don't pick. To catch blind XSS and SSRF, add a collaborator/interaction host as a second argument. The first run installs the toolchain automatically (one time), and results land in a self-contained folder under `~/Desktop/`.

Prefer the terminal? The same thing runs as a single command — see [Quick start](#quick-start) below.

## What it does

- **Enumerates subdomains** by handing the whole recon stage to `subdomain-recon`'s engine — org → discover + validate owned roots + full enumeration (passive, advanced, brute / permutations / TLS-SAN); domains → those directly. The exact same flow `subdomain-recon` runs standalone.
- **Probes what's live and screenshots it.** `httpx` for tech detection, `gowitness` for screenshots, so admin panels and login pages jump out at you.
- **Collects URLs** from the Wayback Machine, GAU (Wayback + CommonCrawl + AlienVault + URLScan), and an active `katana` crawl.
- **Pivots through GitHub.** Resolves the official GitHub org (CONFIRMED tier) and discovers employees' personal repos two ways: public org membership, and **code search for `"@acme.com"`** — surfacing repos that hardcode a company email in a checked-in config / `.env` (the real leak vector). Each repo is tiered `CONFIRMED` / `LIKELY` / `POSSIBLE`.
- **Scans for verified leaked secrets** with **TruffleHog v3** across both the harvested JS bundles and every discovered GitHub repo. `--only-verified` means each match is test-fired against its provider's API before flagging — no regex false positives.
- **Runs 22 automated vulnerability checks** — Nuclei CVEs, XSS, SSRF, CORS, open redirect, exposed sensitive files, verified secret scanning, SQLi screening, port scan, JWT attacks, host-header injection, GraphQL deep test, SSTI, mass assignment, vhost discovery, shadow APIs, NoSQL injection, JSLuice AST-based JS analysis, Kiterunner API shadow-route discovery, CRLF injection, 403/401 bypass, source-map exposure, and Azure/GCP cloud asset enum.
- **Points you at the manual stuff.** It flags likely IDOR, auth, and business-logic candidates — the bugs automation can find but can't confirm.
- **Writes it up** as a Markdown report with severity counts, plus a PDF you can hand off.

## Requirements

- Python 3.9 or newer
- `subdomain-recon` installed next to this skill (used for the enumeration stage)
- The tooling the installer sets up (full list below)
- Optional: a collaborator/interaction host if you want blind XSS and SSRF detection

`install_tools.sh` is idempotent and cross-platform (macOS + Linux), and `run_all.sh` calls it automatically if anything is missing — including the `subdomain-recon` toolchain it depends on. Tools already on your system are detected and never reinstalled.

### Tools it installs / uses

This skill reuses everything `subdomain-recon` installs for enumeration, plus its own scanning toolset:

| Group | Tools |
|-------|-------|
| Vulnerability scanning | `nuclei` (+ templates), `dalfox`, `naabu`, `sqlmap` (screening only) |
| Fuzzing / content discovery | `ffuf`, `feroxbuster`, `arjun`, `x8`, `kr` (kiterunner) |
| URL collection / crawl | `gau`, `waybackurls`, `katana`, `hakrawler` |
| Filtering / rewriting | `gf` (+ patterns), `qsreplace`, `kxss`, `unfurl`, `anew`, `httprobe` |
| Screenshots | `gowitness` |
| Takeover / CORS | `subjack`, `baddns`, `corsy` |
| Secrets (verified) | `trufflehog` v3 |
| JS analysis | `jsluice` (AST), `sourcemapper` |
| Cloud / asset enum | `s3scanner`, `cloud_enum`, `cdncheck`, `tlsx` |
| Bypass + injection | `crlfuzz`, `bypass-403` |
| GraphQL | `graphw00f`, `clairvoyance`, `graphql-cop` |
| Reporting | `reportlab` / `pdfkit` (Markdown → PDF) |

If a tool can't be installed on a given host, that check is skipped and the rest of the run continues.

## Installation

You don't have to run this — `run_all.sh` auto-installs anything missing (both toolsets). But to set up (or refresh) by hand:

```bash
bash scripts/install_tools.sh
source ~/.recon-tools/activate.sh
```

## Quick start

One command does the whole run. Give it **either** an org name **or** one/more
domains (mode auto-detected); an optional collaborator host turns on blind XSS/SSRF:

```bash
# Org name → discover + validate roots, enumerate, then scan everything
bash scripts/run_all.sh "Acme Corp"

# Domains → recon + scan exactly those
bash scripts/run_all.sh "acme.com,product.io"

# Add a collaborator host to catch blind XSS and SSRF
bash scripts/run_all.sh "Acme Corp" your.collab.host
```

Everything for a run lands under `~/Desktop/<Org>_<timestamp>/`:
- `<Org>_bounty_report.md` / `.pdf` — the HackerOne-style writeup
- `run.log`, `recon/` (the nested subdomain-recon run), and `findings_partial.json` if interrupted

## Flags

```bash
bash scripts/run_all.sh "<org name | domain | domain1,domain2,...>" [collab_host]
```

| Argument | Required | What it does |
|----------|----------|--------------|
| target | yes | An **org name** (→ discover + validate + enumerate every owned root, then scan) **or** one/more comma-separated **domains** (→ recon + scan exactly those). Auto-detected. |
| `collab_host` | no | A Burp Collaborator / interactsh host. Supplying it turns on blind XSS and SSRF detection; leave it out and those two checks are skipped. |

That's the only optional knob — everything else runs automatically.

## How it works

You give it an org and some domains; it runs recon, then scanning, then reporting. Each step feeds the next.

```
        org name + seed domains  [+ collaborator host]
                  │
   ┌──────────────▼───────────────┐
   │ Phase 0   Install             │  one-time toolchain setup
   │                               │
   └──────────────┬───────────────┘
                  │
   ┌──────────────▼───────────────┐
   │ Phase 1   Subdomain Recon     │  delegates to subdomain-recon's full
   │                               │  engine (discover+validate+enumerate)
   └──────────────┬───────────────┘
                  │ subdomains
   ┌──────────────▼───────────────┐
   │ Phase 2   Live Probe + Shots  │  HTTP tech-detect + screenshots
   │                               │  (spot panels/logins)
   └──────────────┬───────────────┘
                  │ live hosts
   ┌──────────────▼───────────────┐
   │ Phase 3   URL Collection      │  Wayback + GAU + active crawl
   │                               │
   └──────────────┬───────────────┘
                  │ collected URLs
   ┌──────────────▼───────────────┐
   │ Phase 4   Vulnerability Scan  │  22 automated phases (A–W)
   │                               │  → JSON findings
   └──────────────┬───────────────┘
                  │ findings
   ┌──────────────▼───────────────┐
   │ Phase 5   Manual-Assist Hunt  │  surfaces IDOR/auth/logic candidates
   │ (operator-driven)             │  for human validation
   └──────────────┬───────────────┘
                  │
   ┌──────────────▼───────────────┐
   │ Phase 6   Report              │  Markdown + PDF report (~/Desktop)
   │                               │
   └───────────────────────────────┘
```

| Phase | What it covers | Tooling | In → Out |
|-------|----------------|---------|----------|
| **0** | Install | bundled installer | — → toolchain in `~/.recon-tools` |
| **1** | Subdomain recon | `subdomain-recon` full engine (discover + validate + enumerate) | org/domains → subdomains |
| **2** | Live probe + screenshots | `httpx`, `gowitness` | subdomains → live hosts + screenshots |
| **3** | URL collection | Wayback, GAU, katana | live hosts → collected URLs |
| **4** | Vulnerability scan | Nuclei, dalfox, naabu, … (22 checks A–W, below) | live hosts + URLs → JSON findings |
| **5** | Manual-assist hunting | IDOR / auth / param discovery | URLs → candidate lists to review |
| **6** | Report | Markdown + PDF generator | findings → `~/Desktop/<Org>_bounty_report.{md,pdf}` |

Everything except phase 5 runs automatically when you use the one-shot command. Phase 5 is on you — the tooling just hands you a shortlist of candidates; confirming and writing them up is manual work.

### The 22 vulnerability checks (phase 4)

| Check | How | What it catches |
|-------|-----|-----------------|
| A | Nuclei critical/high templates | CVEs, exposed panels, default creds, takeovers |
| B | XSS (`gf` + `dalfox`) | Reflected, stored, DOM XSS |
| C | SSRF (`gf` + `qsreplace` + collaborator) | Server-side request forgery |
| D | CORS (origin reflection test) | Credential-bearing cross-origin access |
| E | Open redirect (`gf` + `qsreplace`) | Phishing enablers |
| F | Sensitive files (ffuf-style) | `.git`, `.env`, `/admin`, `/actuator`, swagger |
| G | Secrets (`trufflehog` v3 verified-only, JS + GitHub repos) | Live API keys / tokens / DB creds with provider-confirmed validity |
| H | SQLi screening (`gf` + error detection) | SQL-injection candidates |
| I | Port scan (`naabu`) | Exposed DBs, Redis, SSH, VNC |
| J | JWT attacks | `alg:none`, RS256↔HS256 confusion, kid injection, weak secret |
| K | Host header injection | Password reset poisoning, cache poisoning |
| L | GraphQL | Introspection, mutation auth bypass, batching |
| M | SSTI | Polyglot → per-engine RCE confirmation |
| N | Mass assignment | `is_admin:true` accepted in API PUT/PATCH |
| O | VHost discovery | Host-header fuzzing finds apps not in DNS |
| P | Content discovery (`feroxbuster`) | Hidden paths with Assetnote wordlists |
| Q | Shadow APIs | Old `/v1/` endpoints still live after `/v2/` ships |
| R | JSLuice (AST JS analysis) | Endpoints + secret candidates inside minified bundles |
| S | Kiterunner (API shadow-route discovery) | Undocumented REST endpoints via 800k+ Swagger-scraped routes |
| T | CRLF injection (`crlfuzz`) | Header injection → cache poisoning / response splitting |
| U | 403/401 bypass | Path tricks + header bypasses on gated endpoints |
| V | Source-map exposure | Leaked `.js.map` files = full original-source disclosure |
| W | Cloud public-asset enum (`cloud_enum`) | Open Azure storage/blobs/vaults + GCP buckets/Firebase RTDB |

## Running individual steps

```bash
# Phase 3 — collect URLs
bash scripts/url_collect.sh /tmp/br_live.txt /tmp/br_urls.txt

# Phase 4 — vulnerability scan
python3 scripts/vuln_scan.py \
  --live   /tmp/br_live.txt \
  --urls   /tmp/br_urls.txt \
  --domain acme.com \
  --org    "Acme Corp" \
  --out    /tmp/br_findings.json \
  --collab your.collab.host

# Phase 6 — report
python3 scripts/report.py \
  --findings /tmp/br_findings.json \
  --org "Acme Corp" \
  --output ~/Desktop/Acme_bounty_report.md

python3 scripts/pdf_report.py \
  --markdown ~/Desktop/Acme_bounty_report.md \
  --output   ~/Desktop/Acme_bounty_report.pdf
```

All vulnerability checks always run — there's no skip switch. Add a collaborator host to turn on blind XSS / SSRF detection:

```bash
python3 scripts/vuln_scan.py ... --collab your.collab.host
```

## Options reference

<details>
<summary><code>vuln_scan.py</code></summary>

| Flag | Required | Description |
|------|----------|-------------|
| `--live` | yes | Live hosts file from `httpx` |
| `--urls` | yes | Collected URLs file |
| `--domain` | yes | Primary target domain |
| `--org` | no | Organisation name |
| `--out` | yes | Output JSON findings file |
| `--collab` | no | Collaborator host for SSRF / blind XSS |
</details>

<details>
<summary><code>report.py</code> / <code>pdf_report.py</code> / <code>url_collect.py</code></summary>

`report.py`: `--findings` `--org` (default `Target`) `--output`
`pdf_report.py`: `--markdown` `--output`
`url_collect.py`: `--live` `--output`
</details>

## The manual half

The scanner finds candidates; you confirm them. These are the classes that tend to pay best, and they all need a human:

- **IDOR / BOLA** — swap user IDs around and see if you can reach another account's data.
- **Auth bypass** — JWT `alg=none`, password-reset flows, SSO misconfigurations.
- **Business logic** — rate-limit bypasses, negative values, skipping payment steps.
- **Mass assignment** — extra JSON fields that the backend shouldn't let you write.
- **GraphQL** — introspection, then hidden mutations, then privilege escalation.

## Things worth remembering

- Acquisitions are usually the richest target — the seams where two systems were stitched together tend to have permission gaps.
- `nuclei -as` picks templates based on the detected tech, so you're not running everything against everything.
- Most of the bugs that actually pay (IDOR, BOLA, SSRF) only show up once you're authenticated, so test logged in.
- `gf` piped into `qsreplace` lets you fuzz parameters across thousands of URLs at once.
- If you can't reproduce it by hand, don't report it.
- Lead with impact. "An attacker can read every user's PII" beats "found an XSS" every time.

## A note on scope

- Stick to programs with an active bug-bounty scope or written authorization.
- Read the scope properly and stay out of anything marked out-of-scope.
- No destructive testing — no real `sqlmap --dump`, no DoS payloads.
- The SQLi check only screens for error signatures — it never dumps data.
- Keep your scan rate reasonable.

## Author

Krutarth Shukla
