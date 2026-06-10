---
name: bounty-recon
owner: Krutarth Shukla
email: krutarth.ce@gmail.com
description: >
  Automated end-to-end bug-bounty recon → vulnerability-hunting pipeline. The
  user gives ONLY an org name or one/more domains; the skill discovers owned
  roots including acquisitions and subsidiaries (org mode), enumerates
  subdomains, collects URLs, does GitHub repo recon,
  runs a 22-phase vulnerability scan (Nuclei CVEs, XSS, SSRF, CORS, open redirect,
  sensitive files, TruffleHog verified secrets, SQLi, port scan, JWT, host-header
  injection, GraphQL, SSTI, mass assignment, vhost, content/shadow-API discovery,
  NoSQL, JSLuice, Kiterunner, CRLF, 403/401 bypass, source maps, cloud assets) and
  writes a HackerOne-style markdown + PDF report. Use for: "bounty recon <org>",
  "find vulns in <org>", "bug bounty scan <org>", "hunt bugs in <org>".
  ONLY run against targets with an active bug-bounty scope or written authorization.
---

# bounty-recon

## ⚠️ Scope first

Only run against programs with an **active bug-bounty scope or explicit written
authorization**. Read the scope; respect out-of-scope assets strictly. No
destructive testing. If scope isn't established, confirm it with the user before
running.

## First run (one-time, per machine)

Before running, check the onboarding marker:

```bash
test -f ~/.recon-tools/.onboarded_bounty && echo onboarded || echo first-run
```

If it prints `first-run`, **pause and confirm with the user before running** —
bounty-recon sends active attack traffic, so this gate matters:
- **Authorization:** confirm the target is in an active bug-bounty scope or the
  user has written permission. Do not proceed otherwise.
- The recon + scanning toolchain **auto-installs on this first run** (several
  minutes, one time).
- **GitHub:** have them run `gh auth login` so the repo/secret recon (Phase 3.5
  + G) works; without it that phase scans only harvested JS.
- *Optional:* a collaborator host (interactsh/Burp) enables blind XSS + SSRF —
  pass it as the 2nd argument.
- *Optional:* for bbot's extra coverage, run once: `bbot --install-all-deps` (sudo).

After they confirm, record it so this never prompts again, then run:

```bash
mkdir -p ~/.recon-tools && touch ~/.recon-tools/.onboarded_bounty
```

If the marker already exists, skip this and run directly.

## How to run it

The user gives **one thing** — an org name, a single domain, or a comma-list of
domains (optionally a collaborator host for blind XSS/SSRF). Take that input
verbatim and run the engine. It does the entire pipeline automatically; do
**not** step through phases yourself.

```bash
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh "<the user's input>" [collab_host]
```

Examples — pass exactly what the user said:

```bash
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh "Acme"                       # org name
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh "acme.com"                    # one domain
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh "acme.com,acme.io"            # several domains
bash ~/.claude/skills/bounty-recon/scripts/run_all.sh "Acme" interact.sh            # org + collaborator
```

**Mode is auto-detected from the input:**

| Input | What the engine does |
|-------|----------------------|
| **Org name** (e.g. `Acme`) | Discovers candidate roots, validates which are owned (via subdomain-recon), then runs the full pipeline over **every owned root**. |
| **One / several domains** | Runs the pipeline over **exactly those domains** — no root discovery. |

The optional 2nd arg is a **collaborator host** (e.g. an interactsh domain) — it
enables blind-XSS and SSRF out-of-band detection. Omit it if you don't have one.

First run on a fresh machine auto-installs the toolchain (`install_tools.sh`) —
this can take several minutes; let it finish. Subsequent runs skip it.
GitHub repo recon (Phase 3.5) uses the `gh` CLI's existing auth — if `gh` isn't
authenticated, that phase is skipped and Phase G scans harvested JS only.

## Reading the output

Everything for a run lands in one self-contained directory:
`~/Desktop/<Org>_<timestamp>/`

- `run.log` — full stdout/stderr of every phase.
- `<Org>_bounty_report.md` / `.pdf` — the HackerOne-style report (findings by
  severity + a subdomain summary).
- `findings_partial.json` — written if the run is interrupted.
- `rejected_domains.txt` — (org mode) roots excluded by ownership validation.

When the engine finishes, summarize for the user: mode, scope (roots scanned),
subdomain/live/URL counts, and the finding counts by severity (critical/high/
medium/low) with the report path. Flag anything the log marked degraded/skipped.

## Pipeline (reference only — the engine runs all of this; you don't)

1. **Phase 0 — Tools.** Verify/auto-install the recon + scanning toolchains.
2. **Phase 1 — Subdomain recon** — delegated to subdomain-recon's **full engine**
   (org → discover roots + validate ownership + enumerate; domains → those): the
   exact same recon flow it runs standalone, incl. brute / permutations / TLS-SAN.
4. **Phase 2 — Live probe + screenshots** (httpx, gowitness).
5. **Phase 3 — URL collection** (`url_collect.py`: wayback + gau).
6. **Phase 3.5 — GitHub repo recon** (`github_recon.py`: official org +
   email-domain / org-member pivots) → feeds Phase G.
7. **Phase 4 — 22-phase vuln scan** (`vuln_scan.py`, A–W, one shot): Nuclei, XSS,
   SSRF, CORS, open redirect, sensitive files, TruffleHog verified secrets, SQLi,
   ports, JWT, host-header, GraphQL, SSTI, mass assignment, vhost, content/shadow
   APIs, NoSQL, JSLuice, Kiterunner, CRLF, 403/401 bypass, source maps, cloud enum.
8. **Phase 5 — Report** (`report.py`) and **Phase 6 — PDF** (`pdf_report.py`).

## Manual-assist follow-ups (highest-paying bug classes)

Automation surfaces candidates; these need human validation: IDOR/BOLA, auth
bypass (JWT alg=none, password-reset/SSO flows), business-logic abuse, mass
assignment, GraphQL introspection → hidden mutations. Validate before reporting —
if you can't reproduce it manually, don't submit.
