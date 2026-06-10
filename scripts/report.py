#!/usr/bin/env python3
"""
report.py — Generate HackerOne-style bug bounty report from findings JSON.

Produces:
  - Markdown report (readable, ready to submit)
  - Per-finding templates with: Title, Severity, CVSS, CWE,
    Steps to Reproduce, Impact, Recommendations

Usage:
  python3 report.py --findings /tmp/bounty_findings.json \
      --org "Acme" --output ~/Desktop/Acme_bounty_report.md
"""

import argparse, json, os, sys
from datetime import datetime

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
CVSS_RANGE = {"critical": "9.0-10.0", "high": "7.0-8.9", "medium": "4.0-6.9", "low": "0.1-3.9"}

IMPACT_TEMPLATE = {
    "critical": "Full compromise possible. Immediate risk of data breach, account takeover, or remote code execution.",
    "high": "Significant data exposure or authentication bypass. High risk of targeted exploitation.",
    "medium": "Limited data exposure or requires user interaction. Moderate exploitation risk.",
    "low": "Minimal direct impact. May assist attackers in reconnaissance.",
    "info": "Informational. No direct security impact but may reveal attack surface.",
}

RECOMMENDATIONS = {
    "CORS Misconfiguration":       "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard with credentials.",
    "Cross-Site Scripting (XSS)":  "Sanitize all user input. Use Content Security Policy. Encode output in the correct context.",
    "Server-Side Request Forgery": "Validate and whitelist allowed URLs/IPs. Block requests to internal/cloud metadata ranges.",
    "Open Redirect":               "Validate redirect targets against an allowlist. Never redirect to user-supplied URLs directly.",
    "SQL Injection":               "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "Hardcoded Secret":            "Remove secrets from code immediately. Rotate the exposed credential. Use environment variables.",
    "Sensitive File":              "Remove from public access. Add to .gitignore. Review CI/CD for accidental uploads.",
    "Exposed Service":             "Restrict with firewall rules. Require authentication. Move admin services off public internet.",
}

def get_recommendation(title):
    for key, rec in RECOMMENDATIONS.items():
        if key.lower() in title.lower():
            return rec
    return "Review the affected component, apply security patches, and follow OWASP guidance."

def get_steps(f):
    steps = [
        f"1. Navigate to: `{f['host']}`",
        f"2. {f['detail']}",
    ]
    if f.get("evidence"):
        steps.append(f"3. Observe the response: `{f['evidence'][:200]}`")
    return "\n".join(steps)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--org", default="Target")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.findings):
        print(f"[!] findings file not found: {args.findings}")
        sys.exit(1)
    try:
        with open(args.findings) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] could not read findings JSON ({e})")
        sys.exit(1)

    all_findings = sorted(data.get("findings", []),
                          key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    by_sev = {}
    for f in all_findings:
        by_sev.setdefault(f["severity"], []).append(f)

    lines = []
    # Header
    lines.append(f"# Bug Bounty Report — {args.org}")
    lines.append(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"> Domain: {data.get('domain', '')}")
    lines.append(f"> Total findings: **{len(all_findings)}**\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical","high","medium","low","info"]:
        count = len(by_sev.get(sev, []))
        if count:
            lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.capitalize()} | {count} |")
    lines.append("")

    if by_sev.get("critical") or by_sev.get("high"):
        lines.append("**Immediate action required** on Critical/High findings.\n")

    # Table of Contents
    lines.append("## Findings\n")
    for i, f in enumerate(all_findings, 1):
        lines.append(f"{i}. [{SEVERITY_EMOJI[f['severity']]} {f['title']}](#{i}) — `{f['host'][:60]}`")
    lines.append("")

    # Each finding
    for i, f in enumerate(all_findings, 1):
        sev = f["severity"]
        lines.append(f"---\n")
        lines.append(f"### {i}. {f['title']}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | {SEVERITY_EMOJI[sev]} {sev.capitalize()} |")
        if f.get("cvss"):
            lines.append(f"| **CVSS Score** | {f['cvss']} ({CVSS_RANGE.get(sev,'')}) |")
        if f.get("cwe"):
            lines.append(f"| **CWE** | [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].replace('CWE-','')}.html) |")
        lines.append(f"| **Affected Host** | `{f['host']}` |")
        lines.append(f"| **Discovered** | {f.get('timestamp','')[:10]} |")
        lines.append("")

        lines.append(f"**Description**\n\n{f['detail']}\n")

        if f.get("evidence"):
            lines.append(f"**Evidence**\n```\n{f['evidence'][:500]}\n```\n")

        lines.append(f"**Steps to Reproduce**\n\n{get_steps(f)}\n")

        lines.append(f"**Impact**\n\n{IMPACT_TEMPLATE.get(sev, '')}\n")

        lines.append(f"**Recommendation**\n\n{get_recommendation(f['title'])}\n")

    # Footer
    lines.append("---")
    lines.append("*Report generated by bounty-recon skill. Validate all findings manually before submission.*")

    with open(args.output, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Report: {args.output}")
    print(f"[+] {len(all_findings)} findings documented")

if __name__ == "__main__":
    main()
