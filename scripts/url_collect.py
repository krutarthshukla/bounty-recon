#!/usr/bin/env python3
"""
url_collect.py — URL collection using subprocess.Popen.
Fixes the background-task output-kill issue that breaks waybackurls/gau/katana.
Same fix as probe_live.py — Python subprocess.Popen bypasses Bash tool stream interception.

Usage: python3 url_collect.py --live live.txt --output urls.txt
"""
import argparse, os, re, subprocess, sys

GOBIN = os.path.expanduser("~/.recon-tools/bin")

def tool(name):
    p = os.path.join(GOBIN, name); return p if os.path.isfile(p) else name

def collect_domain(domain, output_file, timeout=120):
    total = 0
    SKIP = re.compile(r'\.(css|js|png|jpg|gif|ico|woff|ttf|svg|mp4|pdf)(\?|$)', re.I)

    for cmd_name, cmd in [
        ("waybackurls", [tool("waybackurls"), domain]),
        ("gau",         [tool("gau"), "--threads", "3", domain]),
    ]:
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            # communicate() enforces a hard timeout on the *whole* read; the old
            # `for line in proc.stdout` loop could block forever if the tool hung
            # mid-stream, since proc.wait(timeout) only ran after the read finished.
            try:
                out, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            with open(output_file, "a") as f:
                for line in out.splitlines():
                    line = line.strip()
                    if line and not SKIP.search(line):
                        f.write(line + "\n")
                        total += 1
        except Exception:
            if proc and proc.poll() is None:
                proc.kill()
    return total

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.live):
        print(f"[!] live file not found: {args.live}", file=sys.stderr)
        sys.exit(1)

    open(args.output, "w").close()  # reset

    # Extract domains from live file
    domains = set()
    with open(args.live) as fh:
        for line in fh:
            line = line.strip()
            if not line: continue
            domain = re.sub(r'https?://', '', line).split('/')[0].split('[')[0].strip()
            if domain: domains.add(domain)

    total = 0
    print(f"[*] Collecting URLs from {len(domains)} domains...", flush=True)
    for domain in sorted(domains):
        n = collect_domain(domain, args.output)
        print(f"  {domain}: {n}", flush=True)
        total += n

    # Deduplicate
    with open(args.output) as f:
        lines = set(f.readlines())
    with open(args.output, "w") as f:
        f.writelines(sorted(lines))

    print(f"[+] Total unique URLs: {len(lines)}")

if __name__ == "__main__":
    main()
