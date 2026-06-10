#!/usr/bin/env python3
"""
url_collect.py — URL collection using subprocess.Popen.
Fixes the background-task output-kill issue that breaks waybackurls/gau/katana.
Same fix as probe_live.py — Python subprocess.Popen bypasses Bash tool stream interception.

Hosts are processed in PARALLEL (a sequential loop over 100s of live hosts, each
running waybackurls + gau, made Phase 3 the pipeline's slowest stage by far).

Usage: python3 url_collect.py --live live.txt --output urls.txt
"""
import argparse, os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

GOBIN = os.path.expanduser("~/.recon-tools/bin")
_SKIP = re.compile(r'\.(css|js|png|jpg|gif|ico|woff|ttf|svg|mp4|pdf)(\?|$)', re.I)

def tool(name):
    p = os.path.join(GOBIN, name); return p if os.path.isfile(p) else name

def collect_domain(domain, timeout=120):
    """Run waybackurls + gau for one host; return (domain, [urls]). Thread-safe:
    returns its lines instead of writing, so the caller owns the single write."""
    urls = []
    for cmd in ([tool("waybackurls"), domain],
                [tool("gau"), "--threads", "3", domain]):
        proc = None
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True)
            # communicate() enforces a hard timeout on the whole read; the old
            # `for line in proc.stdout` loop could block forever if a tool hung.
            try:
                out, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
            for line in out.splitlines():
                line = line.strip()
                if line and not _SKIP.search(line):
                    urls.append(line)
        except Exception:
            if proc and proc.poll() is None:
                proc.kill()
    return domain, urls

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=20)
    args = parser.parse_args()

    if not os.path.isfile(args.live):
        print(f"[!] live file not found: {args.live}", file=sys.stderr)
        sys.exit(1)

    # Extract hostnames from the live file (strip scheme + any httpx decoration).
    domains = set()
    with open(args.live) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            domain = re.sub(r'https?://', '', line).split('/')[0].split('[')[0].strip()
            if domain:
                domains.add(domain)

    all_urls = set()
    print(f"[*] Collecting URLs from {len(domains)} hosts "
          f"(parallel, {args.threads} workers)...", flush=True)
    workers = max(1, min(args.threads, len(domains)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(collect_domain, d): d for d in sorted(domains)}
        for fut in as_completed(futs):
            d = futs[fut]
            try:
                _, urls = fut.result()
            except Exception:
                urls = []
            if urls:
                all_urls.update(urls)
                print(f"  {d}: {len(urls)}", flush=True)

    with open(args.output, "w") as f:
        for u in sorted(all_urls):
            f.write(u + "\n")
    print(f"[+] Total unique URLs: {len(all_urls)}")

if __name__ == "__main__":
    main()
