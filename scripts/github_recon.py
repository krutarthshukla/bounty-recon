#!/usr/bin/env python3
"""
github_recon.py — Discover GitHub repos relevant to a target org for secret hunting.

Builds the candidate list TruffleHog (Phase G) scans for verified credentials.
Developers leak company secrets into:
  - Official org repos (e.g. github.com/<company>/*)
  - Personal repos where they accidentally committed company .env / configs
  - Forks of internal tools they took home for "convenience"

Discovery strategy (3 tiers of ownership confidence):

  CONFIRMED  — Repo is under the official GitHub organization.
               (Match: owner == resolved org handle.)

  LIKELY     — Personal repo whose author has been seen committing with the
               company email domain (e.g. *@example.com), OR who is a public
               member of the official org.

  POSSIBLE   — Personal repo whose code/README mentions the company domain or
               name, but no email/membership signal exists. Worth scanning but
               higher false-positive rate.

Auth:
  Uses `gh api`. The host's existing `gh auth login` provides the token —
  no GITHUB_TOKEN env var needed for discovery. (TruffleHog itself reads
  GITHUB_TOKEN, set separately.)

Output:
  JSON to --output with shape:
    {"org_login": "...", "scanned_domains": [...], "total": N, "repos": [
        {"full_name", "html_url", "clone_url", "owner", "owner_type",
         "tier", "evidence", "private", "fork"}, ...
    ]}

Usage:
  python3 github_recon.py --org "Acme" --domains "acme.com" \
    --output /tmp/br_github_repos.json [--org-handle acme] [--max-repos 200]
"""

import argparse, json, os, re, subprocess, sys
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed


def gh_api(path, paginate=False, jq=None):
    """Invoke `gh api`. Returns parsed JSON (list/dict) or [] on failure."""
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    cmd.append(path)
    if jq:
        cmd += ["--jq", jq]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if r.returncode != 0:
            return [] if paginate or jq else {}
        out = r.stdout.strip()
        if not out:
            return [] if paginate or jq else {}
        if jq:
            # --jq emits one JSON value per line for arrays
            results = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    results.append(line)
            return results
        # Paginated responses are concatenated JSON arrays — gh handles merging
        try:
            data = json.loads(out)
            return data
        except json.JSONDecodeError:
            # gh --paginate can emit `][` between pages; salvage by re-wrapping
            cleaned = out.replace("][", ",")
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                return [] if paginate else {}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [] if paginate or jq else {}


def resolve_org_handle(org_name, org_handle_hint=None):
    """Find the official GitHub org handle for a free-text org name.

    If `--org-handle` was supplied, validate it; otherwise search GitHub
    `search/users?type=org` and pick the highest-scoring match. Sanity-check
    matches whose login bears no resemblance to the name to avoid landing on
    a random unrelated org.
    """
    if org_handle_hint:
        data = gh_api(f"orgs/{org_handle_hint}")
        if data.get("login"):
            print(f"[*] Using --org-handle: {data['login']}", flush=True)
            return data["login"]
        print(f"[!] --org-handle '{org_handle_hint}' does not exist on GitHub. Continuing with name search.",
              flush=True)

    # Search for the org
    safe = re.sub(r'[^a-zA-Z0-9 ]', '', org_name).strip()
    if not safe:
        return None
    query = f"{safe} type:org"
    print(f"[*] Searching GitHub for org: '{safe}'…", flush=True)
    results = gh_api(f"search/users?q={query.replace(' ', '+')}&per_page=10")
    items = results.get("items", []) if isinstance(results, dict) else []
    if not items:
        return None

    # Pick the closest-name match. Prefer exact lowercase match, then prefix match.
    name_lower = safe.lower().replace(" ", "")
    for item in items:
        if item.get("login", "").lower() == name_lower:
            print(f"[+] Resolved org: {item['login']} (exact match)", flush=True)
            return item["login"]
    for item in items:
        login = item.get("login", "").lower()
        if name_lower in login or login in name_lower:
            print(f"[+] Resolved org: {item['login']} (substring match)", flush=True)
            return item["login"]

    # Fallback to top result with a warning
    top = items[0].get("login")
    print(f"[!] No exact match; using top search result: {top}", flush=True)
    return top


def list_org_repos(org_login, max_repos=200):
    """All public (non-fork preferred) repos under the official org."""
    print(f"[*] Listing repos for org {org_login}…", flush=True)
    repos = gh_api(f"orgs/{org_login}/repos?per_page=100&type=public", paginate=True)
    if not isinstance(repos, list):
        return []
    # De-prioritize forks (less likely to hold leaked secrets, often noise)
    repos.sort(key=lambda r: (r.get("fork", False), -(r.get("stargazers_count", 0) or 0)))
    print(f"[+] Org repos found: {len(repos)} (capped at {max_repos})", flush=True)
    return repos[:max_repos]


def list_org_members(org_login):
    """Public members of the org. Private members are invisible via API."""
    print(f"[*] Listing public org members for {org_login}…", flush=True)
    members = gh_api(f"orgs/{org_login}/members?per_page=100", paginate=True)
    if not isinstance(members, list):
        return []
    print(f"[+] Public members: {len(members)}", flush=True)
    return members


def find_repos_by_email_domain(domains, cap=120):
    """Find repos that hardcode a company email address — a real secret-leak
    vector — via GitHub CODE SEARCH for the literal "@<domain>".

    Why not commit search: GitHub commit search does NOT support author-email
    domain wildcards. The previous queries (`author-email:/@domain$/` and
    `@domain in:author-email`) are not valid qualifiers, so they silently
    returned zero and this whole LIKELY tier was dead. Code search for the
    "@<domain>" string is supported and surfaces personal/forked repos with a
    checked-in config / .env containing a company email.

    Returns a list of (repo_dict, evidence_str).
    """
    out = OrderedDict()  # key=full_name → (repo, evidence); preserves order
    for domain in domains:
        d = domain.strip().lower()
        if not d:
            continue
        print(f"[*] Code search for \"@{d}\" (hardcoded company emails)…", flush=True)
        # %22%40 = the URL-encoded "@ — matches the literal email pattern in code.
        results = gh_api(f"search/code?q=%22%40{d}%22&per_page=100", paginate=False)
        items = results.get("items", []) if isinstance(results, dict) else []
        for item in items:
            repo = item.get("repository") or {}
            fn = repo.get("full_name")
            if not fn or fn in out:
                continue
            path = item.get("path", "")
            out[fn] = (repo, f"Code hardcodes company email @{d} ({path})")
            if len(out) >= cap:
                break
        print(f"  [+] Repos mentioning @{d}: {len(out)} unique so far", flush=True)
        if len(out) >= cap:
            break
    return list(out.values())


def list_user_repos(user_login, per_user_cap=30):
    """Personal repos for a user. Cap per-user so a single prolific dev
    doesn't drown out everyone else in the candidate list."""
    repos = gh_api(f"users/{user_login}/repos?per_page=100&type=owner&sort=updated",
                   paginate=True)
    if not isinstance(repos, list):
        return []
    # Skip forks — leaked secrets are usually in original repos
    own = [r for r in repos if not r.get("fork")]
    return own[:per_user_cap]


def build_repo_entry(repo, tier, evidence):
    return {
        "full_name": repo.get("full_name"),
        "html_url": repo.get("html_url"),
        "clone_url": (repo.get("clone_url")
                      or (f"https://github.com/{repo.get('full_name')}.git"
                          if repo.get("full_name") else None)),
        "owner": (repo.get("owner") or {}).get("login"),
        "owner_type": (repo.get("owner") or {}).get("type"),
        "tier": tier,
        "evidence": evidence if isinstance(evidence, list) else [evidence],
        "private": repo.get("private", False),
        "fork": repo.get("fork", False),
        "stars": repo.get("stargazers_count", 0),
        "updated_at": repo.get("updated_at"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True, help="Org display name (e.g. 'Acme')")
    ap.add_argument("--org-handle", default="", help="Known GitHub org login (skips search)")
    ap.add_argument("--domains", required=True, help="Comma-separated email/company domains")
    ap.add_argument("--output", required=True)
    ap.add_argument("--max-repos", type=int, default=200, help="Cap org repos")
    ap.add_argument("--max-members", type=int, default=50, help="Cap members whose personal repos we enumerate")
    ap.add_argument("--max-email-authors", type=int, default=50, help="Cap email-pivot authors")
    args = ap.parse_args()

    # gh sanity check
    r = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if r.returncode != 0:
        print("[!] gh is not authenticated. Run `gh auth login` first.", file=sys.stderr)
        sys.exit(2)

    domains = [d.strip().lower() for d in args.domains.split(",") if d.strip()]

    # ── 1. Resolve official org ────────────────────────────────────────────
    org_login = resolve_org_handle(args.org, args.org_handle or None)
    repos_by_full_name = OrderedDict()  # dedupe by full_name; first-write-wins tier

    if org_login:
        org_repos = list_org_repos(org_login, args.max_repos)
        for r_ in org_repos:
            entry = build_repo_entry(r_, "CONFIRMED",
                                     [f"Under official org github.com/{org_login}"])
            repos_by_full_name[r_["full_name"]] = entry
    else:
        print("[!] Could not resolve an official GitHub org. Skipping CONFIRMED tier.",
              flush=True)

    # ── 2. Pivot via company email domain (GitHub code search) → LIKELY ─────
    email_repos = find_repos_by_email_domain(domains, cap=args.max_email_authors * 2)
    for repo, evidence in email_repos:
        fn = repo.get("full_name")
        if not fn or fn in repos_by_full_name:
            continue
        repos_by_full_name[fn] = build_repo_entry(repo, "LIKELY", [evidence])

    # ── 3. Pivot via public org membership → LIKELY (when not already seen) ─
    if org_login:
        members = list_org_members(org_login)[:args.max_members]
        print(f"[*] Enumerating personal repos of {len(members)} public org members…",
              flush=True)
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(list_user_repos, m.get("login")): m.get("login")
                       for m in members if m.get("login")}
            for fut in as_completed(futures):
                login = futures[fut]
                try:
                    user_repos = fut.result()
                except Exception:
                    continue
                for r_ in user_repos:
                    fn = r_.get("full_name")
                    if not fn or fn in repos_by_full_name:
                        continue
                    repos_by_full_name[fn] = build_repo_entry(
                        r_, "LIKELY",
                        [f"Owner @{login} is public member of github.com/{org_login}"])

    # ── 4. Write output ────────────────────────────────────────────────────
    out_list = list(repos_by_full_name.values())
    # Sort: CONFIRMED first, then LIKELY, then POSSIBLE; within tier by stars desc
    tier_rank = {"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2}
    out_list.sort(key=lambda r: (tier_rank.get(r["tier"], 3), -(r.get("stars") or 0)))

    payload = {
        "org_name": args.org,
        "org_login": org_login,
        "scanned_domains": domains,
        "total": len(out_list),
        "by_tier": {t: sum(1 for r in out_list if r["tier"] == t)
                    for t in ("CONFIRMED", "LIKELY", "POSSIBLE")},
        "repos": out_list,
    }
    with open(args.output, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"  GitHub repo discovery complete")
    for t in ("CONFIRMED", "LIKELY", "POSSIBLE"):
        n = payload["by_tier"].get(t, 0)
        if n:
            print(f"  {t:10}: {n}")
    print(f"  Total candidates: {len(out_list)}")
    print(f"  Output: {args.output}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
