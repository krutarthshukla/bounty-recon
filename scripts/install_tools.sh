#!/usr/bin/env bash
# bounty-recon install_tools.sh
# Installs all tools needed beyond what subdomain-recon already provides.
# Run once. Idempotent.

set -euo pipefail

TOOLS_DIR="$HOME/.recon-tools"
GOBIN="$TOOLS_DIR/bin"
mkdir -p "$GOBIN"
export GOPATH="$TOOLS_DIR" GOBIN="$GOBIN"
export PATH="$GOBIN:$PATH"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()     { echo -e "${GREEN}[✓]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
info()   { echo -e "    $*"; }
banner() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# Auto-add to shell
PATH_LINE='export PATH="$HOME/.recon-tools/bin:$PATH"'
for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    [ -f "$rc" ] && grep -qF "recon-tools" "$rc" 2>/dev/null || \
        printf '\n%s\n' "$PATH_LINE" >> "$rc" 2>/dev/null
done

go_install() {
    local name="$1" pkg="$2"
    # Only trust $GOBIN/$name — never `command -v $name`. Otherwise an unrelated
    # binary on PATH (e.g. pyenv's Python `httpx` HTTP client shadowing
    # ProjectDiscovery httpx) can satisfy the check, and the Go tool never lands
    # in $GOBIN — phases that hard-code $TOOLS_DIR/bin/<tool> then silently skip.
    [ -x "$GOBIN/$name" ] && { ok "$name"; return; }
    info "Installing $name…"
    # If caller already pinned a version (pkg contains '@'), use it as-is;
    # otherwise default to @latest. Prevents the `@master@latest` bug.
    local target="$pkg"
    [[ "$pkg" != *@* ]] && target="${pkg}@latest"
    GOBIN="$GOBIN" go install "$target" 2>/dev/null && ok "$name" || warn "$name failed"
}

# pipx is the upstream-recommended path for Python CLIs on modern macOS/Linux
# (PEP 668 systems refuse plain pip installs). Fall back through pip variants.
ensure_pipx() {
    command -v pipx &>/dev/null && return 0
    if   command -v brew    &>/dev/null; then brew install pipx -q 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then sudo apt-get install -y -qq pipx 2>/dev/null || true
    elif command -v dnf     &>/dev/null; then sudo dnf install -y -q pipx 2>/dev/null || true
    elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm python-pipx 2>/dev/null || true
    fi
    command -v pipx &>/dev/null || python3 -m pip install --user pipx -q 2>/dev/null \
        || python3 -m pip install --user pipx -q --break-system-packages 2>/dev/null || true
    command -v pipx &>/dev/null && pipx ensurepath &>/dev/null || true
    command -v pipx &>/dev/null
}

pipx_install() {
    ensure_pipx || return 1
    pipx install "$@" 2>/dev/null || pipx install --force "$@" 2>/dev/null
}

pip_install() {
    pip3 install "$@" -q 2>/dev/null \
      || pip3 install "$@" -q --break-system-packages 2>/dev/null \
      || python3 -m pip install "$@" -q --break-system-packages 2>/dev/null \
      || pip3 install "$@" -q --user 2>/dev/null
}

# Portable Go bootstrap (macOS / Linux distros)
[ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
if ! command -v go &>/dev/null; then
    info "Go not found — attempting install for this platform…"
    if   command -v brew    &>/dev/null; then brew install go 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then sudo apt-get update -qq && sudo apt-get install -y -qq golang-go 2>/dev/null || true
    elif command -v dnf     &>/dev/null; then sudo dnf install -y -q golang 2>/dev/null || true
    elif command -v yum     &>/dev/null; then sudo yum install -y -q golang 2>/dev/null || true
    elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm go 2>/dev/null || true
    elif command -v zypper  &>/dev/null; then sudo zypper install -y go 2>/dev/null || true
    fi
    [ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
    command -v go &>/dev/null || { warn "Go unavailable — install from https://go.dev/dl/"; exit 1; }
fi

banner "Vulnerability Scanners"
go_install "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
go_install "naabu"      "github.com/projectdiscovery/naabu/v2/cmd/naabu"
go_install "dalfox"     "github.com/hahwul/dalfox/v2"
go_install "ffuf"       "github.com/ffuf/ffuf/v2"
go_install "gowitness"  "github.com/sensepost/gowitness"

banner "URL Collection & Filtering"
go_install "gau"        "github.com/lc/gau/v2/cmd/gau"
go_install "waybackurls" "github.com/tomnomnom/waybackurls"
go_install "gf"         "github.com/tomnomnom/gf"
go_install "qsreplace"  "github.com/tomnomnom/qsreplace"
go_install "kxss"       "github.com/Emoe/kxss"
go_install "hakrawler"  "github.com/hakluke/hakrawler"
go_install "katana"     "github.com/projectdiscovery/katana/cmd/katana"

banner "Parameter & Content Discovery"
go_install "anew"       "github.com/tomnomnom/anew"
go_install "unfurl"     "github.com/tomnomnom/unfurl"
go_install "httprobe"   "github.com/tomnomnom/httprobe"

banner "Additional tools (PDF research additions)"
go_install "feroxbuster" "github.com/epi052/feroxbuster" 2>/dev/null || \
    { command -v cargo &>/dev/null && cargo install feroxbuster --quiet 2>/dev/null; } || \
    warn "feroxbuster — install manually: cargo install feroxbuster"
go_install "subjack"     "github.com/haccer/subjack"
go_install "kxss"        "github.com/Emoe/kxss"
go_install "hakrawler"   "github.com/hakluke/hakrawler"
# S3Scanner — Haddix/NahamSec staple for bucket enum. Repo name is mixed-case;
# `go install` resolves it lower-case, the binary lands as `S3Scanner`. Symlink
# to a stable lowercase name so phase code doesn't have to know.
go_install "S3Scanner"   "github.com/sa7mon/S3Scanner"
[ -x "$GOBIN/S3Scanner" ] && ln -sf "$GOBIN/S3Scanner" "$GOBIN/s3scanner" 2>/dev/null || true

banner "Modern recon stack (2025-2026 additions)"
# cdncheck — fingerprint CDN/WAF/cloud-fronted hosts so we don't waste time
# port-scanning Cloudflare IPs and don't trip WAFs. ProjectDiscovery library.
go_install "cdncheck"   "github.com/projectdiscovery/cdncheck/cmd/cdncheck"
# tlsx — TLS/cert intel at scale: SAN pivoting, JARM, weak cipher detection.
# Adds material new subdomain candidates over what subfinder/uncover return.
go_install "tlsx"       "github.com/projectdiscovery/tlsx/cmd/tlsx"
# JSLuice — BishopFox AST-based JS parser. Surfaces routes/secrets/API paths
# from webpack/minified bundles that regex tools (incl. trufflehog) miss.
go_install "jsluice"    "github.com/BishopFox/jsluice/cmd/jsluice"
# kiterunner — Assetnote API content discovery. 800k+ Swagger-scraped route
# wordlist with content-type-aware fuzzing; finds shadow REST endpoints
# directory-busters miss.
go_install "kr"         "github.com/assetnote/kiterunner/cmd/kiterunner"
[ -x "$GOBIN/kr" ] && ln -sf "$GOBIN/kr" "$GOBIN/kiterunner" 2>/dev/null || true
# crlfuzz — CRLF injection at scale (header injection → XSS/cache poisoning).
go_install "crlfuzz"    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
# x8 — hidden parameter discovery (body/query/headers). Materially better
# than arjun (which misses headers). Rust-based.
if command -v cargo &>/dev/null; then
    [ -x "$GOBIN/x8" ] && ok "x8" || {
        info "Installing x8 via cargo…"
        cargo install x8 --quiet --root "$TOOLS_DIR" 2>/dev/null \
            && ok "x8" || warn "x8 cargo install failed (optional)"
    }
else
    warn "cargo not present — skipping x8 (install rust + retry to enable)"
fi
# sourcemapper — recovers original source from leaked .map files. Massive
# impact-multiplier when a target ships sourcemaps to prod.
go_install "sourcemapper" "github.com/denandz/sourcemapper"

banner "Modern recon stack — Python tools"
# graphw00f / clairvoyance / graphql-cop — GraphQL deep testing trio:
#   graphw00f      → fingerprint the engine (Apollo, Hasura, AWS AppSync, etc.)
#   clairvoyance   → recover schema even when introspection is OFF
#   graphql-cop    → audit batching, depth, alias DoS, CSRF, auth flaws
# Together they cover GraphQL well beyond the simple introspection probe in
# Phase L of vuln_scan.
for pkg in graphw00f clairvoyance graphql-cop; do
    if command -v "$pkg" &>/dev/null; then
        ok "$pkg"
    elif pipx_install "$pkg" &>/dev/null || pip_install "$pkg"; then
        ok "$pkg installed"
    else
        warn "$pkg failed (optional)"
    fi
done
# cloud_enum — multi-cloud public-asset enum (AWS S3 + Azure storage/blobs/
# vaults + GCP buckets/firebase). Closes the Azure/GCP gap S3Scanner doesn't.
if command -v cloud_enum &>/dev/null; then
    ok "cloud_enum"
else
    git clone --depth=1 https://github.com/initstring/cloud_enum \
        "$TOOLS_DIR/cloud_enum" 2>/dev/null || true
    if [ -f "$TOOLS_DIR/cloud_enum/cloud_enum.py" ]; then
        pip_install "$(cat "$TOOLS_DIR/cloud_enum/requirements.txt" 2>/dev/null)" >/dev/null 2>&1 || true
        cat > "$GOBIN/cloud_enum" <<'WRAP'
#!/usr/bin/env bash
exec python3 "$HOME/.recon-tools/cloud_enum/cloud_enum.py" "$@"
WRAP
        chmod +x "$GOBIN/cloud_enum"
        ok "cloud_enum installed"
    else
        warn "cloud_enum clone failed (optional)"
    fi
fi
# bypass-403 — quick path-based 403 bypass kit (single bash script). Cloned
# under $TOOLS_DIR and shim'd into $GOBIN so phase code calls it like any
# other tool.
if [ ! -x "$GOBIN/bypass-403" ]; then
    git clone --depth=1 https://github.com/iamj0ker/bypass-403 \
        "$TOOLS_DIR/bypass-403-src" 2>/dev/null || true
    if [ -f "$TOOLS_DIR/bypass-403-src/bypass-403.sh" ]; then
        ln -sf "$TOOLS_DIR/bypass-403-src/bypass-403.sh" "$GOBIN/bypass-403"
        chmod +x "$TOOLS_DIR/bypass-403-src/bypass-403.sh"
        ok "bypass-403 installed"
    else
        warn "bypass-403 clone failed (optional)"
    fi
fi

banner "TruffleHog v3 (verified secret scanning)"
# TruffleHog v3 (trufflesecurity/trufflehog) is the Go-based verified-secret scanner
# we use in Phase G. The PyPI package named "trufflehog" is the legacy v2 with
# no verification — we explicitly avoid it. Install order:
#   1) $GOBIN binary (if already installed via go install)
#   2) brew (macOS)
#   3) upstream install.sh (Linux + macOS fallback)
#   4) go install (last resort — slower build)
install_trufflehog() {
    [ -x "$GOBIN/trufflehog" ] && { ok "trufflehog (v3)"; return; }
    if command -v trufflehog &>/dev/null; then
        # Ensure it's v3, not the legacy PyPI v2 still on PATH.
        if trufflehog --version 2>&1 | grep -qiE 'trufflehog v3|3\.[0-9]+'; then
            ok "trufflehog (v3, on PATH)"; return
        fi
        warn "Found legacy trufflehog v2 on PATH — installing v3 to $GOBIN/ alongside"
    fi
    info "Installing trufflehog v3…"
    if command -v brew &>/dev/null; then
        brew install trufflehog -q 2>/dev/null && \
            { ln -sf "$(brew --prefix)/bin/trufflehog" "$GOBIN/trufflehog" 2>/dev/null; ok "trufflehog (brew)"; return; }
    fi
    # Upstream installer: writes to $GOBIN directly via -b flag (works on macOS+Linux)
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b "$GOBIN" 2>/dev/null && [ -x "$GOBIN/trufflehog" ]; then
        ok "trufflehog (upstream installer)"; return
    fi
    # Final fallback — build from source via go install
    GOBIN="$GOBIN" go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null \
        && [ -x "$GOBIN/trufflehog" ] && ok "trufflehog (go install)" \
        || warn "trufflehog install failed — Phase G (secret scanning) will be skipped"
}
install_trufflehog

banner "Python tools"
# Prefer pipx (isolated venv, PEP 668-safe) and fall back to pip variants.
# BadDNS pulls in `blasthttp` which needs rust + openssl headers — make sure
# they're present before the install attempt.
# NOTE: `trufflehog` deliberately NOT in this list — the PyPI package is the
# deprecated v2 with no verification. v3 is installed via install_trufflehog above.
if ! command -v cargo &>/dev/null; then
    command -v brew &>/dev/null && brew install rust -q 2>/dev/null || true
fi
if command -v brew &>/dev/null && brew --prefix openssl@3 &>/dev/null; then
    export OPENSSL_DIR="$(brew --prefix openssl@3)"
    export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
    export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
fi
for pkg in arjun corsy baddns linkfinder; do
    if command -v "$pkg" &>/dev/null; then
        ok "$pkg"
    elif pipx_install "$pkg" &>/dev/null || pip_install "$pkg"; then
        ok "$pkg installed"
    else
        warn "$pkg failed (optional)"
    fi
done
# sqlmap
if command -v sqlmap &>/dev/null; then
    ok "sqlmap"
elif pipx_install sqlmap &>/dev/null || pip_install sqlmap; then
    ok "sqlmap installed"
else
    warn "sqlmap (optional)"
fi

banner "Nuclei templates (update)"
nuclei -update-templates -silent 2>/dev/null && ok "nuclei-templates updated" || warn "nuclei-templates update failed"

banner "Wordlists"
WLDIR="$HOME/.recon-tools/wordlists"
mkdir -p "$WLDIR"
# Top-5k subdomains for ffuf VHost discovery (Phase O of vuln_scan)
if [ ! -s "$WLDIR/subdomains-top5k.txt" ]; then
    info "Downloading subdomains-top5k for vhost discovery..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -o "$WLDIR/subdomains-top5k.txt" 2>/dev/null \
        && ok "subdomains-top5k.txt ($(wc -l < "$WLDIR/subdomains-top5k.txt") words)" \
        || warn "subdomains-top5k download failed (vhost phase will fall back to top-110k)"
fi

# gf patterns (tomnomnom's patterns)
GF_PATTERNS="$HOME/.gf"
mkdir -p "$GF_PATTERNS"
if [ ! -f "$GF_PATTERNS/xss.json" ]; then
    info "Installing gf patterns…"
    git clone --depth=1 https://github.com/tomnomnom/gf /tmp/_gf 2>/dev/null || true
    [ -d "/tmp/_gf/examples" ] && cp /tmp/_gf/examples/*.json "$GF_PATTERNS/" 2>/dev/null || true
    # Also get 1ndianl33t patterns (more comprehensive)
    git clone --depth=1 https://github.com/1ndianl33t/Gf-Patterns /tmp/_gfp 2>/dev/null || true
    [ -d "/tmp/_gfp" ] && cp /tmp/_gfp/*.json "$GF_PATTERNS/" 2>/dev/null || true
    ok "gf patterns installed"
fi

banner "Summary"
for t in nuclei dalfox ffuf naabu gowitness gau gf qsreplace kxss katana anew arjun \
         trufflehog s3scanner subjack cdncheck tlsx jsluice kiterunner crlfuzz \
         sourcemapper x8 bypass-403 cloud_enum; do
    [ -f "$GOBIN/$t" ] || command -v "$t" &>/dev/null \
        && echo -e "  ${GREEN}✓${NC} $t" || echo -e "  ${YELLOW}?${NC} $t"
done
echo ""
echo -e "  Templates: ${CYAN}$(ls ~/.local/nuclei-templates/http/ 2>/dev/null | wc -l) dirs${NC}"
echo -e "  gf patterns: ${CYAN}$(ls ~/.gf/*.json 2>/dev/null | wc -l) patterns${NC}"
