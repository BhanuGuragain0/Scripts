import asyncio
import aiohttp
import subprocess
import sys
import os
import time
import urllib.parse
from bs4 import BeautifulSoup
from datetime import datetime
import random
import pyfiglet
from colorama import Fore, Style, init
import psutil
import re
import logging
import qrcode

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DISCLAIMER_PAGE_URL = "http://gateway.example.com/no_cookie_loginpages/"
LOGIN_PAGE_URL = "http://gateway.example.com/loginpages/"
WI_FI_NAMES = [f"STWCU_LR-{i}" for i in range(1, 21)]
CREDENTIALS = {"username": "softwarica", "password": "coventry2019"}

# Sample list of user agents for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
]

# Display header with ASCII art
def display_header():
    ascii_art = pyfiglet.figlet_format("WiFi Auto Login")
    print(Fore.GREEN + ascii_art)

# Show loading animation
def show_loading_animation():
    for i in range(3):
        print(Fore.YELLOW + "Loading" + "." * i, end='\r')
        time.sleep(1)
    print(Fore.GREEN + "Done!")

# Check internet connectivity using provided session
async def check_internet_connectivity(session):
    try:
        async with session.get("http://www.google.com", timeout=5) as response:
            if response.status == 200:
                logging.info("Already connected to the internet.")
                show_connected_wifi_info()
                return True
    except aiohttp.ClientError as e:
        logging.warning(f"Internet connectivity check failed: {e}")
    return False

# Detect and connect to the nearest WiFi using nmcli
def detect_and_connect_to_wifi():
    try:
        result = subprocess.run(
            ['nmcli', '-f', 'SSID,SECURITY,SIGNAL', 'dev', 'wifi', 'list'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.splitlines()
        if len(lines) <= 1:
            logging.error("No WiFi networks found in nmcli output.")
            return None
        # Skip header and process networks
        networks = lines[1:]
        matching_networks = []
        for line in networks:
            # Split using multiple spaces as delimiter
            parts = [p.strip() for p in re.split(r'\s{2,}', line) if p.strip()]
            if not parts:
                continue
            ssid = parts[0]
            if any(wifi in ssid for wifi in WI_FI_NAMES):
                # Assuming signal is the third element; convert if possible
                try:
                    signal = int(parts[2]) if len(parts) >= 3 else 0
                except ValueError:
                    signal = 0
                matching_networks.append((ssid, signal))
        if not matching_networks:
            logging.error("No matching WiFi networks found.")
            return None
        # Sort networks by signal strength descending
        matching_networks.sort(key=lambda x: x[1], reverse=True)
        strongest_network = matching_networks[0][0]
        logging.info(f"Attempting to connect to WiFi network: {strongest_network}")
        # Connect to the selected WiFi network
        subprocess.run(['nmcli', 'dev', 'wifi', 'connect', strongest_network], check=True)
        logging.info(f"Connected to {strongest_network}")
        return strongest_network
    except subprocess.CalledProcessError as e:
        logging.error(f"Error connecting to WiFi: {e}")
        return None

# Handle portal login process
async def handle_portal_login(session):
    # Try the primary login page first
    try:
        async with session.get(LOGIN_PAGE_URL, timeout=5) as response:
            if response.status == 200:
                logging.info("Accessed login page.")
                return await login_process(session, response)
    except aiohttp.ClientError as e:
        logging.warning(f"Error accessing login page: {e}")

    # Fallback to disclaimer page if login page is not reachable
    try:
        async with session.get(DISCLAIMER_PAGE_URL, timeout=5) as response:
            if response.status == 200:
                soup = BeautifulSoup(await response.text(), 'html.parser')
                agree_button = soup.find('button', {'id': 'agree_button'})
                if agree_button and 'onclick' in agree_button.attrs:
                    onclick_value = agree_button['onclick']
                    # Extract URL from onclick using regex
                    match = re.search(r"'(http[^']+)'", onclick_value)
                    if match:
                        agree_url = match.group(1)
                        logging.info(f"Agree URL extracted: {agree_url}")
                        async with session.get(agree_url, timeout=5) as agree_response:
                            if agree_response.status == 200:
                                return await login_process(session, agree_response)
    except aiohttp.ClientError as e:
        logging.warning(f"Error accessing disclaimer page: {e}")

    # Final fallback: attempt connectivity to trigger portal login
    try:
        async with session.get("http://www.google.com", timeout=5) as response:
            if response.status == 200:
                return await login_process(session, response)
    except aiohttp.ClientError as e:
        logging.warning(f"Final fallback failed: {e}")
    logging.error("Portal login failed.")
    return None

# Perform login by submitting credentials via the form
async def login_process(session, response):
    content = await response.text()
    soup = BeautifulSoup(content, 'html.parser')
    login_form = soup.find('form', {'id': 'login_form'})
    if not login_form:
        # Fallback: try to find any form with a password input
        login_form = soup.find('form', lambda tag: tag.find('input', {'type': 'password'}))
    if login_form:
        action_url = login_form.get('action')
        if not action_url:
            logging.error("Login form action URL not found.")
            return None
        # Ensure action_url is absolute
        action_url = urllib.parse.urljoin(str(response.url), action_url)
        data = {
            'username': CREDENTIALS['username'],
            'password': CREDENTIALS['password']
        }
        logging.info(f"Submitting credentials to {action_url}")
        try:
            async with session.post(action_url, data=data, timeout=5) as post_response:
                post_content = await post_response.text()
                if "Hello, you are logged in via softwarica" in post_content:
                    logging.info("Login successful!")
                    await post_login_verification(session)
                    return True
                else:
                    logging.error("Login failed. Unexpected response received.")
                    return False
        except aiohttp.ClientError as e:
            logging.error(f"Error during form submission: {e}")
            return None
    else:
        logging.error("Login form not found in the portal page.")
        return None

# Post-login verification to check internet connectivity
async def post_login_verification(session):
    try:
        async with session.get("http://www.google.com", timeout=5) as response:
            if response.status == 200:
                logging.info("Internet connectivity verified post login.")
                ssid = get_current_ssid()
                if ssid:
                    show_wifi_qr_code(ssid, CREDENTIALS['password'])
                return True
            else:
                logging.error("Failed to verify internet connectivity after login.")
    except aiohttp.ClientError as e:
        logging.error(f"Error during post-login verification: {e}")
    return False

# Retrieve current connected WiFi SSID using nmcli
def get_current_ssid():
    try:
        result = subprocess.run(['nmcli', '-t', '-f', 'ACTIVE,SSID', 'dev', 'wifi'], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1]
    except subprocess.CalledProcessError as e:
        logging.error(f"Error retrieving connected WiFi SSID: {e}")
    return None

# Display connected WiFi information
def show_connected_wifi_info():
    try:
        result = subprocess.run(['nmcli', 'dev', 'wifi', 'show'], capture_output=True, text=True, check=True)
        print(Fore.CYAN + result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error showing WiFi info: {e}")

# Generate and display WiFi QR code in the terminal
def show_wifi_qr_code(ssid, password, encryption="WPA"):
    try:
        qr_data = f"WIFI:T:{encryption};S:{ssid};P:{password};;"
        qr = qrcode.QRCode(version=1, box_size=2, border=2)
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr.print_ascii(invert=True)  # Print ASCII representation of the QR code
        logging.info("WiFi QR code generated successfully.")
    except Exception as e:
        logging.error(f"Error generating WiFi QR code: {e}")

# Display system information
def show_system_info():
    try:
        user = os.getlogin()
    except Exception:
        user = "Unknown"
    print(Fore.CYAN + "System Information:")
    print(f"User: {user}")
    print(f"OS: {os.name}")
    uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
    print(f"Uptime: {uptime}")

# Main asynchronous function
async def main():
    display_header()
    show_system_info()
    show_loading_animation()
    # Create a session with a randomized User-Agent header
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    async with aiohttp.ClientSession(headers=headers) as session:
        if await check_internet_connectivity(session):
            return
        ssid = detect_and_connect_to_wifi()
        if not ssid:
            logging.error("Failed to connect to any matching WiFi network. Exiting.")
            return
        await asyncio.sleep(2)  # Allow time for connection stabilization
        await handle_portal_login(session)

if __name__ == "__main__":
    asyncio.run(main())
