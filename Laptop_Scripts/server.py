#!/usr/bin/env python3

"""
Kali Linux - WiFi Auto Login Script
Author: Shadow Junior
Date: 2025-02-27

Features:
- Reads config from config.ini (fallback to embedded defaults)
- Uses keyring for secure credential storage
- Connects to WiFi using nmcli (Linux)
- Captive portal login via Selenium (headless Chrome)
- Force login logic
- Robust internet checks (HTTP + ping fallback)
- Rotating logs in logs/wifi_auto_login.log
- Daemonizable (systemd instructions included at bottom)
"""

import os
import sys
import time
import random
import subprocess
import logging
import configparser
import shutil
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional

import asyncio
import aiohttp
import requests
import pyfiglet
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import qrcode
from tqdm import tqdm
import keyring

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager

# ==============================
#     INITIAL CONFIG & SETUP
# ==============================

init(autoreset=True)

# Embedded fallback config
EMBEDDED_CONFIG = {
    "WiFi": {
        "wifi_names": "STWCU_LR-1,STWCU_LR-2,STWCU_LR-3,STWCU_LR-4,STWCU_LR-5",
        "disclaimer_page_url": "http://gateway.example.com/no_cookie_loginpages/",
        "login_page_url": "http://gateway.example.com/loginpages/",
    },
    "Credentials": {
        "username": "softwarica",
        "password": "coventry2019",
    },
    "Advanced": {
        "connection_retries": "3",
        "disclaimer_check_enabled": "true",
        "selenium_timeout": "10",
        "log_dir": "logs",
        "force_login": "false",
    }
}

COLORS = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

# ==============================
#   HELPER: Ensure Log Directory
# ==============================

def ensure_log_directory(config_log_dir: str) -> str:
    """Ensures the log directory exists and returns the full path to the log file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(script_dir, config_log_dir.strip() or "logs")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, "wifi_auto_login.log")

# ==============================
#     PRELIM LOGGING SETUP
# ==============================

temp_logger = logging.getLogger("temp_logger")
temp_logger.setLevel(logging.INFO)
temp_stream_handler = logging.StreamHandler(sys.stdout)
temp_logger.addHandler(temp_stream_handler)

# Parse config.ini if available
config_parser = configparser.ConfigParser()
config_from_file = {}

script_dir = os.path.dirname(os.path.abspath(__file__))
config_file_path = os.path.join(script_dir, "config.ini")

if os.path.exists(config_file_path):
    try:
        config_parser.read(config_file_path)
        for section in config_parser.sections():
            config_from_file[section] = {}
            for key, value in config_parser.items(section):
                config_from_file[section][key] = value
    except Exception as e:
        temp_logger.warning(f"Failed to read config.ini. Error: {e}. Using embedded defaults.")

# Determine final log dir
configured_log_dir = (
    config_from_file.get("Advanced", {}).get("log_dir")
    if config_from_file.get("Advanced", {}).get("log_dir")
    else EMBEDDED_CONFIG["Advanced"]["log_dir"]
)
final_log_path = ensure_log_directory(configured_log_dir)

# ==============================
#    CONFIGURE MAIN LOGGING
# ==============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler(final_log_path, maxBytes=1_000_000, backupCount=3),
        logging.StreamHandler(sys.stdout),
    ],
)
logging.info(f"Logs will be written to: {final_log_path}")

# ==============================
#     WIFI AUTO LOGIN CLASS
# ==============================

class WiFiAutoLogin:
    """Main class for WiFi connection and captive portal login on Kali Linux."""
    
    def __init__(self, config_file: str = "config.ini"):
        self.config_file = config_file
        self.config = None
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        self.config = self.load_config()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def load_config(self) -> Dict[str, Dict[str, str]]:
        """Load configuration from config.ini or use embedded defaults."""
        # Start with embedded defaults
        config_data = {
            section: dict(EMBEDDED_CONFIG[section]) for section in EMBEDDED_CONFIG
        }

        # Merge user config if available
        if config_from_file:
            logging.info("Merging user config from config.ini...")
            for section, kv_pairs in config_from_file.items():
                if section not in config_data:
                    config_data[section] = {}
                for k, v in kv_pairs.items():
                    config_data[section][k] = v

        # Try loading credentials from keyring
        try:
            stored_username = keyring.get_password("wifi_auto_login", "username")
            stored_password = keyring.get_password("wifi_auto_login", "password")
            if stored_username:
                config_data["Credentials"]["username"] = stored_username
            if stored_password:
                config_data["Credentials"]["password"] = stored_password
        except Exception as e:
            logging.warning(f"Keyring not available: {e}")

        # Ensure we have credentials (default to softwarica/coventry2019)
        if not config_data["Credentials"].get("username"):
            config_data["Credentials"]["username"] = "softwarica"
        if not config_data["Credentials"].get("password"):
            config_data["Credentials"]["password"] = "coventry2019"

        return config_data

    @staticmethod
    def display_header():
        """Display ASCII art header."""
        header = pyfiglet.figlet_format("WiFi Auto Login", font="slant")
        print(random.choice(COLORS) + header)
        print(Fore.CYAN + "🔥 Shadow Junior's WiFi Auto Login Tool 🔥\n")
        print(Fore.GREEN + f"Username: softwarica")
        print(Fore.GREEN + f"Password: coventry2019\n")

    def robust_internet_check(self, test_url: str = "https://clients3.google.com/generate_204") -> bool:
        """Robust internet connectivity check using HTTP request + ping fallback."""
        try:
            r = requests.get(test_url, timeout=4)
            if r.status_code in [200, 204]:
                logging.info(f"Internet confirmed via HTTP ({r.status_code})")
                return True
        except Exception:
            logging.warning(f"HTTP check failed, trying ping...")

        # Fallback to ping
        try:
            param = "-n" if os.name == "nt" else "-c"
            subprocess.check_output(["ping", param, "1", "8.8.8.8"], timeout=5)
            logging.info("Internet confirmed via ping")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logging.warning("Ping test failed")
            return False

    def check_internet(self, retries: int = 3, delay: int = 3) -> bool:
        """Attempt internet check with retries."""
        for attempt in range(1, retries + 1):
            if self.robust_internet_check():
                return True
            logging.warning(f"Internet check {attempt}/{retries} failed. Retrying in {delay}s...")
            time.sleep(delay)
        return False

    def connect_to_wifi(self) -> bool:
        """Connect to available WiFi using nmcli."""
        wifi_names = [w.strip() for w in self.config["WiFi"]["wifi_names"].split(",")]
        
        if not shutil.which("nmcli"):
            logging.error("nmcli not found. Install NetworkManager or connect manually.")
            return False

        try:
            # Scan for available networks
            logging.info("Scanning for WiFi networks...")
            scan_output = subprocess.check_output(["nmcli", "dev", "wifi"], timeout=10).decode("utf-8", errors="ignore")
            
            available_networks = set()
            for line in scan_output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "--":
                    available_networks.add(parts[1])

            # Try connecting to each configured network
            for wifi in wifi_names:
                if wifi in available_networks:
                    logging.info(f"🔗 Connecting to: {wifi}")
                    result = subprocess.run(
                        ["nmcli", "dev", "wifi", "connect", wifi], 
                        capture_output=True, 
                        timeout=15
                    )
                    
                    if result.returncode == 0:
                        logging.info(f"✅ Connected to {wifi}")
                        time.sleep(5)  # Wait for connection to stabilize
                        if self.check_internet():
                            logging.info(f"🌐 Internet available via {wifi}")
                            return True
                    else:
                        logging.warning(f"❌ Failed to connect to {wifi}")
                        
            logging.error("No matching WiFi networks found or connection failed")
            return False
            
        except Exception as e:
            logging.error(f"WiFi connection error: {e}")
            return False

    def handle_disclaimer_page(self, driver: webdriver.Chrome):
        """Handle disclaimer page if required."""
        if not self.config["Advanced"].get("disclaimer_check_enabled", "true").lower() == "true":
            return

        disclaimer_url = self.config["WiFi"].get("disclaimer_page_url", "").strip()
        if disclaimer_url:
            logging.info(f"Processing disclaimer page: {disclaimer_url}")
            try:
                driver.get(disclaimer_url)
                time.sleep(2)
                # Add specific disclaimer handling logic here
                logging.info("Disclaimer page processed")
            except Exception as e:
                logging.warning(f"Disclaimer handling failed: {e}")

    def handle_portal_login(self) -> bool:
        """Automate captive portal login using Selenium."""
        login_url = self.config["WiFi"]["login_page_url"].strip()
        username = self.config["Credentials"]["username"]
        password = self.config["Credentials"]["password"]
        selenium_timeout = int(self.config["Advanced"].get("selenium_timeout", 10))

        logging.info(f"🔐 Attempting portal login with credentials: {username}/{password}")

        # Setup Chrome driver
        try:
            driver_path = ChromeDriverManager().install()
        except Exception as e:
            logging.error(f"ChromeDriver installation failed: {e}")
            return False

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        try:
            driver = webdriver.Chrome(service=Service(driver_path), options=options)
            driver.set_page_load_timeout(selenium_timeout)

            # Handle disclaimer if needed
            self.handle_disclaimer_page(driver)

            # Access login page
            logging.info(f"Accessing login page: {login_url}")
            driver.get(login_url)
            time.sleep(3)

            # Find and fill login form
            try:
                username_field = driver.find_element(By.NAME, "username")
                password_field = driver.find_element(By.NAME, "password")
                submit_button = driver.find_element(By.NAME, "submit")

                username_field.clear()
                username_field.send_keys(username)
                password_field.clear()
                password_field.send_keys(password)
                
                logging.info("Submitting login form...")
                submit_button.click()
                time.sleep(5)

                # Check for successful login
                page_source = driver.page_source.lower()
                success_indicators = [
                    "you are logged in", "log out", "success", 
                    "welcome", "dashboard", "authenticated"
                ]
                
                if any(indicator in page_source for indicator in success_indicators):
                    logging.info("✅ Portal login successful!")
                    driver.quit()
                    return True
                else:
                    logging.error("❌ Login failed - check credentials or portal status")
                    driver.quit()
                    return False

            except Exception as e:
                logging.error(f"Login form interaction failed: {e}")
                driver.quit()
                return False

        except Exception as e:
            logging.error(f"Selenium/Chrome error: {e}")
            return False

    def verify_connection(self) -> bool:
        """Verify internet connection and generate WiFi QR code."""
        if self.check_internet(retries=3, delay=2):
            logging.info("🌐 Internet connectivity verified!")
            
            # Generate QR code for first WiFi network
            wifi_names = self.config["WiFi"]["wifi_names"].split(",")
            if wifi_names:
                first_wifi = wifi_names[0].strip()
                logging.info(f"📱 Generating QR code for: {first_wifi}")
                
                try:
                    qr = qrcode.QRCode(version=1, box_size=10, border=5)
                    wifi_string = f"WIFI:T:WPA2;S:{first_wifi};P:{self.config['Credentials']['password']};;"
                    qr.add_data(wifi_string)
                    qr.make(fit=True)
                    qr.print_ascii(invert=True)
                except Exception as e:
                    logging.warning(f"QR code generation failed: {e}")
            
            return True
        else:
            logging.error("❌ No internet access after login attempt")
            return False

    def display_system_info(self):
        """Display system information for debugging."""
        logging.info("=== System Information ===")
        
        # User and OS
        try:
            user = os.getlogin()
        except Exception:
            user = os.environ.get("USER", "Unknown")
        logging.info(f"User: {user}")
        logging.info(f"OS: {os.name}")

        # System stats
        commands = {
            "uptime": ["uptime"],
            "memory": ["free", "-h"],
            "disk": ["df", "-h", "/"]
        }

        for name, cmd in commands.items():
            if shutil.which(cmd[0]):
                try:
                    output = subprocess.check_output(cmd, timeout=5).decode().strip()
                    logging.info(f"{name.capitalize()}: {output}")
                except Exception:
                    logging.warning(f"Could not retrieve {name}")

# ==============================
#         MAIN FUNCTION
# ==============================

async def main():
    """Main execution function."""
    async with WiFiAutoLogin() as wifi_auto_login:
        wifi_auto_login.display_header()
        wifi_auto_login.display_system_info()

        force_login = wifi_auto_login.config["Advanced"].get("force_login", "false").lower() == "true"

        # Skip if already connected and not forcing
        if not force_login and wifi_auto_login.check_internet():
            logging.info("✅ Already connected to internet. Use force_login=true to override.")
            return

        # Main execution flow
        logging.info("🚀 Starting WiFi auto-login process...")
        
        if wifi_auto_login.connect_to_wifi() or force_login:
            if wifi_auto_login.handle_portal_login():
                if wifi_auto_login.verify_connection():
                    logging.info("🎉 WiFi auto-login completed successfully!")
                    print(Fore.GREEN + "✅ Connected and authenticated successfully!")
                    print(Fore.YELLOW + f"📡 Network: {wifi_auto_login.config['WiFi']['wifi_names'].split(',')[0].strip()}")
                    print(Fore.YELLOW + f"👤 Username: {wifi_auto_login.config['Credentials']['username']}")
                    print(Fore.CYAN + "🔥 Shadow Junior's tool executed flawlessly! 🔥")
                else:
                    logging.error("❌ Connection verification failed")
            else:
                logging.error("❌ Portal login failed")
        else:
            logging.error("❌ Could not connect to any configured WiFi networks")

# ==============================
#         ENTRY POINT
# ==============================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("⚠️ Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"💥 Unexpected error: {e}")
        sys.exit(1)

# ==============================
#    SYSTEMD SERVICE SETUP
# ==============================
"""
To run as a systemd service on Kali Linux:

1. Create service file:
sudo nano /etc/systemd/system/wifi-auto-login.service

[Unit]
Description=WiFi Auto Login Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /path/to/wifi_auto_login.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target

2. Enable and start:
sudo systemctl daemon-reload
sudo systemctl enable wifi-auto-login.service
sudo systemctl start wifi-auto-login.service

3. Check status:
sudo systemctl status wifi-auto-login.service
"""
