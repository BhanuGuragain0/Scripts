#!/usr/bin/env python3

"""
Kali Linux - WiFi Auto Login Script
Author: You
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
- Future placeholders: Slack/Telegram notifications, AI disclaimers, etc.
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
import requests  # For robust HTTP check
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

# Initialize colorama for colorful console output
init(autoreset=True)

# Embedded fallback config for usage if config.ini is missing or incomplete
EMBEDDED_CONFIG = {
    "WiFi": {
        "wifi_names": "STWCU_LR-1, STWCU_LR-2, STWCU_LR-3, STWCU_LR-4, STWCU_LR-5",
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

# Some color variety for the ASCII banner
COLORS = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

# ==============================
#   HELPER: Ensure Log Directory
# ==============================

def ensure_log_directory(config_log_dir: str) -> str:
    """
    Ensures the log directory exists.
    Returns the full path to the wifi_auto_login.log file.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # If user-specified, use that, otherwise default to 'logs'
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

# We’ll parse config.ini for a custom log directory if available
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
    """
    Main class for loading config, connecting to WiFi, and handling captive portal login on Kali Linux.
    """
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
        """
        Load configuration from config.ini if it exists, else fallback to EMBEDDED_CONFIG.
        Also tries to load credentials from the system keyring.
        """
        # Start by copying embedded defaults
        config_data = {
            section: dict(EMBEDDED_CONFIG[section]) for section in EMBEDDED_CONFIG
        }

        # Merge user config from global config_from_file if found
        if config_from_file:
            logging.info("Merging user config from config.ini into defaults...")
            for section, kv_pairs in config_from_file.items():
                if section not in config_data:
                    config_data[section] = {}
                for k, v in kv_pairs.items():
                    config_data[section][k] = v

        # Attempt to load credentials from keyring
        try:
            stored_username = keyring.get_password("wifi_auto_login", "username")
            stored_password = keyring.get_password("wifi_auto_login", "password")
            if stored_username:
                config_data["Credentials"]["username"] = stored_username
            if stored_password:
                config_data["Credentials"]["password"] = stored_password
        except Exception as e:
            logging.warning(f"Keyring not available: {e}")

        # Prompt for missing credentials
        if not config_data["Credentials"].get("username") or not config_data["Credentials"].get("password"):
            print(Fore.YELLOW + "Credentials not found or incomplete. Please enter your WiFi login details:")
            config_data["Credentials"]["username"] = input("Username: ")
            config_data["Credentials"]["password"] = input("Password: ")
            # Save them to keyring
            try:
                keyring.set_password("wifi_auto_login", "username", config_data["Credentials"]["username"])
                keyring.set_password("wifi_auto_login", "password", config_data["Credentials"]["password"])
            except Exception as e:
                logging.warning(f"Failed to save credentials to keyring: {e}")

        return config_data

    @staticmethod
    def display_header():
        """Display an ASCII art header."""
        header = pyfiglet.figlet_format("WiFi Auto Login", font="slant")
        print(random.choice(COLORS) + header)
        print(Fore.CYAN + "Initializing script...\n")

    def robust_internet_check(self, test_url: str = "https://clients3.google.com/generate_204") -> bool:
        """
        A more robust check that first tries a quick HTTP 204/200 request.
        If that fails, it falls back to ping. Returns True if internet is up.
        """
        try:
            r = requests.get(test_url, timeout=4)
            if r.status_code in [200, 204]:
                logging.info(f"Confirmed internet by HTTP request to {test_url} (status={r.status_code}).")
                return True
        except Exception:
            logging.warning(f"HTTP check to {test_url} failed, falling back to ping test...")

        # Fallback to ping
        try:
            param = "-n" if os.name == "nt" else "-c"
            subprocess.check_output(["ping", param, "1", "google.com"])
            logging.info("Confirmed internet connection by ping.")
            return True
        except subprocess.CalledProcessError:
            logging.warning("Ping test to google.com failed.")
            return False

    def check_internet(self, retries: int = 3, delay: int = 3) -> bool:
        """
        Attempt a robust internet check multiple times. Return True if successful, else False.
        """
        for attempt in range(1, retries + 1):
            if self.robust_internet_check():
                return True
            logging.warning(f"Attempt {attempt}/{retries} to confirm internet failed. Retrying in {delay}s...")
            time.sleep(delay)
        return False

    def connect_to_wifi(self) -> bool:
        """
        Connect to an available WiFi from the config list using nmcli (Kali Linux).
        Returns True on success, False if no network could be connected.
        """
        wifi_names = [w.strip() for w in self.config["WiFi"]["wifi_names"].split(",")]
        
        # Check nmcli availability
        if not shutil.which("nmcli"):
            logging.error("`nmcli` not found on system. Please install NetworkManager or connect manually.")
            return False

        try:
            # Scan WiFi
            scan_output = subprocess.check_output(["nmcli", "dev", "wifi"]).decode("utf-8", errors="ignore")
            available_networks = {}
            for line in scan_output.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 2:
                    continue
                ssid = parts[1]
                if ssid != "--":
                    available_networks[ssid] = line

            # Attempt connection
            for wifi in wifi_names:
                if wifi in available_networks:
                    logging.info(f"Attempting to connect to: {wifi}")
                    subprocess.run(["nmcli", "dev", "wifi", "connect", wifi], check=False)
                    time.sleep(5)  # Wait a bit
                    if self.check_internet():
                        logging.info(f"Connected successfully to {wifi}")
                        return True
                    else:
                        logging.warning(f"No internet after connecting to {wifi}. Trying next network...")
            logging.error("No matching WiFi found or unable to connect to any listed network.")
            return False
        except Exception as e:
            logging.error(f"Error connecting to WiFi: {e}")
            return False

    def handle_disclaimer_page(self, driver: webdriver.Chrome):
        """
        If a disclaimer page is needed before the login page, handle it here.
        Extend as needed for your actual disclaimers.
        """
        disclaimer_check_enabled = self.config["Advanced"].get("disclaimer_check_enabled", "true").lower() == "true"
        if not disclaimer_check_enabled:
            logging.info("Disclaimer check disabled in config.")
            return

        disclaimer_url = self.config["WiFi"].get("disclaimer_page_url", "").strip()
        if disclaimer_url:
            logging.info(f"Accessing disclaimer page: {disclaimer_url}")
            try:
                driver.get(disclaimer_url)
                time.sleep(2)
                # Example: if there's an Accept button
                # accept_button = driver.find_element(By.ID, "accept")
                # accept_button.click()
                # time.sleep(1)
            except Exception as e:
                logging.warning(f"Disclaimer page handling failed: {e}")

    def handle_portal_login(self) -> bool:
        """
        Automate captive portal login using Selenium. Returns True if login was successful.
        """
        login_url = self.config["WiFi"]["login_page_url"].strip()
        username = self.config["Credentials"]["username"]
        password = self.config["Credentials"]["password"]
        selenium_timeout = int(self.config["Advanced"].get("selenium_timeout", 10))

        # Check/install ChromeDriver
        try:
            driver_path = ChromeDriverManager().install()
        except Exception as e:
            logging.error(f"Unable to install/find ChromeDriver: {e}")
            return False

        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")

        try:
            driver = webdriver.Chrome(service=Service(driver_path), options=options)
            driver.set_page_load_timeout(selenium_timeout)

            # Possibly handle disclaimers first
            self.handle_disclaimer_page(driver)

            logging.info(f"Accessing login page: {login_url}")
            driver.get(login_url)
            time.sleep(3)

            # Interact with login form
            try:
                username_field = driver.find_element(By.NAME, "username")
                password_field = driver.find_element(By.NAME, "password")
                submit_button = driver.find_element(By.NAME, "submit")

                username_field.send_keys(username)
                password_field.send_keys(password)
                submit_button.click()
                time.sleep(3)

                page_source = driver.page_source.lower()
                if ("you are logged in" in page_source
                        or "log out" in page_source
                        or "success" in page_source
                        or "hello," in page_source):
                    logging.info("Login successful!")
                    driver.quit()
                    return True
                else:
                    logging.error("Login failed. Check credentials or portal issues.")
                    driver.quit()
                    return False
            except Exception as e:
                logging.error(f"Error interacting with login form: {e}")
                driver.quit()
                return False

        except Exception as e:
            logging.error(f"Selenium/Chrome error: {e}")
            return False

    def verify_connection(self) -> bool:
        """
        Verify we have an internet connection after login. Optionally generate a QR code for the WiFi network.
        Returns True if internet is up, else False.
        """
        # Try multiple checks
        if self.check_internet(retries=2, delay=2):
            logging.info("Successfully verified internet connectivity.")
            # Generate a QR code for the first WiFi
            wifi_names = self.config["WiFi"]["wifi_names"].split(",")
            first_wifi = wifi_names[0].strip()
            if first_wifi:
                logging.info(f"Generating QR code for Wi-Fi: {first_wifi}")
                qr = qrcode.QRCode()
                qr.add_data(f"WIFI:T:WPA2;S:{first_wifi};P:{self.config['Credentials']['password']};;")
                qr.make()
                # Print ASCII QR code
                qr.print_ascii(invert=True)
            return True
        else:
            logging.error("No internet access after login attempt.")
            return False

    def display_system_info(self):
        """Display some system info, useful for debugging on Kali."""
        logging.info("System Information:")
        # User
        try:
            user = os.getlogin()
        except Exception:
            user = os.environ.get("USER", "Unknown")
        logging.info(f"User: {user}")

        # OS name
        logging.info(f"OS: {os.name}")

        # Attempt to get uptime, CPU usage, memory usage
        if shutil.which("uptime"):
            try:
                uptime_str = subprocess.check_output(["uptime"]).decode().strip()
                logging.info(f"Uptime: {uptime_str}")
            except Exception:
                logging.warning("Could not retrieve uptime.")
        else:
            logging.warning("`uptime` not installed/found.")

        if shutil.which("top"):
            try:
                top_output = subprocess.check_output(["top", "-bn1"]).decode().splitlines()
                if len(top_output) > 2:
                    logging.info(f"CPU Usage: {top_output[2]}")
            except Exception:
                logging.warning("Could not retrieve CPU usage from top.")
        else:
            logging.warning("`top` not installed/found.")

        if shutil.which("free"):
            try:
                mem_output = subprocess.check_output(["free", "-m"]).decode().splitlines()
                if len(mem_output) > 1:
                    logging.info(f"Memory Usage: {mem_output[1]}")
            except Exception:
                logging.warning("Could not retrieve Memory usage from free.")
        else:
            logging.warning("`free` not installed/found.")

# ==============================
#         MAIN FUNCTION
# ==============================

async def main():
    async with WiFiAutoLogin() as wifi_auto_login:
        wifi_auto_login.display_header()
        wifi_auto_login.display_system_info()

        # Check if user wants to force login
        force_login = wifi_auto_login.config["Advanced"].get("force_login", "false").lower() == "true"

        # If not forcing and we already have internet, exit
        if not force_login and wifi_auto_login.check_internet():
            logging.info("Already connected to the internet and 'force_login' is False. Exiting.")
            return

        # Otherwise, attempt to connect to WiFi
        if wifi_auto_login.connect_to_wifi() or force_login:
            # Then handle captive portal
            if wifi_auto_login.handle_portal_login():
                # Finally verify connectivity
                if wifi_auto_login.verify_connection():
                    logging.info("Script completed successfully!")
                else:
                    logging.error("Connection verification failed.")
            else:
                logging.error("Portal login failed or not accessible.")
        else:
            logging.error("Could not connect to any configured WiFi networks.")

# Entry point
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
