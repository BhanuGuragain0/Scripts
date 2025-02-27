#!/usr/bin/env python3
"""
Professional Python HTTP Server Launcher (Internet-Only)
Shadow@Bhanu Python Server Starting

Features:
- Binds to 0.0.0.0 (Internet-facing) every time.
- Allows specifying port with -p or prompts user if omitted.
- Foreground or background server mode with -b.
- Command-line or interactive usage, robust logging, rotating logs.
- Port validation, usage checks, graceful shutdown on Ctrl+C.
- Ideal for pentesting or quick file sharing over the internet.
"""

import sys
import os
import time
import signal
import subprocess
import argparse
import logging
from logging.handlers import RotatingFileHandler
import socket

from colorama import init, Fore, Style

# ===============================
#   INITIAL SETUP (COLOR + LOGS)
# ===============================
init(autoreset=True)

COLOR_BLUE = Fore.BLUE + Style.BRIGHT
COLOR_RED = Fore.RED + Style.BRIGHT
COLOR_GREEN = Fore.GREEN + Style.BRIGHT
COLOR_YELLOW = Fore.YELLOW + Style.BRIGHT
COLOR_RESET = Style.RESET_ALL

# Create a logs directory automatically if not present
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

MAIN_LOG_FILE = os.path.join(LOG_DIR, "python_http_server.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(MAIN_LOG_FILE, maxBytes=1_000_000, backupCount=3),
        logging.StreamHandler(sys.stdout),
    ],
)
logging.info(f"Logs will be written to: {MAIN_LOG_FILE}")

# ===============================
#      HELPER / UTILITY FUNCS
# ===============================

def get_timestamp() -> str:
    """Return the current timestamp as a string."""
    return time.strftime("%Y-%m-%d %H:%M:%S")

def validate_port(port: int) -> None:
    """
    Raise ValueError if the port is out of [1..65535].
    """
    if port < 1 or port > 65535:
        raise ValueError(f"Port {port} is invalid. Must be between 1 and 65535.")

def port_in_use_ss(port: int) -> bool:
    """
    Check if a port is in use using 'ss -tuln' (Linux).
    Returns True if in use, False otherwise.
    If 'ss' is missing or fails, we do a socket-based fallback.
    """
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True,
            text=True,
            check=True
        )
        return f":{port} " in result.stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return port_in_use_socket(port)

def port_in_use_socket(port: int) -> bool:
    """
    Fallback: try binding to the port. If it fails, it's already in use.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        sock.close()
        return True
    sock.close()
    return False

def stop_server(pid: int) -> None:
    """
    Attempt to gracefully kill the server process.
    """
    logging.info(f"Stopping server (PID={pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    logging.info(f"Server (PID={pid}) stopped successfully.")

# ===============================
#   START HTTP SERVER (MODES)
# ===============================

def start_http_server_foreground(port: int, log_filename: str) -> None:
    """
    Start python -m http.server in the foreground, bound to 0.0.0.0.
    This blocks until the server stops.
    """
    logging.info(
        f"{COLOR_GREEN}[ {get_timestamp()} ] Starting server on port {port}, "
        f"bind=0.0.0.0 (foreground){COLOR_RESET}"
    )
    logging.info(
        f"{COLOR_GREEN}[ {get_timestamp()} ] Output will be logged to {log_filename}{COLOR_RESET}"
    )

    cmd = [
        "python3",
        "-m",
        "http.server",
        str(port),
        "--bind",
        "0.0.0.0"
    ]
    with open(log_filename, "a") as f:
        process = subprocess.Popen(cmd, stdout=f, stderr=f)

    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] Server is running (PID={process.pid}).{COLOR_RESET}")
    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] Logs: {log_filename}{COLOR_RESET}")
    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] Press CTRL+C to stop the server.{COLOR_RESET}")

    # Handle Ctrl+C
    def signal_handler(sig, frame):
        logging.info(f"{COLOR_RED}Received CTRL+C, stopping the server...{COLOR_RESET}")
        stop_server(process.pid)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    process.wait()
    logging.info(f"Server with PID={process.pid} has exited.")

def start_http_server_background(port: int, log_filename: str) -> int:
    """
    Start python -m http.server in the background, bound to 0.0.0.0.
    Returns the PID of the launched process.
    """
    logging.info(
        f"{COLOR_GREEN}[ {get_timestamp()} ] Starting server on port {port}, "
        f"bind=0.0.0.0 (background){COLOR_RESET}"
    )
    logging.info(
        f"{COLOR_GREEN}[ {get_timestamp()} ] Output will be logged to {log_filename}{COLOR_RESET}"
    )

    cmd = [
        "python3",
        "-m",
        "http.server",
        str(port),
        "--bind",
        "0.0.0.0"
    ]
    with open(log_filename, "a") as f:
        process = subprocess.Popen(cmd, stdout=f, stderr=f)

    pid = process.pid
    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] Server is running in background (PID={pid}).{COLOR_RESET}")
    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] Logs: {log_filename}{COLOR_RESET}")
    print(f"{COLOR_YELLOW}[ {get_timestamp()} ] To stop the server, run: kill {pid}{COLOR_RESET}")
    return pid

# ===============================
#             MAIN
# ===============================

def main():
    # Banner
    print(f"{COLOR_BLUE}╔════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_BLUE}║   Shadow@Bhanu Python Server Starting  ║{COLOR_RESET}")
    print(f"{COLOR_BLUE}╚════════════════════════════════════════╝{COLOR_RESET}\n")

    # Arg Parsing
    parser = argparse.ArgumentParser(
        description="Advanced Python HTTP Server Launcher (Internet-Only).",
        add_help=False
    )
    parser.add_argument("-p", "--port", type=int, help="Port number [1..65535].")
    parser.add_argument("-b", "--background", action="store_true", help="Run the server in background mode.")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit.")
    args, unknown = parser.parse_known_args()

    if args.help:
        print(f"{COLOR_YELLOW}Usage: {os.path.basename(sys.argv[0])} -p <port> [-b] [-h]{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  -p, --port         : Specify port number (1..65535).{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  -b, --background   : Run server in background mode.{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  -h, --help         : Show this help message and exit.{COLOR_RESET}")
        sys.exit(0)

    # Prompt user for port if not provided
    port = args.port
    if not port:
        try:
            user_input = input(f"{COLOR_YELLOW}Enter the port number to start the server (default 8080): {COLOR_RESET}")
            if not user_input.strip():
                port = 8080
            else:
                port = int(user_input.strip())
        except ValueError:
            logging.error(f"{COLOR_RED}[ {get_timestamp()} ] Invalid port entered.{COLOR_RESET}")
            sys.exit(1)

    # Validate port
    try:
        validate_port(port)
    except ValueError as ve:
        logging.error(f"{COLOR_RED}[ {get_timestamp()} ] {ve}{COLOR_RESET}")
        sys.exit(1)

    # Check port usage
    if port_in_use_ss(port):
        logging.error(f"{COLOR_RED}[ {get_timestamp()} ] Port {port} is already in use. Choose a different port.{COLOR_RESET}")
        sys.exit(1)

    # Create unique session log file
    unique_log_filename = f"server_{port}_{time.strftime('%Y%m%d-%H%M%S')}.log"
    full_log_path = os.path.join(LOG_DIR, unique_log_filename)

    background_mode = args.background

    if background_mode:
        # Start in background
        pid = start_http_server_background(port, full_log_path)
        sys.exit(0)
    else:
        # Start in foreground
        start_http_server_foreground(port, full_log_path)

if __name__ == "__main__":
    main()
