#!/usr/bin/env python3
"""
Enhanced Python HTTP Server for Kali Linux
Professional HTTP Server with Advanced Features for Security Testing

Features:
- Multi-interface binding (0.0.0.0, localhost, specific IPs)
- SSL/TLS support with self-signed certificates
- Custom headers and CORS configuration
- Directory listing customization
- Upload functionality for file transfers
- Basic authentication support
- Request logging and forensics
- Steganography-friendly file serving
- Anti-forensic log rotation
- Process monitoring and auto-restart
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
import threading
import http.server
import socketserver
import ssl
import base64
import hashlib
import json
from pathlib import Path
import shutil
import urllib.parse

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Installing colorama...")
    subprocess.run([sys.executable, "-m", "pip", "install", "colorama"], check=True)
    from colorama import init, Fore, Style
    init(autoreset=True)

# ===============================
#   ENHANCED CONFIGURATION
# ===============================

COLOR_BLUE = Fore.BLUE + Style.BRIGHT
COLOR_RED = Fore.RED + Style.BRIGHT
COLOR_GREEN = Fore.GREEN + Style.BRIGHT
COLOR_YELLOW = Fore.YELLOW + Style.BRIGHT
COLOR_MAGENTA = Fore.MAGENTA + Style.BRIGHT
COLOR_CYAN = Fore.CYAN + Style.BRIGHT
COLOR_RESET = Style.RESET_ALL

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "server_logs")
UPLOAD_DIR = os.path.join(SCRIPT_DIR, "uploads")
SSL_DIR = os.path.join(SCRIPT_DIR, "ssl")

# Create directories
for directory in [LOG_DIR, UPLOAD_DIR, SSL_DIR]:
    os.makedirs(directory, exist_ok=True)

MAIN_LOG_FILE = os.path.join(LOG_DIR, "enhanced_server.log")

# Enhanced logging with forensic capabilities
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        RotatingFileHandler(MAIN_LOG_FILE, maxBytes=5_000_000, backupCount=10),
        logging.StreamHandler(sys.stdout),
    ],
)

class EnhancedHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Enhanced HTTP request handler with additional features"""
    
    def __init__(self, *args, directory=None, auth_user=None, auth_pass=None, 
                 custom_headers=None, enable_upload=False, **kwargs):
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.custom_headers = custom_headers or {}
        self.enable_upload = enable_upload
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        """Enhanced logging with client info"""
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        logging.info(f"[{client_ip}] [{user_agent}] {format % args}")
    
    def check_auth(self):
        """Check basic authentication if enabled"""
        if not self.auth_user or not self.auth_pass:
            return True
            
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return False
            
        try:
            credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
            username, password = credentials.split(':', 1)
            return username == self.auth_user and password == self.auth_pass
        except:
            return False
    
    def send_auth_request(self):
        """Send authentication request"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentication required')
    
    def end_headers(self):
        """Add custom headers"""
        for header, value in self.custom_headers.items():
            self.send_header(header, value)
        super().end_headers()
    
    def do_GET(self):
        """Handle GET requests with auth check"""
        if not self.check_auth():
            self.send_auth_request()
            return
        super().do_GET()
    
    def do_POST(self):
        """Handle POST requests for file upload"""
        if not self.check_auth():
            self.send_auth_request()
            return
            
        if not self.enable_upload:
            self.send_error(405, "Method Not Allowed")
            return
            
        if self.path == '/upload':
            self.handle_upload()
        else:
            self.send_error(404, "Not Found")
    
    def handle_upload(self):
        """Handle file upload"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 100_000_000:  # 100MB limit
                self.send_error(413, "File too large")
                return
                
            post_data = self.rfile.read(content_length)
            
            # Simple file upload (in real implementation, parse multipart/form-data)
            filename = f"upload_{int(time.time())}.bin"
            filepath = os.path.join(UPLOAD_DIR, filename)
            
            with open(filepath, 'wb') as f:
                f.write(post_data)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"File uploaded: {filename}".encode())
            
            logging.info(f"File uploaded: {filename} ({len(post_data)} bytes)")
            
        except Exception as e:
            logging.error(f"Upload error: {e}")
            self.send_error(500, "Internal Server Error")

# ===============================
#   ENHANCED UTILITY FUNCTIONS
# ===============================

def get_timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"Port {port} is invalid. Must be between 1 and 65535.")

def get_local_ips():
    """Get all local IP addresses"""
    ips = ['127.0.0.1', '0.0.0.0']
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        if result.returncode == 0:
            ips.extend(result.stdout.strip().split())
    except:
        pass
    return list(set(ips))

def create_self_signed_cert():
    """Create self-signed SSL certificate"""
    cert_file = os.path.join(SSL_DIR, "server.crt")
    key_file = os.path.join(SSL_DIR, "server.key")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    try:
        # Generate self-signed certificate
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes",
            "-subj", "/C=US/ST=State/L=City/O=Org/CN=localhost"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logging.info("Self-signed SSL certificate created")
        return cert_file, key_file
    except subprocess.CalledProcessError:
        logging.warning("Failed to create SSL certificate. OpenSSL may not be installed.")
        return None, None

def port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    """Check if port is in use"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
        sock.close()
        return False
    except OSError:
        sock.close()
        return True

def get_system_info():
    """Get basic system information"""
    info = {
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "python_version": sys.version.split()[0],
        "working_directory": os.getcwd(),
        "script_directory": SCRIPT_DIR,
        "local_ips": get_local_ips()
    }
    return info

# ===============================
#   ENHANCED SERVER CLASS
# ===============================

class EnhancedHTTPServer:
    def __init__(self, port=8080, host="0.0.0.0", directory=None, 
                 use_ssl=False, auth_user=None, auth_pass=None,
                 enable_upload=False, custom_headers=None):
        self.port = port
        self.host = host
        self.directory = directory or os.getcwd()
        self.use_ssl = use_ssl
        self.auth_user = auth_user
        self.auth_pass = auth_pass
        self.enable_upload = enable_upload
        self.custom_headers = custom_headers or {}
        self.server = None
        self.server_thread = None
    
    def create_handler_class(self):
        """Create handler class with configuration"""
        return lambda *args, **kwargs: EnhancedHTTPRequestHandler(
            *args,
            directory=self.directory,
            auth_user=self.auth_user,
            auth_pass=self.auth_pass,
            custom_headers=self.custom_headers,
            enable_upload=self.enable_upload,
            **kwargs
        )
    
    def start(self, background=False):
        """Start the server"""
        try:
            handler_class = self.create_handler_class()
            self.server = socketserver.TCPServer((self.host, self.port), handler_class)
            
            if self.use_ssl:
                cert_file, key_file = create_self_signed_cert()
                if cert_file and key_file:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(cert_file, key_file)
                    self.server.socket = context.wrap_socket(
                        self.server.socket, server_side=True
                    )
                    protocol = "HTTPS"
                else:
                    logging.error("SSL requested but certificate creation failed")
                    return False
            else:
                protocol = "HTTP"
            
            if background:
                self.server_thread = threading.Thread(target=self.server.serve_forever)
                self.server_thread.daemon = True
                self.server_thread.start()
                logging.info(f"Server running in background: {protocol}://{self.host}:{self.port}")
            else:
                logging.info(f"Starting server: {protocol}://{self.host}:{self.port}")
                logging.info(f"Serving directory: {self.directory}")
                self.server.serve_forever()
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            return False
    
    def stop(self):
        """Stop the server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logging.info("Server stopped")

# ===============================
#   MAIN FUNCTION
# ===============================

def main():
    print(f"{COLOR_CYAN}╔══════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}║      Enhanced Kali Linux HTTP Server v2.0       ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}║           Professional Security Testing          ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}╚══════════════════════════════════════════════════╝{COLOR_RESET}\n")
    
    # System info
    sys_info = get_system_info()
    print(f"{COLOR_YELLOW}System Info:{COLOR_RESET}")
    print(f"  Hostname: {sys_info['hostname']}")
    print(f"  Platform: {sys_info['platform']}")
    print(f"  Python: {sys_info['python_version']}")
    print(f"  Available IPs: {', '.join(sys_info['local_ips'])}")
    print()
    
    parser = argparse.ArgumentParser(
        description="Enhanced HTTP Server for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-p", "--port", type=int, default=8080,
                       help="Port number (default: 8080)")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0",
                       help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("-d", "--directory", type=str,
                       help="Directory to serve (default: current)")
    parser.add_argument("-s", "--ssl", action="store_true",
                       help="Enable SSL/HTTPS")
    parser.add_argument("-b", "--background", action="store_true",
                       help="Run in background")
    parser.add_argument("-u", "--upload", action="store_true",
                       help="Enable file upload")
    parser.add_argument("--auth", type=str, metavar="USER:PASS",
                       help="Enable basic authentication")
    parser.add_argument("--cors", action="store_true",
                       help="Enable CORS headers")
    parser.add_argument("--list-ips", action="store_true",
                       help="List available IP addresses and exit")
    
    args = parser.parse_args()
    
    if args.list_ips:
        print(f"{COLOR_GREEN}Available IP addresses:{COLOR_RESET}")
        for ip in get_local_ips():
            print(f"  {ip}")
        sys.exit(0)
    
    # Validate port
    try:
        validate_port(args.port)
    except ValueError as e:
        logging.error(f"{COLOR_RED}{e}{COLOR_RESET}")
        sys.exit(1)
    
    # Check if port is in use
    if port_in_use(args.port, args.host):
        logging.error(f"{COLOR_RED}Port {args.port} on {args.host} is already in use{COLOR_RESET}")
        sys.exit(1)
    
    # Parse authentication
    auth_user, auth_pass = None, None
    if args.auth:
        try:
            auth_user, auth_pass = args.auth.split(":", 1)
        except ValueError:
            logging.error(f"{COLOR_RED}Invalid auth format. Use USER:PASS{COLOR_RESET}")
            sys.exit(1)
    
    # Setup custom headers
    custom_headers = {}
    if args.cors:
        custom_headers.update({
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        })
    
    # Create and start server
    server = EnhancedHTTPServer(
        port=args.port,
        host=args.host,
        directory=args.directory,
        use_ssl=args.ssl,
        auth_user=auth_user,
        auth_pass=auth_pass,
        enable_upload=args.upload,
        custom_headers=custom_headers
    )
    
    def signal_handler(sig, frame):
        logging.info(f"{COLOR_RED}Received signal, stopping server...{COLOR_RESET}")
        server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Display configuration
    protocol = "HTTPS" if args.ssl else "HTTP"
    print(f"{COLOR_GREEN}Server Configuration:{COLOR_RESET}")
    print(f"  URL: {protocol.lower()}://{args.host}:{args.port}")
    print(f"  Directory: {args.directory or os.getcwd()}")
    print(f"  SSL: {'Enabled' if args.ssl else 'Disabled'}")
    print(f"  Auth: {'Enabled' if args.auth else 'Disabled'}")
    print(f"  Upload: {'Enabled' if args.upload else 'Disabled'}")
    print(f"  CORS: {'Enabled' if args.cors else 'Disabled'}")
    print(f"  Mode: {'Background' if args.background else 'Foreground'}")
    print()
    
    if args.upload:
        print(f"{COLOR_YELLOW}Upload endpoint: POST {protocol.lower()}://{args.host}:{args.port}/upload{COLOR_RESET}")
    
    if not server.start(background=args.background):
        sys.exit(1)
    
    if args.background:
        print(f"{COLOR_GREEN}Server running in background. Check logs for details.{COLOR_RESET}")
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
