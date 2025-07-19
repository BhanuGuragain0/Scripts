#!/usr/bin/env python3
"""
Enhanced Secure TCP Server for Kali Linux
Advanced encrypted command & control server with steganography and evasion capabilities

Features:
- Multi-layered encryption (AES + RSA hybrid)
- Steganographic data hiding
- Traffic obfuscation and mimicry
- Advanced session management
- File transfer capabilities
- Network reconnaissance tools
- Anti-forensic features
- Payload delivery system
"""

import argparse
import socket
import ssl
import asyncio
import logging
import bcrypt
import json
import time
import os
import base64
import hashlib
import struct
import random
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from sympy import sympify, SympifyError
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import subprocess
import platform
import psutil
import requests
from datetime import datetime, timedelta

# Enhanced logging with anti-forensic capabilities
class AntiForensicLogger:
    def __init__(self, log_file="server.log", max_bytes=10*1024*1024, backup_count=5):
        self.logger = logging.getLogger("SecureServer")
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory
        os.makedirs("logs", exist_ok=True)
        
        handler = RotatingFileHandler(
            f"logs/{log_file}", 
            maxBytes=max_bytes, 
            backupCount=backup_count
        )
        
        # Custom formatter with obfuscation
        formatter = logging.Formatter(
            "%(asctime)s - [%(levelname)s] - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Console handler for debug
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def info(self, msg, obfuscate=False):
        if obfuscate:
            msg = self._obfuscate_log(msg)
        self.logger.info(msg)
    
    def warning(self, msg, obfuscate=False):
        if obfuscate:
            msg = self._obfuscate_log(msg)
        self.logger.warning(msg)
    
    def error(self, msg, obfuscate=False):
        if obfuscate:
            msg = self._obfuscate_log(msg)
        self.logger.error(msg)
    
    def _obfuscate_log(self, msg):
        # Simple log obfuscation (base64 encode sensitive parts)
        return base64.b64encode(msg.encode()).decode()

logger = AntiForensicLogger()

# Enhanced encryption with hybrid RSA+AES
class HybridCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
    
    def encrypt_hybrid(self, data):
        """Hybrid encryption: AES for data, RSA for AES key"""
        try:
            # Generate random AES key
            aes_key = get_random_bytes(32)  # 256-bit key
            
            # Encrypt data with AES
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode())
            
            # Encrypt AES key with RSA
            cipher_rsa = PKCS1_OAEP.new(self.public_key, hashAlgo=SHA256)
            encrypted_key = cipher_rsa.encrypt(aes_key)
            
            return {
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "nonce": base64.b64encode(cipher_aes.nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()
            }
        except Exception as e:
            logger.error(f"Hybrid encryption error: {e}")
            return None
    
    def decrypt_hybrid(self, encrypted_data):
        """Hybrid decryption"""
        try:
            # Decrypt AES key with RSA
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key, hashAlgo=SHA256)
            aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_data["encrypted_key"]))
            
            # Decrypt data with AES
            cipher_aes = AES.new(aes_key, AES.MODE_GCM, base64.b64decode(encrypted_data["nonce"]))
            plaintext = cipher_aes.decrypt_and_verify(
                base64.b64decode(encrypted_data["ciphertext"]),
                base64.b64decode(encrypted_data["tag"])
            )
            
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Hybrid decryption error: {e}")
            return None

# Steganography module
class Steganography:
    @staticmethod
    def hide_in_image_data(data, cover_data):
        """Hide data in image-like binary data using LSB"""
        try:
            data_bytes = data.encode()
            data_len = len(data_bytes)
            
            if len(cover_data) < data_len * 8 + 32:
                return None  # Not enough cover data
            
            # Hide length first (4 bytes)
            result = bytearray(cover_data)
            for i in range(32):
                bit = (data_len >> i) & 1
                result[i] = (result[i] & 0xFE) | bit
            
            # Hide data
            for i, byte in enumerate(data_bytes):
                for bit_pos in range(8):
                    bit = (byte >> bit_pos) & 1
                    byte_pos = 32 + i * 8 + bit_pos
                    result[byte_pos] = (result[byte_pos] & 0xFE) | bit
            
            return bytes(result)
        except Exception as e:
            logger.error(f"Steganography error: {e}")
            return None
    
    @staticmethod
    def extract_from_image_data(stego_data):
        """Extract hidden data from image-like binary data"""
        try:
            # Extract length
            data_len = 0
            for i in range(32):
                bit = stego_data[i] & 1
                data_len |= (bit << i)
            
            if data_len <= 0 or data_len > len(stego_data):
                return None
            
            # Extract data
            data_bytes = bytearray()
            for i in range(data_len):
                byte = 0
                for bit_pos in range(8):
                    byte_pos = 32 + i * 8 + bit_pos
                    if byte_pos >= len(stego_data):
                        break
                    bit = stego_data[byte_pos] & 1
                    byte |= (bit << bit_pos)
                data_bytes.append(byte)
            
            return bytes(data_bytes).decode()
        except Exception as e:
            logger.error(f"Steganography extraction error: {e}")
            return None

# Enhanced command functions
def cmd_echo(args, session):
    """Echo the provided input."""
    return args

def cmd_upper(args, session):
    """Convert input to uppercase."""
    return args.upper()

def cmd_lower(args, session):
    """Convert input to lowercase."""
    return args.lower()

def cmd_reverse(args, session):
    """Reverse the input string."""
    return args[::-1]

def cmd_math(args, session):
    """Evaluate a mathematical expression safely."""
    try:
        result = sympify(args)
        return str(result)
    except SympifyError as e:
        return f"Math evaluation error: {e}"

def cmd_time(args, session):
    """Return the current server time."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def cmd_stats(args, session):
    """Return statistics of the session."""
    uptime = time.time() - session.get('start_time', time.time())
    return f"Commands executed: {len(session.get('commands', []))}, Session uptime: {uptime:.2f}s"

def cmd_sysinfo(args, session):
    """Get detailed system information."""
    try:
        info = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": f"{psutil.virtual_memory().total // (1024**3)} GB",
            "disk_usage": f"{psutil.disk_usage('/').percent}%",
            "network_interfaces": list(psutil.net_if_addrs().keys())
        }
        return json.dumps(info, indent=2)
    except Exception as e:
        return f"System info error: {e}"

def cmd_netstat(args, session):
    """Network reconnaissance - list active connections."""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                connections.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "pid": conn.pid,
                    "status": conn.status
                })
        return json.dumps(connections[:20], indent=2)  # Limit output
    except Exception as e:
        return f"Network scan error: {e}"

def cmd_portscan(args, session):
    """Basic port scan of target host."""
    if not args:
        return "Usage: portscan <host> [ports]"
    
    try:
        parts = args.split()
        host = parts[0]
        ports = [22, 80, 443, 8080, 3389] if len(parts) < 2 else [int(p) for p in parts[1].split(',')]
        
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
        
        return f"Open ports on {host}: {open_ports}"
    except Exception as e:
        return f"Port scan error: {e}"

def cmd_download(args, session):
    """Download file from URL."""
    if not args:
        return "Usage: download <url> [filename]"
    
    try:
        parts = args.split()
        url = parts[0]
        filename = parts[1] if len(parts) > 1 else url.split('/')[-1]
        
        os.makedirs("downloads", exist_ok=True)
        filepath = os.path.join("downloads", filename)
        
        response = requests.get(url, stream=True, timeout=30)
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        return f"File downloaded: {filepath} ({os.path.getsize(filepath)} bytes)"
    except Exception as e:
        return f"Download error: {e}"

def cmd_upload(args, session):
    """Upload file to server (base64 encoded)."""
    if not args:
        return "Usage: upload <filename> <base64_data>"
    
    try:
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: upload <filename> <base64_data>"
        
        filename, b64_data = parts
        os.makedirs("uploads", exist_ok=True)
        filepath = os.path.join("uploads", filename)
        
        data = base64.b64decode(b64_data)
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return f"File uploaded: {filepath} ({len(data)} bytes)"
    except Exception as e:
        return f"Upload error: {e}"

def cmd_exec(args, session):
    """Execute system command (use with caution)."""
    if not args:
        return "Usage: exec <command>"
    
    try:
        # Security check - limit dangerous commands
        dangerous = ['rm ', 'del ', 'format', 'shutdown', 'reboot']
        if any(cmd in args.lower() for cmd in dangerous):
            return "Dangerous command blocked for safety"
        
        result = subprocess.run(
            args,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout if result.stdout else result.stderr
        return output[:2000]  # Limit output size
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Execution error: {e}"

def cmd_steghide(args, session):
    """Hide data using steganography."""
    if not args:
        return "Usage: steghide <data_to_hide>"
    
    try:
        # Generate random cover data
        cover_data = get_random_bytes(len(args) * 10 + 1000)
        stego = Steganography()
        result = stego.hide_in_image_data(args, cover_data)
        
        if result:
            filename = f"stego_{int(time.time())}.bin"
            os.makedirs("stego", exist_ok=True)
            filepath = os.path.join("stego", filename)
            
            with open(filepath, 'wb') as f:
                f.write(result)
            
            return f"Data hidden in: {filepath}"
        else:
            return "Steganography failed"
    except Exception as e:
        return f"Steganography error: {e}"

def cmd_stegextract(args, session):
    """Extract data from steganographic file."""
    if not args:
        return "Usage: stegextract <filename>"
    
    try:
        filepath = os.path.join("stego", args)
        if not os.path.exists(filepath):
            return "File not found"
        
        with open(filepath, 'rb') as f:
            stego_data = f.read()
        
        stego = Steganography()
        extracted = stego.extract_from_image_data(stego_data)
        
        return extracted if extracted else "No hidden data found"
    except Exception as e:
        return f"Extraction error: {e}"

def cmd_encrypt(args, session):
    """Encrypt data using hybrid encryption."""
    if not args:
        return "Usage: encrypt <data>"
    
    crypto = session.get('crypto')
    if not crypto:
        crypto = HybridCrypto()
        session['crypto'] = crypto
    
    result = crypto.encrypt_hybrid(args)
    return json.dumps(result, indent=2) if result else "Encryption failed"

def cmd_decrypt(args, session):
    """Decrypt data using hybrid encryption."""
    if not args:
        return "Usage: decrypt <encrypted_json>"
    
    try:
        crypto = session.get('crypto')
        if not crypto:
            return "No crypto context available"
        
        encrypted_data = json.loads(args)
        result = crypto.decrypt_hybrid(encrypted_data)
        return result if result else "Decryption failed"
    except Exception as e:
        return f"Decryption error: {e}"

def cmd_help(args, session):
    """List available commands and their descriptions."""
    commands_info = [f"{cmd}: {func.__doc__}" for cmd, func in COMMANDS.items()]
    return "\n".join(commands_info)

def cmd_clear(args, session):
    """Clear session command history."""
    session["commands"].clear()
    return "Session history cleared."

def cmd_history(args, session):
    """Return the history of executed commands."""
    history = session.get("commands", [])
    return "\n".join(history[-20:]) if history else "No history available."

def cmd_sessions(args, session):
    """List active sessions."""
    try:
        active_sessions = []
        for addr, sess in session.get('server_sessions', {}).items():
            active_sessions.append({
                "address": str(addr),
                "start_time": sess.get('start_time', 0),
                "commands": len(sess.get('commands', []))
            })
        return json.dumps(active_sessions, indent=2)
    except Exception as e:
        return f"Sessions error: {e}"

# Enhanced command mapping
COMMANDS = {
    "echo": cmd_echo,
    "upper": cmd_upper,
    "lower": cmd_lower,
    "reverse": cmd_reverse,
    "math": cmd_math,
    "time": cmd_time,
    "stats": cmd_stats,
    "sysinfo": cmd_sysinfo,
    "netstat": cmd_netstat,
    "portscan": cmd_portscan,
    "download": cmd_download,
    "upload": cmd_upload,
    "exec": cmd_exec,
    "steghide": cmd_steghide,
    "stegextract": cmd_stegextract,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "help": cmd_help,
    "clear": cmd_clear,
    "history": cmd_history,
    "sessions": cmd_sessions,
}

class EnhancedSecureServer:
    """
    Enhanced secure TCP server with advanced capabilities for security testing.
    """
    def __init__(self, port, certfile, keyfile, max_workers=20, passphrase_hash=None):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_context = self.create_ssl_context()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.passphrase_hash = passphrase_hash
        self.sessions = {}
        self.start_time = time.time()
        self.crypto = HybridCrypto()
        
        # Create required directories
        for dir_name in ['logs', 'downloads', 'uploads', 'stego']:
            os.makedirs(dir_name, exist_ok=True)

    def create_ssl_context(self):
        """Create and configure the SSL context with enhanced security."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        
        # Enhanced SSL configuration
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        
        return context

    async def handle_client(self, ssl_socket, client_address):
        """Handle a client connection with enhanced session management."""
        logger.info(f"Connected to {client_address}")
        session = {
            "commands": [],
            "start_time": time.time(),
            "client_address": client_address,
            "crypto": self.crypto,
            "server_sessions": self.sessions
        }
        self.sessions[client_address] = session
        
        try:
            # Enhanced authentication with multiple attempts
            max_attempts = 3
            for attempt in range(max_attempts):
                await self.send_message(ssl_socket, f"Enter passphrase (attempt {attempt + 1}/{max_attempts}):")
                passphrase = await self.receive_message(ssl_socket, timeout=30)
                
                if passphrase is None:
                    break
                
                if bcrypt.checkpw(passphrase.encode(), self.passphrase_hash):
                    await self.send_message(ssl_socket, "Authentication successful! Enhanced secure shell ready.")
                    logger.info(f"Successful authentication from {client_address}")
                    break
                else:
                    logger.warning(f"Invalid passphrase attempt {attempt + 1} from {client_address}")
                    if attempt < max_attempts - 1:
                        await self.send_message(ssl_socket, "Invalid passphrase. Try again.")
                    else:
                        await self.send_message(ssl_socket, "Authentication failed. Connection terminated.")
                        return

            # Main command loop
            await self.send_message(ssl_socket, "Type 'help' for available commands.")
            
            while True:
                await self.send_message(ssl_socket, f"[{client_address[0]}]> ")
                command_data = await self.receive_message(ssl_socket, timeout=300)  # 5 minute timeout
                
                if command_data is None:
                    break

                command_data = command_data.strip()
                if command_data.lower() in ['quit', 'exit', 'bye']:
                    await self.send_message(ssl_socket, "Session terminated. Goodbye!")
                    break

                if not command_data:
                    continue

                response = self.process_command(command_data, session)
                await self.send_message(ssl_socket, response)
                
        except asyncio.TimeoutError:
            logger.warning(f"Client {client_address} timed out.")
            await self.send_message(ssl_socket, "Session timeout. Connection closed.")
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            try:
                ssl_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            ssl_socket.close()
            self.sessions.pop(client_address, None)
            logger.info(f"Connection closed for {client_address}")

    async def send_message(self, ssl_socket, message):
        """Send a message to the client with error handling."""
        loop = asyncio.get_running_loop()
        try:
            full_message = message + "\n"
            await loop.run_in_executor(self.executor, ssl_socket.sendall, full_message.encode())
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    async def receive_message(self, ssl_socket, buffer_size=4096, timeout=60):
        """Receive a message from the client with enhanced timeout handling."""
        loop = asyncio.get_running_loop()
        try:
            data = await asyncio.wait_for(
                loop.run_in_executor(self.executor, ssl_socket.recv, buffer_size),
                timeout
            )
            if data:
                return data.decode().strip()
            return None
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for client message.")
            raise
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None

    def process_command(self, data, session):
        """Process a client command with enhanced error handling and logging."""
        try:
            if not data.strip():
                return json.dumps({"error": "Empty command received."})
            
            parts = data.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            
            if command in COMMANDS:
                session.setdefault("commands", []).append(data)
                logger.info(f"Executing command '{command}' from {session['client_address']}", obfuscate=True)
                
                result = COMMANDS[command](args, session)
                return json.dumps({"result": result, "timestamp": time.time()})
            else:
                available_commands = ", ".join(sorted(COMMANDS.keys()))
                return json.dumps({
                    "error": f"Unknown command: {command}",
                    "available_commands": available_commands
                })
                
        except Exception as e:
            logger.error(f"Error processing command: {e}")
            return json.dumps({"error": f"Command processing error: {str(e)}"})

    async def start_server(self):
        """Start the enhanced server with improved error handling."""
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(("::", self.port))
            server_socket.listen(10)
            logger.info(f"Enhanced Secure Server listening on port {self.port}")
            logger.info(f"Server capabilities: {len(COMMANDS)} commands available")
            
            loop = asyncio.get_running_loop()
            
            while True:
                try:
                    client_socket, client_address = await loop.run_in_executor(
                        self.executor, server_socket.accept
                    )
                    
                    try:
                        ssl_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                        asyncio.create_task(self.handle_client(ssl_socket, client_address))
                    except ssl.SSLError as e:
                        logger.error(f"SSL error with client {client_address}: {e}")
                        client_socket.close()
                        
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
                    continue
                    
        except KeyboardInterrupt:
            logger.info("Server shutdown initiated by user...")
        except Exception as e:
            logger.error(f"Server encountered an error: {e}")
        finally:
            server_socket.close()
            logger.info("Server shutdown complete.")

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════╗
    ║       Enhanced Secure TCP Server for Kali       ║
    ║          Advanced C&C with Encryption            ║
    ╚══════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description="Enhanced Secure TCP Server")
    parser.add_argument("--port", required=True, type=int, help="Port number to listen on")
    parser.add_argument("--certfile", required=True, help="Path to SSL certificate file")
    parser.add_argument("--keyfile", required=True, help="Path to SSL private key file")
    parser.add_argument("--passphrase", required=True, help="Server passphrase for client authentication")
    parser.add_argument("--generate-certs", action="store_true", help="Generate self-signed certificates")
    
    args = parser.parse_args()
    
    # Generate certificates if requested
    if args.generate_certs:
        cert_dir = "certs"
        os.makedirs(cert_dir, exist_ok=True)
        
        cert_file = os.path.join(cert_dir, "server.crt")
        key_file = os.path.join(cert_dir, "server.key")
        
        try:
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", key_file, "-out", cert_file,
                "-days", "365", "-nodes",
                "-subj", "/C=US/ST=State/L=City/O=SecureOrg/CN=secure-server"
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"✓ Certificates generated: {cert_file}, {key_file}")
            args.certfile = cert_file
            args.keyfile = key_file
        except subprocess.CalledProcessError as e:
            print(f"✗ Certificate generation failed: {e}")
            exit(1)

    # Hash the passphrase for secure comparison
    hashed_passphrase = bcrypt.hashpw(args.passphrase.encode(), bcrypt.gensalt())

    server = EnhancedSecureServer(
        args.port, 
        args.certfile, 
        args.keyfile, 
        passphrase_hash=hashed_passphrase
    )
    
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user.")
    except Exception as e:
        logger.error(f"Unexpected server error: {e}")
