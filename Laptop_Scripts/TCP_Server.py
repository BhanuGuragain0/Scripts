#!/usr/bin/env python3
import argparse
import socket
import ssl
import asyncio
import logging
import bcrypt
import json
import time
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from sympy import sympify, SympifyError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configure logging
logger = logging.getLogger("SecureServer")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("server.log", maxBytes=5 * 1024 * 1024, backupCount=2)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Command function definitions
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
    return f"Commands executed: {len(session.get('commands', []))}"

def cmd_encrypt(args, session):
    """Encrypt the provided input using AES."""
    return SecureServer.encrypt_data(args)

def cmd_decrypt(args, session):
    """Decrypt the provided input using AES."""
    return SecureServer.decrypt_data(args)

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
    return "\n".join(history) if history else "No history available."

# Mapping of commands to functions
COMMANDS = {
    "echo": cmd_echo,
    "upper": cmd_upper,
    "lower": cmd_lower,
    "reverse": cmd_reverse,
    "math": cmd_math,
    "time": cmd_time,
    "stats": cmd_stats,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "help": cmd_help,
    "clear": cmd_clear,
    "history": cmd_history,
}


class SecureServer:
    """
    A secure TCP server that handles client connections using SSL and provides various commands.
    """
    def __init__(self, port, certfile, keyfile, max_workers=10, passphrase_hash=None):
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_context = self.create_ssl_context()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.passphrase_hash = passphrase_hash
        self.sessions = {}  # Track client sessions

    def create_ssl_context(self):
        """
        Create and configure the SSL context.
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        return context

    @staticmethod
    def encrypt_data(data):
        """
        Encrypt data using AES.
        """
        try:
            key = get_random_bytes(16)  # 128-bit key
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
            return json.dumps({"key": key.hex(), "iv": cipher.iv.hex(), "ciphertext": ct_bytes.hex()})
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return json.dumps({"error": f"Encryption failed: {e}"})

    @staticmethod
    def decrypt_data(data):
        """
        Decrypt data using AES.
        """
        try:
            data_dict = json.loads(data)
            key = bytes.fromhex(data_dict["key"])
            iv = bytes.fromhex(data_dict["iv"])
            ciphertext = bytes.fromhex(data_dict["ciphertext"])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return pt.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return f"Decryption failed: {e}"

    async def handle_client(self, ssl_socket, client_address):
        """
        Handle a client connection.
        """
        logger.info(f"Connected to {client_address}")
        session = {"commands": [], "start_time": time.time()}
        self.sessions[client_address] = session
        try:
            await self.send_message(ssl_socket, "Enter passphrase:")
            passphrase = await self.receive_message(ssl_socket)
            if passphrase is None or not bcrypt.checkpw(passphrase.encode(), self.passphrase_hash):
                await self.send_message(ssl_socket, "Invalid passphrase. Connection will be closed.")
                logger.warning(f"Invalid passphrase attempt from {client_address}")
                return

            await self.send_message(ssl_socket, "Passphrase accepted. Welcome!")

            while True:
                await self.send_message(ssl_socket, "Enter command (or type 'quit' to exit):")
                command_data = await self.receive_message(ssl_socket)
                if command_data is None:
                    break

                if command_data.strip().lower() == "quit":
                    await self.send_message(ssl_socket, "Goodbye!")
                    break

                response = self.process_command(command_data, session)
                await self.send_message(ssl_socket, response)
        except asyncio.TimeoutError:
            logger.warning(f"Client {client_address} timed out.")
            await self.send_message(ssl_socket, "Connection timed out. Goodbye!")
        except Exception as e:
            logger.exception(f"Error handling client {client_address}: {e}")
        finally:
            try:
                ssl_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            ssl_socket.close()
            self.sessions.pop(client_address, None)
            logger.info(f"Connection closed for {client_address}")

    async def send_message(self, ssl_socket, message):
        """
        Send a message to the client.
        """
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(self.executor, ssl_socket.sendall, (message + "\n").encode())
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    async def receive_message(self, ssl_socket, buffer_size=1024, timeout=60):
        """
        Receive a message from the client.
        """
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
        """
        Process a client command.
        """
        try:
            if not data.strip():
                return json.dumps({"error": "Empty command received."})
            parts = data.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            if command in COMMANDS:
                # Record the command in session history
                session.setdefault("commands", []).append(data)
                result = COMMANDS[command](args, session)
                return json.dumps({"result": result})
            else:
                return json.dumps({"error": f"Unknown command: {command}. Type 'help' for available commands."})
        except Exception as e:
            logger.exception("Error processing command")
            return json.dumps({"error": f"Error processing command: {e}"})

    async def start_server(self):
        """
        Start the server and listen for client connections.
        """
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("::", self.port))
        server_socket.listen(5)
        logger.info(f"Server listening on port {self.port}...")

        loop = asyncio.get_running_loop()
        try:
            while True:
                client_socket, client_address = await loop.run_in_executor(self.executor, server_socket.accept)
                try:
                    ssl_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    asyncio.create_task(self.handle_client(ssl_socket, client_address))
                except ssl.SSLError as e:
                    logger.error(f"SSL error with client {client_address}: {e}")
                    client_socket.close()
        except KeyboardInterrupt:
            logger.info("Server shutdown initiated...")
        except Exception as e:
            logger.exception(f"Server encountered an error: {e}")
        finally:
            server_socket.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure TCP Server")
    parser.add_argument("--port", required=True, type=int, help="Port number to listen on")
    parser.add_argument("--certfile", required=True, help="Path to SSL certificate file")
    parser.add_argument("--keyfile", required=True, help="Path to SSL private key file")
    parser.add_argument("--passphrase", required=True, help="Server passphrase for client authentication")
    args = parser.parse_args()

    # Hash the passphrase for secure comparison
    hashed_passphrase = bcrypt.hashpw(args.passphrase.encode(), bcrypt.gensalt())

    server = SecureServer(args.port, args.certfile, args.keyfile, passphrase_hash=hashed_passphrase)
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by KeyboardInterrupt.")
    except Exception as e:
        logger.exception(f"Unexpected server error: {e}")
