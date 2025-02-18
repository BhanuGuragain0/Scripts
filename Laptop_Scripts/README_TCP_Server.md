# Secure TCP Server

## Overview
This is a highly secure, SSL/TLS-encrypted TCP server that supports multiple commands and client authentication using bcrypt-hashed passphrases. The server handles various client commands, including text transformations, encryption/decryption, mathematical computations, and session management.

## Features
- **SSL/TLS Encryption:** Ensures secure communication between clients and the server.
- **Client Authentication:** Requires clients to enter a passphrase, which is securely hashed and validated.
- **Command Execution:** Supports multiple built-in commands (see below).
- **AES Encryption & Decryption:** Allows secure data transmission.
- **Session Management:** Tracks session history and statistics.
- **Thread-Safe & Asynchronous:** Utilizes multi-threading and async I/O for efficient performance.
- **Logging & Error Handling:** Implements detailed logging using rotating file handlers.

## Requirements
- Python 3.8+
- Required Libraries:
  - `bcrypt`
  - `socket`
  - `ssl`
  - `asyncio`
  - `logging`
  - `json`
  - `time`
  - `sympy`
  - `pycryptodome`

Install dependencies using:
```sh
pip install bcrypt sympy pycryptodome
```

## Installation & Setup
1. **Clone the Repository:**
   ```sh
   git clone <repository-url>
   cd <repository-folder>
   ```

2. **Generate SSL Certificates:**
   ```sh
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

3. **Run the Server:**
   ```sh
   python3 secure_server.py --port 443 --certfile cert.pem --keyfile key.pem --passphrase "your_secure_passphrase"
   ```

## Usage
### Available Commands
The server supports the following commands:

| Command       | Description |
|--------------|-------------|
| `echo`       | Echoes back the provided input. |
| `upper`      | Converts input to uppercase. |
| `lower`      | Converts input to lowercase. |
| `reverse`    | Reverses the input string. |
| `math`       | Evaluates mathematical expressions safely using `sympy`. |
| `time`       | Returns the current server time. |
| `stats`      | Displays the number of executed commands in the session. |
| `encrypt`    | Encrypts a given string using AES encryption. |
| `decrypt`    | Decrypts an AES-encrypted message. |
| `help`       | Lists all available commands. |
| `clear`      | Clears the session command history. |
| `history`    | Displays the history of executed commands. |
| `quit`       | Terminates the session. |

### Example Client Interaction
```sh
$ nc <server-ip> <port>
Enter passphrase:
> your_secure_passphrase
Passphrase accepted. Welcome!
> echo Hello, Secure World!
Hello, Secure World!
> upper security
SECURITY
> math 2+3*5
17
> encrypt "Sensitive Data"
{"key": "<encrypted-key>", "iv": "<initialization-vector>", "ciphertext": "<encrypted-text>"}
> quit
Goodbye!
```

## Security Considerations
- **Passphrase Hashing:** The passphrase is securely hashed using `bcrypt` before authentication.
- **SSL/TLS Encryption:** Ensures that all communication is encrypted.
- **Logging & Monitoring:** Logs all connection attempts and commands for auditing.
- **Thread-Safe Execution:** Uses a thread pool executor to handle multiple clients efficiently.
- **Safe Math Evaluation:** Prevents code injection by using `sympy` for safe expression parsing.

## Troubleshooting
### Common Issues & Solutions
| Issue | Solution |
|--------|------------|
| **SSL certificate error** | Ensure that the `cert.pem` and `key.pem` are correctly generated and accessible. |
| **Connection refused** | Verify that the server is running on the correct port and the firewall allows connections. |
| **Invalid passphrase** | Ensure that the passphrase entered matches the one set during server startup. |
| **Command not recognized** | Type `help` to view available commands. |

## License
This project is licensed under the MIT License.

## Contributors
- **Bhanu Guragain (Shadow Junior😈)**

