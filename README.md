# 🛠️ Scripts Collection

A comprehensive collection of security scripts, CTF solvers, and automation tools for penetration testing, web security challenges, and ethical hacking practice.

---

## 📚 Repository Structure

### 🎯 [CTF/](./CTF)
Capture The Flag challenge solutions and automation scripts
- **PWN**: Binary exploitation and pwn challenges

### 🔐 [Hack_The_Box/](./Hack_The_Box)
Scripts and tools for solving Hack The Box machines and challenges (16 scripts)

### 🧪 [Lab_Solver_Scripts_Practice/](./Lab_Solver_Scripts_Practice)
Practice scripts for various web security lab challenges
- NoSQL Injection labs
- SQL Injection exploits
- SSRF (Server-Side Request Forgery) bypasses
- XXE (XML External Entity) injection
- Generic lab solver framework

**Lab Scripts Include:**
- `basic_ssrf_localhost.py` - Basic SSRF to localhost
- `blind_ssrf_with_out-of-band_detection.py` - Blind SSRF detection
- `ssrf_blacklist_bypass.py` - SSRF filter bypass techniques
- `ssrf_whitelist_bypass.py` - SSRF whitelist bypass
- `ssrf_open_redirect_bypass.py` - SSRF via open redirect
- `sql_injection_lab1.py` - SQL injection fundamentals
- `lab2.py`, `lab3.py` - Advanced SQL injection
- `lab_1.py`, `lab_3.py` - NoSQL injection labs
- `xxe_lab1.py`, `xxe_lab2.py` - XXE exploitation

### 🔑 [Password_Generator/](./Password_Generator)
Advanced password generation tool with multiple customization options

### 🎓 [Port_Swigger_Labs/](./Port_Swigger_Labs)
Complete collection of PortSwigger Web Security Academy lab solutions (307+ scripts)

**Categories covered:**
- Access Control Vulnerabilities
- API Testing
- Authentication Bypasses
- Business Logic Vulnerabilities
- Clickjacking
- CORS (Cross-Origin Resource Sharing)
- CSRF (Cross-Site Request Forgery)
- Cross-Site Scripting (XSS)
- DOM-based Vulnerabilities
- Essential Skills
- File Upload Vulnerabilities
- GraphQL API Vulnerabilities
- HTTP Host Header Attacks
- HTTP Request Smuggling
- Information Disclosure
- Insecure Deserialization
- JWT (JSON Web Tokens)
- NoSQL Injection
- OAuth Authentication
- OS Command Injection
- Path Traversal
- Prototype Pollution
- Race Conditions
- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- SQL Injection
- Web Cache Deception
- Web Cache Poisoning
- Web LLM Attacks
- WebSockets Security
- XXE (XML External Entity) Injection

---

## 🚀 Usage

### Requirements
Most scripts require:
```bash
pip install requests beautifulsoup4 urllib3
```

### Running Scripts
```bash
# Example: Running an SSRF script
python Lab_Solver_Scripts_Practice/basic_ssrf_localhost.py

# Example: Password generator
python Password_Generator/password_generator.py

# Example: PortSwigger lab solution
python Port_Swigger_Labs/SQL_injection/lab1_sqli_union_attack.py
```

---

## 📊 Repository Stats

- **Total Categories**: 5 main folders
- **PortSwigger Labs**: 307+ scripts across 40+ vulnerability categories
- **Hack The Box**: 16 automation scripts
- **Lab Practice Scripts**: 14 focused vulnerability scripts
- **Languages**: Primarily Python

---

## 🎯 Purpose

This repository serves as:
- **Learning Resource**: Study web security vulnerabilities through practical examples
- **CTF Toolkit**: Ready-to-use scripts for CTF competitions
- **Penetration Testing**: Automation tools for security assessments
- **Security Research**: Reference implementations for various attack vectors

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

These scripts are designed for:
- Authorized security testing
- Educational environments
- CTF competitions
- Lab environments (PortSwigger, Hack The Box, etc.)

**DO NOT USE** these scripts on systems without explicit written permission. Unauthorized access to computer systems is illegal.

---

## 📝 License

See [LICENSE](./LICENSE) for details.

---

## 🤝 Contributing

This is a personal security research collection. Scripts are continuously updated as new challenges are solved.

---

## 📬 Contact

**Author**: BhanuGuragain0  
**GitHub**: [@BhanuGuragain0](https://github.com/BhanuGuragain0)

---

## 🔄 Recent Updates

- ✅ Migrated Password_Generator from Tools_Scripts_For_Hacking repo
- ✅ Consolidated PortSwigger lab scripts from multiple repositories
- ✅ Added 12 new lab practice scripts (NoSQL, SQL, SSRF, XXE)
- ✅ Organized flat structure for Lab_Solver_Scripts_Practice

---

**⭐ Star this repository if you find it useful!**
