# 🔥 Advanced Password Generator By Shadow@Bhanu
*Remember: With great power comes great responsibility. Use your skills to protect, not exploit.*

This is a cutting-edge Python framework designed for **elite ethical hackers, penetration testers, and red team operators**. This tool combines multiple password generation techniques with comprehensive security analysis, delivering production-grade capabilities for advanced cybersecurity operations.

## 🎯 **Core Features**

### **🚀 Multiple Generation Modes**
- **Brute Force**: Exhaustive generation of all possible combinations
- **Random**: Cryptographically secure random password generation using `secrets` module
- **Pronounceable**: Human-readable passwords with maintained security
- **Passphrase**: Multi-word secure passphrases with randomization
- **Hybrid**: Advanced combination of multiple techniques for maximum entropy

### **🔒 Character Set Profiles**
- **Basic**: Lowercase letters + digits (`a-z0-9`)
- **Standard**: All letters + digits (`A-Za-z0-9`)
- **Advanced**: Letters + digits + basic symbols (`A-Za-z0-9!@#$%^&*`)
- **Elite**: Extended symbols for high-security environments
- **Military**: Elite + limited unicode symbols for specialized operations
- **Alien**: Full unicode symbol set for maximum complexity
- **Custom**: User-defined character sets

### **🔍 Advanced Security Analysis**
- **Entropy Calculation**: Precise bit-level entropy measurements
- **Pattern Detection**: Keyboard sequences, character repetition, common patterns
- **Dictionary Resistance**: Detection of common passwords and dictionary words
- **Time-to-Crack Estimation**: Based on current GPU attack speeds
- **Character Diversity Analysis**: Comprehensive character type breakdown
- **Strength Classification**: 6-tier strength rating system

### **📊 Multiple Output Formats**
- **TXT**: Standard password lists for immediate use
- **CSV**: Spreadsheet-compatible format with analysis metrics
- **JSON**: Structured data with complete security analysis

### **⚡ Performance Optimization**
- **Multiprocessing**: Parallel generation using all CPU cores
- **Memory Efficiency**: Streaming output for large datasets
- **Real-time Progress**: Live generation statistics and ETA
- **Chunk-based Processing**: Optimized task distribution

## 📋 **Prerequisites**

### **System Requirements**
- **Python 3.7+**
- **Minimum 4GB RAM** (8GB+ recommended for large operations)
- **Multi-core CPU** (performance scales with core count)

### **Required Dependencies**
```bash
pip install tqdm colorama numpy
```

### **Optional Dependencies**
```bash
# For extended unicode support
pip install unicodedata2

# For advanced analysis features
pip install matplotlib seaborn
```

## 🚀 **Installation**

### **Clone Repository**
```bash
git clone https://github.com/shadowjunior/advanced-password-arsenal.git
cd advanced-password-arsenal
```

### **Setup Virtual Environment (Recommended)**
```bash
python3 -m venv shadow_env
source shadow_env/bin/activate  # Linux/macOS
# shadow_env\Scripts\activate  # Windows
```

### **Install Dependencies**
```bash
pip install -r requirements.txt
```

### **Verify Installation**
```bash
python3 shadow_generator.py --help
```

## 💡 **Usage Examples**

### **🎲 Random Password Generation**
```bash
# Generate 10,000 elite random passwords with analysis
python3 shadow_generator.py \
    --mode random \
    --count 10000 \
    --length 16 \
    --profile elite \
    --analyze \
    --output-format json \
    --output elite_passwords.json

# High-entropy passwords excluding ambiguous characters
python3 shadow_generator.py \
    --mode random \
    --count 5000 \
    --length 24 \
    --profile alien \
    --exclude-ambiguous \
    --min-entropy 120 \
    --output alien_passwords.txt
```

### **🗣️ Pronounceable Password Generation**
```bash
# Generate pronounceable passwords for social engineering
python3 shadow_generator.py \
    --mode pronounceable \
    --count 2000 \
    --length 12 \
    --analyze \
    --filter-strength good \
    --output pronounceable_passwords.txt

# Pronounceable with strength analysis
python3 shadow_generator.py \
    --mode pronounceable \
    --count 1000 \
    --length 16 \
    --analyze \
    --output-format csv \
    --output pronounceable_analysis.csv
```

### **📝 Passphrase Generation**
```bash
# Generate secure passphrases for high-value targets
python3 shadow_generator.py \
    --mode passphrase \
    --count 1000 \
    --words 5 \
    --analyze \
    --output passphrases.txt

# Extended passphrases with analysis
python3 shadow_generator.py \
    --mode passphrase \
    --count 500 \
    --words 7 \
    --analyze \
    --output-format json \
    --filter-strength strong \
    --output extended_passphrases.json
```

### **🔬 Hybrid Generation**
```bash
# Advanced hybrid passwords combining multiple techniques
python3 shadow_generator.py \
    --mode hybrid \
    --count 5000 \
    --length 20 \
    --profile military \
    --analyze \
    --exclude-dictionary \
    --output hybrid_advanced.txt

# Hybrid with maximum security profile
python3 shadow_generator.py \
    --mode hybrid \
    --count 1000 \
    --length 32 \
    --profile alien \
    --min-entropy 150 \
    --analyze \
    --output-format json \
    --output maximum_security.json
```

### **💥 Brute Force Generation**
```bash
# Traditional brute force with modern analysis
python3 shadow_generator.py \
    --mode brute \
    --min-length 8 \
    --max-length 10 \
    --profile advanced \
    --analyze \
    --filter-strength good \
    --output brute_filtered.txt

# Comprehensive brute force with custom charset
python3 shadow_generator.py \
    --mode brute \
    --min-length 6 \
    --max-length 8 \
    --characters "ABCDEFabcdef0123456789!@#$" \
    --analyze \
    --output-format csv \
    --output custom_brute.csv
```

### **🎯 Advanced Filtering & Analysis**
```bash
# High-entropy passwords with dictionary exclusion
python3 shadow_generator.py \
    --mode random \
    --count 10000 \
    --length 18 \
    --profile elite \
    --min-entropy 95 \
    --exclude-dictionary \
    --exclude-ambiguous \
    --analyze \
    --output-format json \
    --output filtered_elite.json

# Military-grade passwords with comprehensive analysis
python3 shadow_generator.py \
    --mode hybrid \
    --count 2000 \
    --length 25 \
    --profile military \
    --filter-strength very_strong \
    --analyze \
    --output-format json \
    --workers 8 \
    --output military_grade.json
```

### **⚡ Performance Optimization**
```bash
# Maximum performance configuration
python3 shadow_generator.py \
    --mode random \
    --count 100000 \
    --length 16 \
    --profile elite \
    --workers 16 \
    --chunk-size 50000 \
    --output high_performance.txt

# Memory-efficient large dataset generation
python3 shadow_generator.py \
    --mode brute \
    --min-length 6 \
    --max-length 7 \
    --profile standard \
    --chunk-size 25000 \
    --workers 12 \
    --output large_dataset.txt
```

## 🔧 **Command Line Options**

### **Generation Parameters**
- `--mode`: Generation mode (`brute`, `random`, `pronounceable`, `passphrase`, `hybrid`)
- `--min-length`, `--max-length`: Password length range (brute mode)
- `--length`: Fixed password length (non-brute modes)
- `--count`: Number of passwords to generate (non-brute modes)
- `--words`: Number of words in passphrase (passphrase mode)

### **Character Set Configuration**
- `--profile`: Predefined character set profile
- `--characters`: Custom character set string
- `--exclude-ambiguous`: Remove ambiguous characters (0,O,1,l,I)

### **Output Configuration**
- `--output`: Output file path
- `--output-format`: Output format (`txt`, `csv`, `json`)
- `--analyze`: Enable password strength analysis

### **Quality Filters**
- `--filter-strength`: Minimum strength level
- `--min-entropy`: Minimum entropy threshold (bits)
- `--exclude-dictionary`: Exclude dictionary words

### **Performance Options**
- `--workers`: Number of worker processes
- `--chunk-size`: Task chunk size for optimization

## 📊 **Output Format Examples**

### **JSON Output with Analysis**
```json
[
  {
    "password": "Kx7#mR9$pL2@nF5!",
    "length": 16,
    "entropy": 89.42,
    "strength": "very_strong",
    "time_to_crack": "2.3 million years"
  }
]
```

### **CSV Output with Metrics**
```csv
password,entropy,strength,time_to_crack
Kx7#mR9$pL2@nF5!,89.42,very_strong,2.3 million years
```

## 🎯 **Strength Classification**

| **Strength Level** | **Entropy Range** | **Estimated Crack Time** | **Use Case** |
|--------------------|-------------------|---------------------------|--------------|
| Very Weak          | 0-20 bits         | < 1 second                | Testing only |
| Weak               | 21-35 bits        | Minutes to hours          | Basic systems |
| Fair               | 36-50 bits        | Days to weeks             | Standard security |
| Good               | 51-65 bits        | Months to years           | Business systems |
| Strong             | 66-80 bits        | Decades                   | High security |
| Very Strong        | 81+ bits          | Centuries+                | Military/Intelligence |

## 🔍 **Pattern Detection**

The analysis engine detects:
- **Keyboard patterns**: `qwerty`, `asdf`, `123456`
- **Repetition**: Character/sequence repetition
- **Dictionary words**: Common password dictionary
- **Sequential patterns**: `abc`, `123`, `xyz`
- **Character distribution**: Entropy-based analysis

## ⚡ **Performance Benchmarks**

### **Generation Speeds** (on 8-core system)
- **Random Mode**: ~50,000 passwords/second
- **Pronounceable**: ~30,000 passwords/second
- **Hybrid**: ~25,000 passwords/second
- **Brute Force**: ~100,000 combinations/second

### **Memory Usage**
- **Base**: ~100MB RAM
- **With Analysis**: ~200MB RAM
- **Large datasets**: Streaming (constant memory)

## 🛡️ **Security Considerations**

### **Operational Security**
- Generated passwords are written directly to files (not stored in memory)
- No network communication or external dependencies
- Secure random number generation using `secrets` module
- Optional exclusion of ambiguous characters for human readability

### **Storage Recommendations**
- Store generated passwords on encrypted drives
- Use secure deletion for temporary files
- Implement proper access controls on output files
- Consider using in-memory filesystems for sensitive operations

## 🔧 **Troubleshooting**

### **Common Issues**

**Memory Errors with Large Datasets**
```bash
# Use smaller chunk sizes
--chunk-size 5000

# Reduce worker processes
--workers 4
```

**Slow Generation Speed**
```bash
# Increase worker processes (up to CPU cores)
--workers 12

# Increase chunk size for brute force
--chunk-size 25000

# Disable analysis for maximum speed
# (remove --analyze flag)
```

**Unicode Character Issues**
```bash
# Use basic profiles for compatibility
--profile standard

# Exclude unicode characters
--exclude-ambiguous
```

## 📈 **Advanced Use Cases**

### **Red Team Operations**
- Generate credential lists for password spraying attacks
- Create pronounceable passwords for social engineering campaigns
- Develop custom wordlists based on target organization patterns

### **Penetration Testing**
- Build comprehensive password dictionaries for hash cracking
- Generate high-entropy passwords for secure system testing
- Create passphrases for long-term access scenarios

### **Security Research**
- Analyze password complexity in different character sets
- Study entropy distribution across generation methods
- Benchmark password cracking resistance

## 📄 **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## ⚠️ **Legal Disclaimer**

This tool is designed for **authorized security testing, research, and educational purposes only**. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

**Use responsibly. Test only systems you own or have explicit permission to test.**
