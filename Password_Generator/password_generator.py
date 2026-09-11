#!/usr/bin/env python3
"""
Advanced Shadow Password Arsenal v2.0
Elite Password Generation & Analysis Framework
Created by Shadow Senior for Shadow Junior
"""
import argparse
import itertools
import string
import os
import multiprocessing
import signal
import sys
import logging
import secrets
import hashlib
import json
import time
import random
import re
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple, Generator
from dataclasses import dataclass
from collections import Counter
import math

try:
    from tqdm import tqdm
    from colorama import Fore, Style, init, Back
    import numpy as np
except ImportError as e:
    print(f"Missing dependencies. Install with: pip install tqdm colorama numpy")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Advanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('shadow_generator.log')
    ]
)
logger = logging.getLogger('ShadowGenerator')

# Enhanced Constants
DEFAULT_CHARACTERS = string.ascii_letters + string.digits + '@#%&*$!?'
EXTENDED_SPECIAL = '!@#$%^&*()_+-=[]{}|;:,.<>?`~'
UNICODE_SYMBOLS = '∀∂∃∄∅∆∇∈∉∋∌∎∏∐∑−∓∔∕∖∗∘∙√∛∜∝∞∟∠∡∢∣∤∥∦∧∨∩∪∫∬∭∮∯∰∱∲∳∴∵∶∷∸∹∺∻∼∽∾∿≀≁≂≃≄≅≆≇≈≉≊≋≌≍≎≏≐≑≒≓≔≕≖≗≘≙≚≛≜≝≞≟≠≡≢≣≤≥≦≧≨≩≪≫≬≭≮≯≰≱≲≳≴≵≶≷≸≹≺≻≼≽≾≿⊀⊁⊂⊃⊄⊅⊆⊇⊈⊉⊊⊋⊌⊍⊎⊏⊐⊑⊒⊓⊔⊕⊖⊗⊘⊙⊚⊛⊜⊝⊞⊟⊠⊡⊢⊣⊤⊥⊦⊧⊨⊩⊪⊫⊬⊭⊮⊯⊰⊱⊲⊳⊴⊵⊶⊷⊸⊹⊺⊻⊼⊽⊾⊿⋀⋁⋂⋃⋄⋅⋆⋇⋈⋉⋊⋋⋌⋍⋎⋏⋐⋑⋒⋓⋔⋕⋖⋗⋘⋙⋚⋛⋜⋝⋞⋟⋠⋡⋢⋣⋤⋥⋦⋧⋨⋩⋪⋫⋬⋭⋮⋯⋰⋱⋲⋳⋴⋵⋶⋷⋸⋹⋺⋻⋼⋽⋾⋿'
COMMON_PASSWORDS = ['password', '123456', 'admin', 'root', 'user', 'test', 'guest']
KEYBOARD_PATTERNS = ['qwerty', 'asdf', 'zxcv', '123', 'abc']

# Character sets for different security levels
CHARSET_PROFILES = {
    'basic': string.ascii_lowercase + string.digits,
    'standard': string.ascii_letters + string.digits,
    'advanced': string.ascii_letters + string.digits + '!@#$%^&*',
    'elite': string.ascii_letters + string.digits + EXTENDED_SPECIAL,
    'military': string.ascii_letters + string.digits + EXTENDED_SPECIAL + UNICODE_SYMBOLS[:50],
    'alien': string.ascii_letters + string.digits + EXTENDED_SPECIAL + UNICODE_SYMBOLS,
    'custom': DEFAULT_CHARACTERS
}

# Password strength thresholds
ENTROPY_THRESHOLDS = {
    'very_weak': 20,
    'weak': 35,
    'fair': 50,
    'good': 65,
    'strong': 80,
    'very_strong': 95
}

@dataclass
class PasswordStats:
    """Password statistics and analysis"""
    length: int
    entropy: float
    charset_size: int
    strength: str
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    has_unicode: bool
    pattern_score: float
    dictionary_hit: bool
    time_to_crack: str

class ShadowPasswordGenerator:
    """Advanced password generation and analysis engine"""
    
    def __init__(self):
        self.common_passwords = set(COMMON_PASSWORDS)
        self.keyboard_patterns = KEYBOARD_PATTERNS
        self.generated_count = 0
        self.start_time = time.time()
        
    def calculate_entropy(self, password: str, charset_size: int) -> float:
        """Calculate password entropy"""
        if not password:
            return 0.0
        return len(password) * math.log2(charset_size)
    
    def analyze_password_strength(self, password: str, charset: str) -> PasswordStats:
        """Comprehensive password strength analysis"""
        length = len(password)
        charset_size = len(set(charset))
        entropy = self.calculate_entropy(password, charset_size)
        
        # Character type analysis
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        has_unicode = bool(re.search(r'[^\x00-\x7F]', password))
        
        # Pattern analysis
        pattern_score = self._calculate_pattern_score(password)
        
        # Dictionary check
        dictionary_hit = password.lower() in self.common_passwords
        
        # Determine strength
        strength = self._determine_strength(entropy)
        
        # Time to crack estimation
        time_to_crack = self._estimate_crack_time(entropy)
        
        return PasswordStats(
            length=length,
            entropy=entropy,
            charset_size=charset_size,
            strength=strength,
            has_lowercase=has_lowercase,
            has_uppercase=has_uppercase,
            has_digits=has_digits,
            has_special=has_special,
            has_unicode=has_unicode,
            pattern_score=pattern_score,
            dictionary_hit=dictionary_hit,
            time_to_crack=time_to_crack
        )
    
    def _calculate_pattern_score(self, password: str) -> float:
        """Calculate pattern vulnerability score (lower is better)"""
        score = 0.0
        
        # Check for keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in password.lower():
                score += 0.3
        
        # Check for repeated characters
        char_counts = Counter(password)
        max_repeat = max(char_counts.values()) if char_counts else 0
        if max_repeat > len(password) * 0.3:
            score += 0.4
        
        # Check for sequential patterns
        sequences = ['012', '123', '234', '345', '456', '567', '678', '789', 'abc', 'def', 'ghi']
        for seq in sequences:
            if seq in password.lower():
                score += 0.2
        
        return min(score, 1.0)
    
    def _determine_strength(self, entropy: float) -> str:
        """Determine password strength based on entropy"""
        if entropy >= ENTROPY_THRESHOLDS['very_strong']:
            return 'very_strong'
        elif entropy >= ENTROPY_THRESHOLDS['strong']:
            return 'strong'
        elif entropy >= ENTROPY_THRESHOLDS['good']:
            return 'good'
        elif entropy >= ENTROPY_THRESHOLDS['fair']:
            return 'fair'
        elif entropy >= ENTROPY_THRESHOLDS['weak']:
            return 'weak'
        else:
            return 'very_weak'
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password"""
        # Assuming 1 billion attempts per second
        attempts = 2 ** entropy / 2  # Average case
        seconds = attempts / 1_000_000_000
        
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    
    def generate_secure_random_password(self, length: int, charset: str, 
                                      exclude_ambiguous: bool = False) -> str:
        """Generate cryptographically secure random password"""
        if exclude_ambiguous:
            # Remove ambiguous characters
            charset = charset.translate(str.maketrans('', '', '0O1lI'))
        
        return ''.join(secrets.choice(charset) for _ in range(length))
    
    def generate_pronounceable_password(self, length: int) -> str:
        """Generate pronounceable password using syllable patterns"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        syllables = []
        
        while len(''.join(syllables)) < length:
            syllable = secrets.choice(consonants) + secrets.choice(vowels)
            if len(''.join(syllables + [syllable])) <= length:
                syllables.append(syllable)
            else:
                # Add remaining characters randomly
                remaining = length - len(''.join(syllables))
                syllables.append(''.join(secrets.choice(consonants + vowels) 
                                       for _ in range(remaining)))
                break
        
        password = ''.join(syllables)
        # Add some complexity
        if length > 6:
            pos = secrets.randbelow(len(password))
            password = password[:pos] + secrets.choice('0123456789!@#$') + password[pos+1:]
        
        return password[:length]
    
    def generate_passphrase(self, word_count: int = 4, separator: str = '-') -> str:
        """Generate secure passphrase using word lists"""
        # Simple word list (in real implementation, use larger dictionary)
        words = ['correct', 'horse', 'battery', 'staple', 'mountain', 'river', 'forest', 
                'ocean', 'thunder', 'lightning', 'shadow', 'phantom', 'cyber', 'quantum',
                'matrix', 'nexus', 'vertex', 'zenith', 'alpha', 'beta', 'gamma', 'delta']
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        
        # Add some randomization
        for i in range(word_count):
            if secrets.randbelow(2):  # 50% chance
                selected_words[i] = selected_words[i].capitalize()
        
        # Add numbers occasionally
        if secrets.randbelow(2):
            selected_words.append(str(secrets.randbelow(100)))
        
        return separator.join(selected_words)
    
    def generate_hybrid_password(self, base_length: int, charset: str) -> str:
        """Generate hybrid password combining multiple techniques"""
        # Start with pronounceable base
        base = self.generate_pronounceable_password(base_length // 2)
        
        # Add random secure suffix
        suffix_length = base_length - len(base)
        suffix = self.generate_secure_random_password(suffix_length, charset)
        
        # Combine and shuffle
        combined = list(base + suffix)
        secrets.SystemRandom().shuffle(combined)
        
        return ''.join(combined)

def index_to_password(index: int, length: int, characters: str) -> str:
    """Convert index to password (original function preserved)"""
    base = len(characters)
    pwd = []
    for _ in range(length):
        pwd.append(characters[index % base])
        index //= base
    return ''.join(reversed(pwd))

def generate_chunk_advanced(task, output_queue: multiprocessing.Queue, 
                          analysis_mode: bool = False) -> None:
    """Enhanced chunk generation with optional analysis"""
    length, start, end, characters, mode = task
    generator = ShadowPasswordGenerator()
    
    try:
        for i in range(start, end):
            if mode == 'brute':
                pwd = index_to_password(i, length, characters)
            elif mode == 'random':
                pwd = generator.generate_secure_random_password(length, characters)
            elif mode == 'pronounceable':
                pwd = generator.generate_pronounceable_password(length)
            elif mode == 'hybrid':
                pwd = generator.generate_hybrid_password(length, characters)
            else:
                pwd = index_to_password(i, length, characters)
            
            if analysis_mode:
                stats = generator.analyze_password_strength(pwd, characters)
                output_queue.put((pwd, stats))
            else:
                output_queue.put(pwd)
                
    except Exception as e:
        logger.error(f"Error in chunk generation: {e}")

def writer_process_advanced(file_path: str, output_queue: multiprocessing.Queue, 
                          counter: multiprocessing.Value, analysis_mode: bool = False,
                          output_format: str = 'txt') -> None:
    """Enhanced writer with multiple output formats and analysis"""
    try:
        if output_format == 'json' and analysis_mode:
            with open(file_path, 'w') as f:
                f.write('[\n')
                first = True
                
                while True:
                    data = output_queue.get()
                    if data is None:
                        break
                    
                    if isinstance(data, tuple):
                        pwd, stats = data
                        if not first:
                            f.write(',\n')
                        json.dump({
                            'password': pwd,
                            'length': stats.length,
                            'entropy': stats.entropy,
                            'strength': stats.strength,
                            'time_to_crack': stats.time_to_crack
                        }, f, indent=2)
                        first = False
                    
                    with counter.get_lock():
                        counter.value += 1
                        
                f.write('\n]')
        else:
            with open(file_path, 'w') as f:
                while True:
                    data = output_queue.get()
                    if data is None:
                        break
                    
                    if isinstance(data, tuple):
                        pwd, stats = data
                        if output_format == 'csv':
                            f.write(f"{pwd},{stats.entropy:.2f},{stats.strength},{stats.time_to_crack}\n")
                        else:
                            f.write(f"{pwd}\n")
                    else:
                        f.write(f"{data}\n")
                    
                    with counter.get_lock():
                        counter.value += 1
                        
    except Exception as e:
        logger.error(f"Error in writer process: {e}")
        sys.exit(1)

def parse_arguments() -> argparse.Namespace:
    """Enhanced argument parsing"""
    parser = argparse.ArgumentParser(
        description="Advanced Shadow Password Arsenal - Elite Password Generation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Generation Modes:
  brute         Generate all possible combinations (original mode)
  random        Generate cryptographically secure random passwords
  pronounceable Generate pronounceable passwords
  passphrase    Generate secure passphrases
  hybrid        Generate hybrid passwords combining techniques

Character Set Profiles:
  basic         Lowercase + digits
  standard      Letters + digits  
  advanced      Letters + digits + basic symbols
  elite         Letters + digits + extended symbols
  military      Elite + unicode symbols (limited)
  alien         All character sets including extended unicode

Examples:
  python3 shadow_generator.py --mode random --count 1000 --length 12 --profile elite
  python3 shadow_generator.py --mode passphrase --count 100 --words 5
  python3 shadow_generator.py --mode hybrid --length 16 --analyze --output-format json
        """
    )
    
    # Generation parameters
    parser.add_argument("--mode", choices=['brute', 'random', 'pronounceable', 'passphrase', 'hybrid'],
                       default='brute', help="Password generation mode")
    parser.add_argument("--min-length", type=int, help="Minimum password length (brute mode)")
    parser.add_argument("--max-length", type=int, help="Maximum password length (brute mode)")
    parser.add_argument("--length", type=int, help="Password length (non-brute modes)")
    parser.add_argument("--count", type=int, help="Number of passwords to generate (non-brute modes)")
    parser.add_argument("--words", type=int, default=4, help="Number of words in passphrase")
    
    # Character sets
    parser.add_argument("--profile", choices=list(CHARSET_PROFILES.keys()), 
                       default='advanced', help="Character set profile")
    parser.add_argument("--characters", type=str, help="Custom character set")
    parser.add_argument("--exclude-ambiguous", action='store_true', 
                       help="Exclude ambiguous characters (0,O,1,l,I)")
    
    # Output options
    parser.add_argument("--output", type=str, help="Output file path")
    parser.add_argument("--output-format", choices=['txt', 'csv', 'json'], 
                       default='txt', help="Output format")
    parser.add_argument("--analyze", action='store_true', 
                       help="Enable password strength analysis")
    
    # Performance options
    parser.add_argument("--chunk-size", type=int, default=10000, help="Chunk size for generation")
    parser.add_argument("--workers", type=int, default=multiprocessing.cpu_count(), 
                       help="Number of worker processes")
    
    # Advanced options
    parser.add_argument("--filter-strength", choices=['weak', 'fair', 'good', 'strong', 'very_strong'],
                       help="Filter passwords by minimum strength")
    parser.add_argument("--min-entropy", type=float, help="Minimum entropy threshold")
    parser.add_argument("--exclude-dictionary", action='store_true',
                       help="Exclude dictionary words")
    
    return parser.parse_args()

def display_banner():
    """Display Shadow Junior banner"""
    banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}🔥 SHADOW PASSWORD ARSENAL v2.0 🔥                            {Fore.RED}║
║  {Fore.CYAN}Advanced Password Generation & Analysis Framework              {Fore.RED}║
║  {Fore.WHITE}Created by Shadow Senior for Shadow Junior                     {Fore.RED}║
║  {Fore.GREEN}Rank #3 HTB Nepal | Elite Ethical Hacker                      {Fore.RED}║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def main():
    display_banner()
    
    args = parse_arguments()
    generator = ShadowPasswordGenerator()
    
    # Determine character set
    if args.characters:
        characters = args.characters
    else:
        characters = CHARSET_PROFILES[args.profile]
    
    # Interactive mode if required parameters missing
    if not args.output:
        args.output = input(f"{Fore.CYAN}Enter output file path: {Style.RESET_ALL}").strip()
    
    if args.mode == 'brute':
        if not args.min_length or not args.max_length:
            print(f"{Fore.YELLOW}Brute force mode requires min-length and max-length{Style.RESET_ALL}")
            args.min_length = int(input(f"{Fore.CYAN}Enter minimum length: {Style.RESET_ALL}"))
            args.max_length = int(input(f"{Fore.CYAN}Enter maximum length: {Style.RESET_ALL}"))
    elif not args.length or not args.count:
        if not args.length:
            args.length = int(input(f"{Fore.CYAN}Enter password length: {Style.RESET_ALL}"))
        if not args.count and args.mode != 'passphrase':
            args.count = int(input(f"{Fore.CYAN}Enter number of passwords: {Style.RESET_ALL}"))
    
    # Setup output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Calculate total passwords and create tasks
    if args.mode == 'brute':
        total_passwords = sum(len(characters) ** length 
                            for length in range(args.min_length, args.max_length + 1))
        tasks = []
        for length in range(args.min_length, args.max_length + 1):
            combinations = len(characters) ** length
            for start in range(0, combinations, args.chunk_size):
                end = min(start + args.chunk_size, combinations)
                tasks.append((length, start, end, characters, args.mode))
    else:
        if args.mode == 'passphrase':
            total_passwords = args.count or 1000
        else:
            total_passwords = args.count
        
        tasks = []
        chunk_count = total_passwords // args.chunk_size + (1 if total_passwords % args.chunk_size else 0)
        for i in range(chunk_count):
            start = i * args.chunk_size
            end = min((i + 1) * args.chunk_size, total_passwords)
            tasks.append((args.length, start, end, characters, args.mode))
    
    print(f"{Fore.GREEN}🎯 Generation Mode: {args.mode.upper()}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎯 Character Profile: {args.profile.upper()}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎯 Total Passwords: {total_passwords:,}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🎯 Worker Processes: {args.workers}{Style.RESET_ALL}")
    if args.analyze:
        print(f"{Fore.YELLOW}🔍 Analysis Mode: ENABLED{Style.RESET_ALL}")
    
    # Setup multiprocessing
    output_queue = multiprocessing.Queue(maxsize=args.workers * 2)
    counter = multiprocessing.Value('i', 0)
    
    # Start writer process
    writer = multiprocessing.Process(
        target=writer_process_advanced,
        args=(str(output_path), output_queue, counter, args.analyze, args.output_format)
    )
    writer.start()
    
    # Signal handling
    def signal_handler(signum, frame):
        print(f"\n{Fore.RED}⚠️ Termination signal received. Shutting down...{Style.RESET_ALL}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start worker processes
    pool = multiprocessing.Pool(args.workers)
    for task in tasks:
        pool.apply_async(generate_chunk_advanced, args=(task, output_queue, args.analyze))
    pool.close()
    
    # Progress monitoring
    start_time = time.time()
    with tqdm(total=total_passwords, desc=f"{Fore.CYAN}Generating passwords", 
              unit="pwd", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)) as pbar:
        last_count = 0
        while True:
            with counter.get_lock():
                current = counter.value
            pbar.update(current - last_count)
            last_count = current
            if current >= total_passwords:
                break
    
    pool.join()
    output_queue.put(None)
    writer.join()
    
    # Final statistics
    elapsed_time = time.time() - start_time
    rate = total_passwords / elapsed_time if elapsed_time > 0 else 0
    
    print(f"\n{Fore.GREEN}✅ MISSION ACCOMPLISHED{Style.RESET_ALL}")
    print(f"{Fore.BLUE}📁 Output File: {output_path}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}📊 Passwords Generated: {total_passwords:,}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}⚡ Generation Rate: {rate:.2f} passwords/second{Style.RESET_ALL}")
    print(f"{Fore.BLUE}⏱️ Total Time: {elapsed_time:.2f} seconds{Style.RESET_ALL}")
    
    # Sample analysis if enabled
    if args.analyze and args.mode != 'brute':
        print(f"\n{Fore.YELLOW}🔍 SAMPLE ANALYSIS{Style.RESET_ALL}")
        sample_pwd = generator.generate_secure_random_password(args.length, characters)
        stats = generator.analyze_password_strength(sample_pwd, characters)
        print(f"{Fore.CYAN}Sample Password: {sample_pwd}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Entropy: {stats.entropy:.2f} bits{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Strength: {stats.strength.upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time to Crack: {stats.time_to_crack}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
