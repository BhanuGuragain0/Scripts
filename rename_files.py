#!/usr/bin/env python3
"""
Advanced File Renamer Script

This script recursively renames files in a given directory by replacing a specified
pattern in their filenames with a replacement string. It supports both simple string
matching and regex-based pattern matching. Additional features include dry-run simulation,
backup creation, interactive confirmation, logging (to console and file), and storing
a mapping file for reverting changes if needed.

Usage examples:
    # Basic usage: rename files ending with "_tool.py" to "_warper.py" in the current directory.
    python3 rename_files.py

    # Specify a base directory and run interactively with verbose logging.
    python3 rename_files.py -d /path/to/directory -p "_tool.py" -r "_warper.py" --interactive --verbose

    # Run in dry-run mode with backup and regex mode enabled.
    python3 rename_files.py --dry-run --backup --regex

    # Log output to a file.
    python3 rename_files.py --log-file rename.log

    # Save a mapping file for potential revert.
    python3 rename_files.py --mapping-file rename_mapping.json
"""

import os
import re
import argparse
import logging
import shutil
import json
from typing import Dict

def parse_args():
    parser = argparse.ArgumentParser(
        description="Recursively rename files by replacing a substring or regex pattern in filenames."
    )
    parser.add_argument(
        '-d', '--directory', type=str, default=os.getcwd(),
        help="Base directory to start renaming (default: current working directory)."
    )
    parser.add_argument(
        '-p', '--pattern', type=str, default='_tool.py',
        help='Filename pattern to search for (default: "_tool.py").'
    )
    parser.add_argument(
        '-r', '--replacement', type=str, default='_warper.py',
        help='Replacement string (default: "_warper.py").'
    )
    parser.add_argument(
        '--regex', action='store_true',
        help="Treat the pattern as a regular expression."
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help="Simulate the renaming process without making any changes."
    )
    parser.add_argument(
        '--backup', action='store_true',
        help="Create backup copies of files before renaming."
    )
    parser.add_argument(
        '--backup-dir', type=str, default=None,
        help="Directory to store backup copies (default: <base_dir>/.rename_backups)."
    )
    parser.add_argument(
        '--interactive', action='store_true',
        help="Ask for confirmation before renaming each file."
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help="Increase output verbosity."
    )
    parser.add_argument(
        '--log-file', type=str, default=None,
        help="Log output to a specified file in addition to the console."
    )
    parser.add_argument(
        '--mapping-file', type=str, default=None,
        help="File to store a JSON mapping of old filenames to new filenames."
    )
    return parser.parse_args()

def setup_logging(verbose: bool, log_file: str = None):
    """Configure logging to console and optionally to a file."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=log_format,
        handlers=handlers
    )

def confirm_action(prompt: str) -> bool:
    """Prompt the user for confirmation."""
    response = input(prompt + " [Y/n]: ").strip().lower()
    return response in ("", "y", "yes")

def create_backup(file_path: str, base_dir: str, backup_dir: str):
    """
    Create a backup copy of a file preserving its relative path from the base directory.
    """
    rel_path = os.path.relpath(file_path, base_dir)
    backup_path = os.path.join(backup_dir, rel_path)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    shutil.copy2(file_path, backup_path)
    logging.info("Backup created: %s", backup_path)

def rename_files(base_dir: str, pattern: str, replacement: str, regex_mode: bool,
                 dry_run: bool, backup: bool, backup_dir: str, interactive: bool) -> Dict[str, str]:
    """
    Walk through the base directory recursively, and rename files that match the specified pattern.
    
    Returns:
        mapping (dict): A dictionary mapping old file paths to new file paths.
    """
    mapping = {}
    total_files = 0
    renamed_files = 0
    logging.info("Starting directory traversal in '%s'", base_dir)

    for root, _, files in os.walk(base_dir):
        logging.debug("Processing directory: %s", root)
        for file in files:
            total_files += 1
            full_path = os.path.join(root, file)
            new_name = None

            # Check if the file matches the pattern (regex or simple string)
            if regex_mode:
                if re.search(pattern, file):
                    new_name = re.sub(pattern, replacement, file)
            else:
                if file.endswith(pattern):
                    new_name = file.replace(pattern, replacement)
            
            if new_name and new_name != file:
                old_path = full_path
                new_path = os.path.join(root, new_name)
                
                # Skip if new file already exists
                if os.path.exists(new_path):
                    logging.error("Target file already exists, skipping: %s", new_path)
                    continue
                
                # Interactive confirmation if enabled
                if interactive and not confirm_action(f"Rename '{old_path}' to '{new_path}'?"):
                    logging.info("Skipped: %s", old_path)
                    continue

                # Create backup if requested
                if backup:
                    create_backup(old_path, base_dir, backup_dir)

                if dry_run:
                    logging.info("[Dry-run] Would rename: %s -> %s", old_path, new_path)
                else:
                    try:
                        os.rename(old_path, new_path)
                        logging.info("Renamed: %s -> %s", old_path, new_path)
                        renamed_files += 1
                        mapping[old_path] = new_path
                    except Exception as e:
                        logging.error("Error renaming '%s': %s", old_path, e)

    logging.info("Traversal complete. Total files processed: %d. Files renamed: %d.", total_files, renamed_files)
    return mapping

def main():
    args = parse_args()
    setup_logging(args.verbose, args.log_file)

    base_dir = os.path.abspath(args.directory)
    if args.backup:
        backup_dir = args.backup_dir or os.path.join(base_dir, ".rename_backups")
        os.makedirs(backup_dir, exist_ok=True)
        logging.info("Backup directory set to: %s", backup_dir)
    else:
        backup_dir = None

    mapping = rename_files(
        base_dir=base_dir,
        pattern=args.pattern,
        replacement=args.replacement,
        regex_mode=args.regex,
        dry_run=args.dry_run,
        backup=args.backup,
        backup_dir=backup_dir,
        interactive=args.interactive
    )

    if args.mapping_file and mapping:
        try:
            with open(args.mapping_file, 'w') as f:
                json.dump(mapping, f, indent=4)
            logging.info("Mapping file written: %s", args.mapping_file)
        except Exception as e:
            logging.error("Error writing mapping file: %s", e)

if __name__ == '__main__':
    main()
