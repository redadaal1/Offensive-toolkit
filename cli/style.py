#!/usr/bin/env python3
"""
CLI styling utilities for colored output.
"""

import sys
from typing import Optional

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_colored(message: str, color: str, bold: bool = False, end: str = '\n') -> None:
    """Print a colored message to stdout."""
    if not sys.stdout.isatty():
        # If not a terminal, print without colors
        print(message, end=end)
        return
    
    formatted = message
    if bold:
        formatted = f"{Colors.BOLD}{formatted}{Colors.END}"
    if color:
        formatted = f"{color}{formatted}{Colors.END}"
    
    print(formatted, end=end)

def print_info(message: str, end: str = '\n') -> None:
    """Print an informational message in blue."""
    print_colored(f"[INFO] {message}", Colors.BLUE, end=end)

def print_success(message: str, end: str = '\n') -> None:
    """Print a success message in green."""
    print_colored(f"[SUCCESS] {message}", Colors.GREEN, end=end)

def print_error(message: str, end: str = '\n') -> None:
    """Print an error message in red."""
    print_colored(f"[ERROR] {message}", Colors.RED, end=end)

def print_warning(message: str, end: str = '\n') -> None:
    """Print a warning message in yellow."""
    print_colored(f"[WARNING] {message}", Colors.YELLOW, end=end)

def print_debug(message: str, end: str = '\n') -> None:
    """Print a debug message in cyan."""
    print_colored(f"[DEBUG] {message}", Colors.CYAN, end=end)

def print_step(message: str, end: str = '\n') -> None:
    """Print a step message in magenta."""
    print_colored(f"[STEP] {message}", Colors.MAGENTA, end=end)

def print_command(message: str, end: str = '\n') -> None:
    """Print a command message in white with bold."""
    print_colored(f"[COMMAND] {message}", Colors.WHITE, bold=True, end=end)

def print_target(message: str, end: str = '\n') -> None:
    """Print a target message in bold cyan."""
    print_colored(f"[TARGET] {message}", Colors.CYAN, bold=True, end=end)

def print_exploit(message: str, end: str = '\n') -> None:
    """Print an exploit message in bold red."""
    print_colored(f"[EXPLOIT] {message}", Colors.RED, bold=True, end=end)

def print_post_exploit(message: str, end: str = '\n') -> None:
    """Print a post-exploit message in bold green."""
    print_colored(f"[POST-EXPLOIT] {message}", Colors.GREEN, bold=True, end=end)

def print_report(message: str, end: str = '\n') -> None:
    """Print a report message in bold blue."""
    print_colored(f"[REPORT] {message}", Colors.BLUE, bold=True, end=end)

def print_walkthrough(message: str, end: str = '\n') -> None:
    """Print a walkthrough message in bold magenta."""
    print_colored(f"[WALKTHROUGH] {message}", Colors.MAGENTA, bold=True, end=end)

def print_separator(char: str = "=", length: int = 60) -> None:
    """Print a separator line."""
    separator = char * length
    print_colored(separator, Colors.WHITE, end='\n')

def print_header(title: str) -> None:
    """Print a header with title."""
    print_separator()
    print_colored(f"[HEADER] {title}", Colors.RED, bold=True)
    print_separator()

def print_phase(phase: str, description: str = "") -> None:
    """Print a phase header."""
    print_colored(f"[PHASE] {phase}", Colors.MAGENTA, bold=True)
    if description:
        print_colored(f"   {description}", Colors.WHITE)
    print()

def print_progress(current: int, total: int, description: str = "Progress") -> None:
    """Print a progress bar."""
    percentage = (current / total) * 100
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    
    print_colored(f"[PROGRESS] {description}: [{bar}] {percentage:.1f}% ({current}/{total})", Colors.CYAN)

def print_table(headers: list, rows: list) -> None:
    """Print a formatted table."""
    if not rows:
        return
    
    # Calculate column widths
    col_widths = []
    for i in range(len(headers)):
        max_width = len(str(headers[i]))
        for row in rows:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)
    
    # Print header
    header_row = " | ".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
    print_colored(header_row, Colors.BOLD)
    print_separator("-", len(header_row))
    
    # Print rows
    for row in rows:
        row_str = " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths))
        print_colored(row_str, Colors.WHITE)

def print_banner() -> None:
    """Print the tool banner."""
    banner = """
Offensive Security Automation Toolkit
Complete Penetration Testing Solution
======================================
"""
    print_colored(banner, Colors.RED, bold=True)

def print_help_examples() -> None:
    """Print help examples."""
    examples = """
Usage Examples:
   python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough
   python3 -m cli.main --target 192.168.1.10 --recon
   python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --exploit
   python3 -m cli.main --target 192.168.1.10 --post-exploit
   python3 -m cli.main --target 192.168.1.10 --report
   python3 -m cli.main --target 192.168.1.10 --walkthrough
"""
    print_colored(examples, Colors.CYAN)
