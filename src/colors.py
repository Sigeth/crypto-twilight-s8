import os
import sys


# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def supports_color():
    """Check if the terminal supports color output."""
    # Check if we're in a terminal
    if not sys.stdout.isatty():
        return False

    # Check for Windows
    if os.name == 'nt':
        # Windows 10 version 1607 and later supports ANSI
        return os.environ.get('ANSICON') is not None or \
            'WT_SESSION' in os.environ or \
            'ConEmuANSI' in os.environ or \
            os.environ.get('TERM_PROGRAM') == 'vscode'

    # Most Unix-like platforms support color
    return True


def colored(text, color):
    """Apply color to text if supported."""
    if supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text