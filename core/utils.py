"""Common utilities for Bug Bounty Recon Framework."""

import logging
import re
import sys
from urllib.parse import urlparse
from typing import Optional
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = r"""
 __        ____  _     _ _____ ____ _____ ____                      
 \ \      / /___|_) __/ |___ /|___ \___  |  _ \ ___  ___ ___  _ __  
  \ \ /\ / /__  \| '_ \_| |_ \ __) / / | |_) / _ \/ __/ _ \| '_ \ 
   \ V  V / ___) | |_) | |___) / __/ / /|  _ <  __/ (_| (_) | | | |
    \_/\_/ |____/|_.__/|_|____/_____|_/ |_| \_\___|\___\___/|_| |_|
                                                                     
    Bug Bounty Recon Framework v1.0
    [!] For authorized testing only
"""


def print_banner():
    """Print the framework banner."""
    print(f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[WARNING] Use this tool only on targets you are authorized to test.{Style.RESET_ALL}")
    print()


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging for the framework."""
    logger = logging.getLogger("bugrecon")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_fmt = logging.Formatter(
        f"{Fore.GREEN}[%(asctime)s]{Style.RESET_ALL} "
        f"{Fore.BLUE}%(name)s{Style.RESET_ALL} - "
        f"%(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    return logger


def validate_url(url: str) -> bool:
    """Validate if a string is a proper URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r'[^\w\s\-.]', '', name).strip().replace(' ', '_')[:100]


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""


def severity_color(severity: str) -> str:
    """Get color code for severity level."""
    colors = {
        "critical": Fore.RED,
        "high": Fore.LIGHTRED_EX,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": Fore.BLUE,
        "none": Fore.WHITE,
    }
    return colors.get(severity.lower(), Fore.WHITE)


def format_report_summary(report: dict) -> str:
    """Format a report as a colored summary string."""
    severity = report.get("severity", "unknown")
    color = severity_color(severity)
    return (
        f"{color}[{severity.upper()}]{Style.RESET_ALL} "
        f"{report.get('title', 'Untitled')} "
        f"{Fore.CYAN}({report.get('platform', 'unknown')}){Style.RESET_ALL} "
        f"- {report.get('category', 'unknown')}"
    )


def chunk_list(lst: list, chunk_size: int) -> list:
    """Split a list into chunks of given size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def normalize_category(category: str) -> str:
    """Normalize vulnerability category name."""
    mappings = {
        "server-side request forgery": "ssrf",
        "server side request forgery": "ssrf",
        "cross-site scripting": "xss",
        "cross site scripting": "xss",
        "sql injection": "sqli",
        "sql-injection": "sqli",
        "insecure direct object reference": "idor",
        "insecure direct object references": "idor",
        "remote code execution": "rce",
        "remote-code-execution": "rce",
        "local file inclusion": "lfi",
        "local-file-inclusion": "lfi",
        "xml external entity": "xxe",
        "xml-external-entity": "xxe",
        "cross-site request forgery": "csrf",
        "cross site request forgery": "csrf",
        "open redirect": "open_redirect",
        "open-redirect": "open_redirect",
        "business logic": "business_logic",
        "business-logic": "business_logic",
    }
    normalized = category.lower().strip()
    return mappings.get(normalized, normalized.replace(" ", "_").replace("-", "_"))
