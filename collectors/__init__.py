"""Report collection modules for bug bounty platforms."""

from .base import BaseCollector, Report, ReportMetadata
from .hackerone import HackerOneCollector
from .bugcrowd import BugcrowdCollector
from .intigriti import IntigritiCollector
from .yeswehack import YesWeHackCollector
from .github import GitHubCollector

__all__ = [
    "BaseCollector",
    "Report",
    "ReportMetadata",
    "HackerOneCollector",
    "BugcrowdCollector",
    "IntigritiCollector",
    "YesWeHackCollector",
    "GitHubCollector",
]
