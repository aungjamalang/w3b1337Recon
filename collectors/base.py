"""Base collector class and data models for report collection."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage


@dataclass
class ReportMetadata:
    """Metadata extracted from a bug report."""
    title: str = ""
    category: str = "unknown"
    severity: str = "unknown"
    platform: str = "unknown"
    url: str = ""
    bounty_amount: float = 0.0
    researcher: str = ""
    disclosed_date: Optional[str] = None
    program: str = ""
    state: str = ""
    cve_ids: List[str] = field(default_factory=list)


@dataclass
class Report:
    """Full bug bounty report with extracted data."""
    id: str = ""
    metadata: ReportMetadata = field(default_factory=ReportMetadata)
    payloads: List[str] = field(default_factory=list)
    parameters_attacked: List[str] = field(default_factory=list)
    bypass_methods: List[str] = field(default_factory=list)
    affected_stack: List[str] = field(default_factory=list)
    recon_patterns: List[str] = field(default_factory=list)
    exploitation_steps: List[str] = field(default_factory=list)
    raw_content: str = ""
    collected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "id": self.id,
            "title": self.metadata.title,
            "category": self.metadata.category,
            "severity": self.metadata.severity,
            "platform": self.metadata.platform,
            "url": self.metadata.url,
            "bounty_amount": self.metadata.bounty_amount,
            "researcher": self.metadata.researcher,
            "disclosed_date": self.metadata.disclosed_date,
            "program": self.metadata.program,
            "payloads": self.payloads,
            "parameters_attacked": self.parameters_attacked,
            "bypass_methods": self.bypass_methods,
            "affected_stack": self.affected_stack,
            "recon_patterns": self.recon_patterns,
            "exploitation_steps": self.exploitation_steps,
            "collected_at": self.collected_at,
        }


class BaseCollector(ABC):
    """Abstract base class for all platform collectors."""

    PLATFORM_NAME: str = "unknown"

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        self.config = config
        self.http_client = http_client
        self.storage = storage
        self.logger = logging.getLogger(f"bugrecon.collector.{self.PLATFORM_NAME}")
        self._platform_config = config.get_platform(self.PLATFORM_NAME)

    @abstractmethod
    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """
        Collect reports from the platform.

        Args:
            limit: Maximum number of reports to collect
            resume: Whether to resume from last checkpoint

        Returns:
            List of collected Report objects
        """
        pass

    @abstractmethod
    async def extract_metadata(self, url: str) -> ReportMetadata:
        """
        Extract metadata from a specific report URL.

        Args:
            url: The report URL

        Returns:
            ReportMetadata object with extracted fields
        """
        pass

    async def authenticate(self) -> bool:
        """
        Authenticate with the platform API (if required).

        Returns:
            True if authentication was successful
        """
        if not self._platform_config.api_token:
            self.logger.warning(f"No API token configured for {self.PLATFORM_NAME}")
            return False
        return True

    def _get_checkpoint(self) -> Optional[Dict[str, Any]]:
        """Get the last checkpoint for this collector."""
        return self.storage.get_checkpoint(self.PLATFORM_NAME)

    def _save_checkpoint(self, page: int, last_id: Optional[str] = None, total: int = 0):
        """Save collection progress."""
        self.storage.save_checkpoint(self.PLATFORM_NAME, page, last_id, total)

    def _save_report(self, report: Report) -> str:
        """Save a report to storage."""
        return self.storage.add_report(report.to_dict())

    def _is_enabled(self) -> bool:
        """Check if this collector is enabled in config."""
        return self._platform_config.enabled

    @property
    def base_url(self) -> str:
        """Get the platform base URL."""
        return self._platform_config.base_url

    @property
    def api_token(self) -> Optional[str]:
        """Get the API token."""
        return self._platform_config.api_token
