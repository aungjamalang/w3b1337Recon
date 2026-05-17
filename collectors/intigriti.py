"""Intigriti report collector."""

import re
import json
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class IntigritiCollector(BaseCollector):
    """Collector for Intigriti disclosed reports."""

    PLATFORM_NAME = "intigriti"
    DISCLOSURES_URL = "https://app.intigriti.com/researcher/disclosures"

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)

    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """Collect disclosed reports from Intigriti."""
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        start_page = checkpoint["last_page"] + 1 if checkpoint else 1
        collected = checkpoint["total_collected"] if checkpoint else 0

        self.logger.info(f"Collecting Intigriti reports (limit={limit})")

        page = start_page
        while collected < limit:
            try:
                batch = await self._fetch_page(page)
                if not batch:
                    break

                for item in batch:
                    if collected >= limit:
                        break

                    report = self._parse_disclosure(item)
                    if report:
                        self._save_report(report)
                        reports.append(report)
                        collected += 1

                self._save_checkpoint(page, str(page), collected)
                page += 1

            except Exception as e:
                self.logger.error(f"Error fetching Intigriti page {page}: {e}")
                break

        self.logger.info(f"Collected {len(reports)} reports from Intigriti")
        return reports

    async def _fetch_page(self, page: int) -> List[Dict[str, Any]]:
        """Fetch a page of Intigriti disclosures."""
        # Try API endpoint
        api_url = f"{self.base_url}/api/researcher/disclosures"
        params = {"page": str(page), "pageSize": "25", "orderBy": "dateCreated", "orderDirection": "desc"}

        headers = {}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        try:
            resp = await self.http_client.get(api_url, params=params, headers=headers)
            if resp.status == 200 and resp.json_data:
                records = resp.json_data
                if isinstance(records, dict):
                    records = records.get("records", []) or records.get("items", [])
                return records
        except Exception:
            pass

        # Fallback: scrape HTML
        return await self._scrape_page(page)

    async def _scrape_page(self, page: int) -> List[Dict[str, Any]]:
        """Scrape Intigriti disclosures page."""
        url = f"{self.DISCLOSURES_URL}?page={page}"
        resp = await self.http_client.get(url)

        if resp.status != 200:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        results = []

        cards = soup.find_all("div", class_=re.compile(r"disclosure|submission|card"))
        for card in cards:
            title_elem = card.find(["a", "h3", "h4", "span"], class_=re.compile(r"title|name"))
            if title_elem:
                disclosure = {
                    "title": title_elem.get_text(strip=True),
                    "url": "",
                    "severity": "",
                    "category": "",
                    "researcher": "",
                }

                link = card.find("a", href=True)
                if link:
                    href = link.get("href", "")
                    disclosure["url"] = href if href.startswith("http") else f"{self.base_url}{href}"

                sev_elem = card.find(class_=re.compile(r"severity|rating"))
                if sev_elem:
                    disclosure["severity"] = sev_elem.get_text(strip=True).lower()

                results.append(disclosure)

        return results

    def _parse_disclosure(self, item: Dict[str, Any]) -> Optional[Report]:
        """Parse an Intigriti disclosure item into a Report."""
        title = item.get("title", "") or item.get("name", "")
        if not title:
            return None

        raw_category = item.get("category", "") or item.get("vulnerabilityType", "") or item.get("type", "")
        category = normalize_category(raw_category) if raw_category else "unknown"

        severity_map = {"1": "low", "2": "medium", "3": "high", "4": "critical"}
        severity = item.get("severity", "unknown")
        if isinstance(severity, (int, float)):
            severity = severity_map.get(str(int(severity)), "unknown")

        metadata = ReportMetadata(
            title=title,
            category=category,
            severity=str(severity).lower(),
            platform="intigriti",
            url=item.get("url", ""),
            bounty_amount=float(item.get("reward", 0) or item.get("bounty", 0) or 0),
            researcher=item.get("researcher", "") or item.get("researcherUsername", ""),
            disclosed_date=item.get("disclosedAt") or item.get("dateCreated"),
            program=item.get("program", "") or item.get("companyHandle", ""),
        )

        return Report(
            id=item.get("id", item.get("submissionId", "")),
            metadata=metadata,
            raw_content=json.dumps(item, default=str),
        )

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from an Intigriti disclosure URL."""
        resp = await self.http_client.get(url)
        if resp.status != 200:
            return ReportMetadata(url=url, platform="intigriti")

        soup = BeautifulSoup(resp.text, "html.parser")
        title = ""
        title_tag = soup.find("h1") or soup.find("h2")
        if title_tag:
            title = title_tag.get_text(strip=True)

        return ReportMetadata(
            title=title,
            platform="intigriti",
            url=url,
        )
