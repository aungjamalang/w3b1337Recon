"""YesWeHack report collector."""

import re
import json
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class YesWeHackCollector(BaseCollector):
    """Collector for YesWeHack disclosed reports."""

    PLATFORM_NAME = "yeswehack"
    REPORTS_URL = "https://yeswehack.com/reports"

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)

    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """Collect disclosed reports from YesWeHack."""
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        start_page = checkpoint["last_page"] + 1 if checkpoint else 1
        collected = checkpoint["total_collected"] if checkpoint else 0

        self.logger.info(f"Collecting YesWeHack reports (limit={limit})")

        page = start_page
        while collected < limit:
            try:
                batch = await self._fetch_page(page)
                if not batch:
                    break

                for item in batch:
                    if collected >= limit:
                        break

                    report = self._parse_report(item)
                    if report:
                        self._save_report(report)
                        reports.append(report)
                        collected += 1

                self._save_checkpoint(page, str(page), collected)
                page += 1

            except Exception as e:
                self.logger.error(f"Error fetching YesWeHack page {page}: {e}")
                break

        self.logger.info(f"Collected {len(reports)} reports from YesWeHack")
        return reports

    async def _fetch_page(self, page: int) -> List[Dict[str, Any]]:
        """Fetch a page of YesWeHack reports."""
        # Try API first
        api_url = f"{self.base_url}/api/reports"
        params = {"page": str(page), "perPage": "25"}

        headers = {}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        try:
            resp = await self.http_client.get(api_url, params=params, headers=headers)
            if resp.status == 200 and resp.json_data:
                data = resp.json_data
                if isinstance(data, dict):
                    return data.get("items", []) or data.get("reports", [])
                return data
        except Exception:
            pass

        # Fallback scraping
        return await self._scrape_page(page)

    async def _scrape_page(self, page: int) -> List[Dict[str, Any]]:
        """Scrape YesWeHack reports page."""
        url = f"{self.REPORTS_URL}?page={page}"
        resp = await self.http_client.get(url)

        if resp.status != 200:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        results = []

        cards = soup.find_all("div", class_=re.compile(r"report|card|item"))
        for card in cards:
            title_elem = card.find(["a", "h3", "h4", "span"], class_=re.compile(r"title|report"))
            if title_elem:
                report = {
                    "title": title_elem.get_text(strip=True),
                    "url": "",
                    "severity": "",
                    "category": "",
                }

                link = card.find("a", href=re.compile(r"/reports/"))
                if link:
                    href = link.get("href", "")
                    report["url"] = href if href.startswith("http") else f"{self.base_url}{href}"

                sev_elem = card.find(class_=re.compile(r"severity|cvss"))
                if sev_elem:
                    report["severity"] = sev_elem.get_text(strip=True).lower()

                results.append(report)

        return results

    def _parse_report(self, item: Dict[str, Any]) -> Optional[Report]:
        """Parse a YesWeHack report item."""
        title = item.get("title", "")
        if not title:
            return None

        raw_cat = item.get("category", "") or item.get("bug_type", "") or item.get("vulnerability_type", "")
        category = normalize_category(raw_cat) if raw_cat else "unknown"

        severity = item.get("severity", "unknown") or item.get("criticity", "unknown")
        if isinstance(severity, (int, float)):
            if severity >= 9:
                severity = "critical"
            elif severity >= 7:
                severity = "high"
            elif severity >= 4:
                severity = "medium"
            else:
                severity = "low"

        metadata = ReportMetadata(
            title=title,
            category=category,
            severity=str(severity).lower(),
            platform="yeswehack",
            url=item.get("url", ""),
            bounty_amount=float(item.get("reward", 0) or item.get("bounty", 0) or 0),
            researcher=item.get("hunter", {}).get("username", "") if isinstance(item.get("hunter"), dict) else item.get("hunter", ""),
            disclosed_date=item.get("disclosed_at") or item.get("closed_at"),
            program=item.get("program", {}).get("title", "") if isinstance(item.get("program"), dict) else item.get("program", ""),
        )

        return Report(
            id=str(item.get("id", "")),
            metadata=metadata,
            raw_content=json.dumps(item, default=str),
        )

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from a YesWeHack report URL."""
        resp = await self.http_client.get(url)
        if resp.status != 200:
            return ReportMetadata(url=url, platform="yeswehack")

        soup = BeautifulSoup(resp.text, "html.parser")
        title = ""
        title_tag = soup.find("h1") or soup.find("h2")
        if title_tag:
            title = title_tag.get_text(strip=True)

        return ReportMetadata(title=title, platform="yeswehack", url=url)
