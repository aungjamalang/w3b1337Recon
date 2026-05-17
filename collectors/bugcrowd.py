"""Bugcrowd report collector."""

import re
import json
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class BugcrowdCollector(BaseCollector):
    """Collector for Bugcrowd disclosed reports."""

    PLATFORM_NAME = "bugcrowd"
    CROWDSTREAM_URL = "https://bugcrowd.com/crowdstream"
    DISCLOSURES_URL = "https://bugcrowd.com/disclosures"

    VRT_CATEGORY_MAP = {
        "Server-Side Request Forgery": "ssrf",
        "Cross-Site Scripting": "xss",
        "SQL Injection": "sqli",
        "Insecure Direct Object Reference": "idor",
        "Broken Access Control": "idor",
        "Remote Code Execution": "rce",
        "Local File Inclusion": "lfi",
        "XML External Entity": "xxe",
        "Cross-Site Request Forgery": "csrf",
        "Open Redirect": "open_redirect",
        "Business Logic": "business_logic",
        "Authentication Bypass": "auth_bypass",
        "Information Disclosure": "info_disclosure",
        "Privilege Escalation": "privilege_escalation",
    }

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)

    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """Collect disclosed reports from Bugcrowd."""
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        start_page = checkpoint["last_page"] + 1 if checkpoint else 1
        collected = checkpoint["total_collected"] if checkpoint else 0

        self.logger.info(f"Collecting Bugcrowd reports (limit={limit}, start_page={start_page})")

        page = start_page
        while collected < limit:
            try:
                batch = await self._fetch_disclosures_page(page)
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
                self.logger.error(f"Error fetching Bugcrowd page {page}: {e}")
                break

        self.logger.info(f"Collected {len(reports)} reports from Bugcrowd")
        return reports

    async def _fetch_disclosures_page(self, page: int) -> List[Dict[str, Any]]:
        """Fetch a page of Bugcrowd disclosures."""
        # Try API-style endpoint
        url = f"{self.DISCLOSURES_URL}.json"
        params = {"page": str(page), "sort": "newest"}

        try:
            resp = await self.http_client.get(url, params=params)
            if resp.status == 200 and resp.json_data:
                return resp.json_data if isinstance(resp.json_data, list) else resp.json_data.get("results", [])
        except Exception:
            pass

        # Fallback: scrape HTML
        return await self._scrape_disclosures(page)

    async def _scrape_disclosures(self, page: int) -> List[Dict[str, Any]]:
        """Scrape Bugcrowd disclosures page."""
        url = f"{self.DISCLOSURES_URL}?page={page}&sort=newest"
        resp = await self.http_client.get(url)

        if resp.status != 200:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        results = []

        # Parse disclosure cards
        cards = soup.find_all("div", class_=re.compile(r"disclosure|submission"))
        if not cards:
            cards = soup.find_all("tr", class_=re.compile(r"disclosure|submission"))

        for card in cards:
            title_elem = card.find(["a", "h3", "h4", "span"], class_=re.compile(r"title|heading"))
            link_elem = card.find("a", href=re.compile(r"/disclosures/"))

            if title_elem or link_elem:
                disclosure = {
                    "title": (title_elem or link_elem).get_text(strip=True),
                    "url": "",
                    "severity": "",
                    "vrt": "",
                    "researcher": "",
                    "program": "",
                }

                if link_elem:
                    href = link_elem.get("href", "")
                    disclosure["url"] = f"https://bugcrowd.com{href}" if href.startswith("/") else href

                # Extract severity
                severity_elem = card.find(class_=re.compile(r"severity|priority"))
                if severity_elem:
                    disclosure["severity"] = severity_elem.get_text(strip=True).lower()

                # Extract VRT category
                vrt_elem = card.find(class_=re.compile(r"vrt|category|vulnerability"))
                if vrt_elem:
                    disclosure["vrt"] = vrt_elem.get_text(strip=True)

                results.append(disclosure)

        return results

    def _parse_disclosure(self, item: Dict[str, Any]) -> Optional[Report]:
        """Parse a Bugcrowd disclosure into a Report."""
        title = item.get("title", "")
        if not title:
            return None

        vrt = item.get("vrt", "") or item.get("vulnerability_type", "")
        category = "unknown"
        for key, val in self.VRT_CATEGORY_MAP.items():
            if key.lower() in vrt.lower():
                category = val
                break
        if category == "unknown":
            category = normalize_category(vrt) if vrt else "unknown"

        metadata = ReportMetadata(
            title=title,
            category=category,
            severity=item.get("severity", "unknown") or item.get("priority", "unknown"),
            platform="bugcrowd",
            url=item.get("url", ""),
            bounty_amount=float(item.get("amount", 0) or 0),
            researcher=item.get("researcher", "") or item.get("username", ""),
            disclosed_date=item.get("disclosed_at") or item.get("created_at"),
            program=item.get("program", "") or item.get("program_name", ""),
        )

        return Report(
            id=item.get("id", item.get("uuid", "")),
            metadata=metadata,
            raw_content=json.dumps(item, default=str),
        )

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from a Bugcrowd disclosure URL."""
        resp = await self.http_client.get(url)
        if resp.status != 200:
            return ReportMetadata(url=url, platform="bugcrowd")

        soup = BeautifulSoup(resp.text, "html.parser")

        title = ""
        title_tag = soup.find("h1") or soup.find("h2")
        if title_tag:
            title = title_tag.get_text(strip=True)

        severity = ""
        sev_elem = soup.find(class_=re.compile(r"severity|priority"))
        if sev_elem:
            severity = sev_elem.get_text(strip=True).lower()

        return ReportMetadata(
            title=title,
            severity=severity,
            platform="bugcrowd",
            url=url,
        )
