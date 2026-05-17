"""HackerOne report collector - scrapes disclosed reports and uses API."""

import re
import json
from typing import List, Optional, Dict, Any
from bs4 import BeautifulSoup

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class HackerOneCollector(BaseCollector):
    """Collector for HackerOne disclosed reports."""

    PLATFORM_NAME = "hackerone"

    # Known disclosed report listing endpoints
    HACKTIVITY_URL = "https://hackerone.com/hacktivity"
    GRAPHQL_URL = "https://hackerone.com/graphql"
    DISCLOSED_URL = "https://hackerone.com/reports/{report_id}.json"

    # Category mapping from HackerOne weakness types
    WEAKNESS_CATEGORY_MAP = {
        "Server-Side Request Forgery (SSRF)": "ssrf",
        "Cross-site Scripting (XSS)": "xss",
        "Reflected XSS": "xss",
        "Stored XSS": "xss",
        "DOM-Based XSS": "xss",
        "SQL Injection": "sqli",
        "Insecure Direct Object References (IDOR)": "idor",
        "Information Disclosure": "info_disclosure",
        "Remote Code Execution": "rce",
        "Path Traversal": "lfi",
        "XML External Entities (XXE)": "xxe",
        "Cross-Site Request Forgery (CSRF)": "csrf",
        "Open Redirect": "open_redirect",
        "Business Logic Errors": "business_logic",
        "Authentication Bypass": "auth_bypass",
        "Privilege Escalation": "privilege_escalation",
        "Race Condition": "race_condition",
    }

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)
        self._api_username = self._platform_config.api_username

    async def authenticate(self) -> bool:
        """Verify HackerOne API credentials."""
        if not self.api_token or not self._api_username:
            self.logger.info("No HackerOne API credentials - using public scraping mode")
            return False

        # Test API access
        try:
            resp = await self.http_client.get(
                "https://api.hackerone.com/v1/me",
                headers=self._get_auth_headers(),
            )
            return resp.status == 200
        except Exception as e:
            self.logger.error(f"HackerOne auth failed: {e}")
            return False

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        import base64
        if self.api_token and self._api_username:
            creds = base64.b64encode(
                f"{self._api_username}:{self.api_token}".encode()
            ).decode()
            return {"Authorization": f"Basic {creds}"}
        return {}

    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """Collect disclosed reports from HackerOne hacktivity."""
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        start_page = checkpoint["last_page"] if checkpoint else 0
        collected = checkpoint["total_collected"] if checkpoint else 0

        self.logger.info(f"Collecting HackerOne reports (limit={limit}, resume_page={start_page})")

        # Use GraphQL endpoint for hacktivity
        page_cursor = None
        page = start_page

        while collected < limit:
            try:
                batch = await self._fetch_hacktivity_page(page_cursor)
                if not batch:
                    break

                for item in batch.get("nodes", []):
                    if collected >= limit:
                        break

                    report = self._parse_hacktivity_node(item)
                    if report:
                        self._save_report(report)
                        reports.append(report)
                        collected += 1

                # Get next page cursor
                page_info = batch.get("pageInfo", {})
                if not page_info.get("hasNextPage"):
                    break
                page_cursor = page_info.get("endCursor")
                page += 1

                # Save checkpoint
                self._save_checkpoint(page, page_cursor, collected)

            except Exception as e:
                self.logger.error(f"Error fetching page {page}: {e}")
                break

        self.logger.info(f"Collected {len(reports)} reports from HackerOne")
        return reports

    async def _fetch_hacktivity_page(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        """Fetch a page of hacktivity using GraphQL."""
        query = """
        query HacktivityPageQuery($cursor: String, $count: Int!) {
            hacktivity_items(first: $count, after: $cursor, 
                where: {report: {disclosed_at: {_is_null: false}}},
                order_by: {field: popular, direction: DESC}) {
                nodes {
                    ... on HacktivityItemInterface {
                        id
                        type
                    }
                    ... on Disclosed {
                        id
                        reporter { username }
                        team { handle, name }
                        report {
                            id
                            title
                            substate
                            url
                            severity_rating
                            weakness { name }
                            bounty_amount
                            disclosed_at
                            created_at
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """
        variables = {"count": 25, "cursor": cursor}

        try:
            resp = await self.http_client.post(
                self.GRAPHQL_URL,
                json={"query": query, "variables": variables},
                headers={"Content-Type": "application/json"},
            )

            if resp.status == 200 and resp.json_data:
                data = resp.json_data.get("data", {})
                return data.get("hacktivity_items", {})
        except Exception as e:
            self.logger.debug(f"GraphQL failed, falling back to scraping: {e}")

        # Fallback: scrape hacktivity page
        return await self._scrape_hacktivity(cursor)

    async def _scrape_hacktivity(self, cursor: Optional[str] = None) -> Dict[str, Any]:
        """Fallback scraper for hacktivity page."""
        url = f"{self.HACKTIVITY_URL}?type=hackerone"
        if cursor:
            url += f"&cursor={cursor}"

        resp = await self.http_client.get(url)
        if resp.status != 200:
            return {}

        # Parse HTML for report links
        soup = BeautifulSoup(resp.text, "html.parser")
        nodes = []

        # Find report cards/links
        report_links = soup.find_all("a", href=re.compile(r"/reports/\d+"))
        for link in report_links:
            report_id = re.search(r"/reports/(\d+)", link.get("href", ""))
            if report_id:
                nodes.append({
                    "report": {
                        "id": report_id.group(1),
                        "url": f"https://hackerone.com/reports/{report_id.group(1)}",
                        "title": link.get_text(strip=True) or f"Report #{report_id.group(1)}",
                    }
                })

        return {"nodes": nodes, "pageInfo": {"hasNextPage": bool(nodes), "endCursor": None}}

    def _parse_hacktivity_node(self, node: Dict[str, Any]) -> Optional[Report]:
        """Parse a hacktivity node into a Report object."""
        report_data = node.get("report", node)
        if not report_data:
            return None

        weakness = report_data.get("weakness", {}) or {}
        weakness_name = weakness.get("name", "")
        category = self.WEAKNESS_CATEGORY_MAP.get(weakness_name, normalize_category(weakness_name))

        severity = report_data.get("severity_rating", "unknown")
        reporter = node.get("reporter", {}) or {}

        metadata = ReportMetadata(
            title=report_data.get("title", "Untitled"),
            category=category or "unknown",
            severity=severity if severity else "unknown",
            platform="hackerone",
            url=report_data.get("url", ""),
            bounty_amount=float(report_data.get("bounty_amount", 0) or 0),
            researcher=reporter.get("username", ""),
            disclosed_date=report_data.get("disclosed_at"),
            program=(node.get("team", {}) or {}).get("handle", ""),
        )

        report = Report(
            id=str(report_data.get("id", "")),
            metadata=metadata,
            raw_content=json.dumps(node, default=str),
        )

        return report

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from a specific HackerOne report URL."""
        # Try JSON endpoint first
        report_id = re.search(r"/reports/(\d+)", url)
        if report_id:
            json_url = self.DISCLOSED_URL.format(report_id=report_id.group(1))
            try:
                resp = await self.http_client.get(json_url)
                if resp.status == 200 and resp.json_data:
                    return self._parse_json_report(resp.json_data)
            except Exception:
                pass

        # Fallback: scrape HTML
        resp = await self.http_client.get(url)
        if resp.status == 200:
            return self._parse_html_report(resp.text, url)

        return ReportMetadata(url=url, platform="hackerone")

    def _parse_json_report(self, data: Dict[str, Any]) -> ReportMetadata:
        """Parse a HackerOne JSON report response."""
        weakness = data.get("weakness", {}) or {}
        weakness_name = weakness.get("name", "")

        return ReportMetadata(
            title=data.get("title", ""),
            category=self.WEAKNESS_CATEGORY_MAP.get(weakness_name, normalize_category(weakness_name)),
            severity=data.get("severity", {}).get("rating", "unknown") if data.get("severity") else "unknown",
            platform="hackerone",
            url=data.get("url", ""),
            bounty_amount=float(data.get("formatted_bounty", "0").replace("$", "").replace(",", "") or 0),
            researcher=data.get("reporter", {}).get("username", "") if data.get("reporter") else "",
            disclosed_date=data.get("disclosed_at"),
            program=data.get("team", {}).get("handle", "") if data.get("team") else "",
            cve_ids=data.get("cve_ids", []),
        )

    def _parse_html_report(self, html: str, url: str) -> ReportMetadata:
        """Parse metadata from HackerOne report HTML."""
        soup = BeautifulSoup(html, "html.parser")

        title = ""
        title_tag = soup.find("h1") or soup.find("title")
        if title_tag:
            title = title_tag.get_text(strip=True)

        return ReportMetadata(
            title=title,
            platform="hackerone",
            url=url,
        )
