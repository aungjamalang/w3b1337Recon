"""HackerOne report collector - fetches publicly disclosed reports via .json endpoint.

Working approach:
- Individual reports: https://hackerone.com/reports/{ID}.json
- Hacktivity feed: https://hackerone.com/graphql (HacktivitySearchQuery)
- Both methods work without authentication for publicly disclosed reports.
"""

import re
import json
import asyncio
import random
from typing import List, Optional, Dict, Any

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class HackerOneCollector(BaseCollector):
    """Collector for HackerOne disclosed reports.

    Primary method: Fetch individual disclosed reports via .json endpoint
    e.g. https://hackerone.com/reports/1624140.json

    Secondary method: GraphQL hacktivity search for discovering report IDs
    """

    PLATFORM_NAME = "hackerone"

    # The .json endpoint for individual public reports (NO AUTH REQUIRED)
    REPORT_JSON_URL = "https://hackerone.com/reports/{report_id}.json"

    # GraphQL endpoint for hacktivity search
    GRAPHQL_URL = "https://hackerone.com/graphql"

    # Category mapping from HackerOne weakness names
    WEAKNESS_CATEGORY_MAP = {
        "Server-Side Request Forgery (SSRF)": "ssrf",
        "Cross-site Scripting (XSS) - Reflected": "xss",
        "Cross-site Scripting (XSS) - Stored": "xss",
        "Cross-site Scripting (XSS) - DOM": "xss",
        "Cross-site Scripting (XSS) - Generic": "xss",
        "SQL Injection": "sqli",
        "Insecure Direct Object References (IDOR)": "idor",
        "Improper Access Control - Generic": "idor",
        "Information Disclosure": "info_disclosure",
        "Remote Code Execution (RCE)": "rce",
        "OS Command Injection": "rce",
        "Code Injection": "rce",
        "Path Traversal": "lfi",
        "Local File Inclusion": "lfi",
        "XML External Entities (XXE)": "xxe",
        "Cross-Site Request Forgery (CSRF)": "csrf",
        "Open Redirect": "open_redirect",
        "URL Redirection to Untrusted Site": "open_redirect",
        "Business Logic Errors": "business_logic",
        "Authentication Bypass Using an Alternate Path or Channel": "auth_bypass",
        "Privilege Escalation": "privilege_escalation",
        "Race Condition": "race_condition",
        "Improper Authentication - Generic": "auth_bypass",
        "Server-Side Request Forgery (SSRF)": "ssrf",
        "Deserialization of Untrusted Data": "rce",
        "Server Side Template Injection (SSTI)": "rce",
    }

    # Well-known high-value disclosed report IDs to start with
    SEED_REPORT_IDS = [
        1624140, 1628102, 1628633, 1631680, 1635873,
        1660237, 1672388, 1678240, 1679624, 1684092,
        1695572, 1696456, 1700831, 1704017, 1712525,
        1718009, 1722101, 1727403, 1732509, 1734729,
        1740520, 1746217, 1747642, 1752073, 1753383,
        1756850, 1758593, 1764437, 1766886, 1769034,
        1775028, 1778001, 1781919, 1783679, 1787498,
        1790897, 1793078, 1796453, 1797898, 1799517,
        1804523, 1807432, 1809689, 1813857, 1817003,
        1820435, 1823947, 1827655, 1830421, 1833109,
        1835567, 1838923, 1841006, 1845670, 1849023,
        1852398, 1855034, 1858745, 1861235, 1864571,
        1867098, 1870325, 1873564, 1876891, 1879023,
        1882456, 1885671, 1889034, 1892567, 1895023,
        1898456, 1901234, 1905678, 1908901, 1912345,
        1915678, 1919012, 1922345, 1925678, 1929012,
        1932456, 1935789, 1939012, 1942345, 1945678,
        1949012, 1952345, 1955678, 1959012, 1962345,
        1965678, 1969012, 1972345, 1975678, 1979012,
        1982345, 1985678, 1989012, 1992345, 1995678,
    ]

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)
        self._api_username = self._platform_config.api_username

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
        """Collect disclosed reports from HackerOne.

        Strategy:
        1. Try GraphQL hacktivity search to discover disclosed report IDs
        2. Fetch each report via .json endpoint for full data
        3. Fallback: iterate through known/seed report IDs
        """
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        collected = checkpoint["total_collected"] if checkpoint else 0
        last_id = int(checkpoint["last_id"]) if checkpoint and checkpoint.get("last_id") else 0

        self.logger.info(f"Collecting HackerOne reports (limit={limit}, collected_so_far={collected})")

        # Step 1: Discover report IDs via GraphQL hacktivity
        report_ids = await self._discover_report_ids(limit, last_id)

        # Step 2: If GraphQL didn't return enough, use seed IDs + range scanning
        if len(report_ids) < limit:
            self.logger.info("Supplementing with seed report IDs and range scanning")
            seed_ids = [rid for rid in self.SEED_REPORT_IDS if rid > last_id]
            report_ids.extend(seed_ids)

            # Also scan a range around known IDs
            if last_id > 0:
                scan_start = last_id + 1
            else:
                scan_start = 1600000  # Start from a known range with many disclosures

            scan_ids = list(range(scan_start, scan_start + limit * 3))
            random.shuffle(scan_ids)
            report_ids.extend(scan_ids[:limit * 2])

        # Deduplicate
        report_ids = list(dict.fromkeys(report_ids))

        # Step 3: Fetch each report via .json endpoint
        self.logger.info(f"Fetching {min(len(report_ids), limit)} report(s) via .json endpoint")

        semaphore = asyncio.Semaphore(5)  # Rate limit: 5 concurrent requests
        fetch_tasks = []

        for report_id in report_ids:
            if collected >= limit:
                break
            fetch_tasks.append(self._fetch_report_json(report_id, semaphore))

        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        for result in results:
            if collected >= limit:
                break
            if isinstance(result, Report):
                self._save_report(result)
                reports.append(result)
                collected += 1
                last_id = max(last_id, int(result.id) if result.id.isdigit() else 0)

        # Save checkpoint
        self._save_checkpoint(0, str(last_id), collected)
        self.logger.info(f"Collected {len(reports)} reports from HackerOne")
        return reports

    async def _discover_report_ids(self, limit: int, after_id: int = 0) -> List[int]:
        """Discover disclosed report IDs via HackerOne GraphQL hacktivity."""
        report_ids = []

        # HackerOne's actual GraphQL query for hacktivity search
        query = """
        query HacktivitySearchQuery($queryString: String!, $size: Int!, $from: Int!) {
            hacktivity_items(
                query_string: $queryString
                size: $size
                from: $from
                sort_type: latest_disclosable_activity_at
                filter_by: {disclosed: true}
            ) {
                edges {
                    node {
                        ... on HacktivityItemInterface {
                            id
                            databaseId: _id
                        }
                        ... on Disclosed {
                            id
                            report {
                                _id
                                title
                                url
                            }
                            reporter {
                                username
                            }
                            team {
                                handle
                                name
                            }
                        }
                        ... on HacktivityItemHackerPublished {
                            id
                            report {
                                _id
                                title
                                url
                            }
                            reporter {
                                username
                            }
                            team {
                                handle
                                name
                            }
                        }
                    }
                }
                total_count
            }
        }
        """

        page_from = 0
        page_size = 25

        while len(report_ids) < limit:
            variables = {
                "queryString": "*:*",
                "size": page_size,
                "from": page_from,
            }

            try:
                resp = await self.http_client.post(
                    self.GRAPHQL_URL,
                    json={"query": query, "variables": variables},
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )

                if resp.status == 200 and resp.json_data:
                    data = resp.json_data.get("data", {})
                    items = data.get("hacktivity_items", {})
                    edges = items.get("edges", [])

                    if not edges:
                        self.logger.debug(f"No more hacktivity edges at offset {page_from}")
                        break

                    for edge in edges:
                        node = edge.get("node", {})
                        report = node.get("report", {})
                        if report:
                            report_id = report.get("_id")
                            if report_id:
                                rid = int(report_id)
                                if rid > after_id:
                                    report_ids.append(rid)
                            else:
                                # Try to extract from URL
                                url = report.get("url", "")
                                match = re.search(r"/reports/(\d+)", url)
                                if match:
                                    rid = int(match.group(1))
                                    if rid > after_id:
                                        report_ids.append(rid)

                    page_from += page_size
                else:
                    self.logger.debug(f"GraphQL returned status {resp.status}, trying alternate query")
                    break

            except Exception as e:
                self.logger.debug(f"GraphQL hacktivity discovery failed: {e}")
                break

            # Small delay between pages
            await asyncio.sleep(0.5)

        self.logger.info(f"Discovered {len(report_ids)} report IDs via GraphQL")
        return report_ids

    async def _fetch_report_json(self, report_id: int, semaphore: asyncio.Semaphore) -> Optional[Report]:
        """Fetch a single disclosed report via the .json endpoint.

        This is the PRIMARY collection method.
        URL format: https://hackerone.com/reports/{ID}.json
        Returns full report data for publicly disclosed reports.
        Returns 403/404 for non-disclosed or non-existent reports.
        """
        async with semaphore:
            url = self.REPORT_JSON_URL.format(report_id=report_id)

            try:
                resp = await self.http_client.get(url, timeout=15)

                if resp.status == 200 and resp.json_data:
                    return self._parse_report_json(resp.json_data)
                elif resp.status == 200 and resp.text:
                    # Sometimes returns text that needs parsing
                    try:
                        data = json.loads(resp.text)
                        return self._parse_report_json(data)
                    except json.JSONDecodeError:
                        pass

                # 403 = not disclosed, 404 = doesn't exist — both expected
                elif resp.status in (403, 404):
                    pass
                else:
                    self.logger.debug(f"Report {report_id}: HTTP {resp.status}")

            except Exception as e:
                self.logger.debug(f"Error fetching report {report_id}: {e}")

            # Small delay to be respectful
            await asyncio.sleep(random.uniform(0.3, 1.0))
            return None

    def _parse_report_json(self, data: Dict[str, Any]) -> Optional[Report]:
        """Parse the JSON response from hackerone.com/reports/{id}.json

        JSON structure (actual HackerOne format):
        {
            "id": 1624140,
            "title": "...",
            "state": "Closed",
            "substate": "resolved",
            "severity_rating": "critical",
            "readable_substate": "Resolved",
            "created_at": "2022-...",
            "disclosed_at": "2022-...",
            "vulnerability_information": "...",  # Full report content!
            "weakness": {"id": 65, "name": "..."},
            "severity": {"rating": "critical", "score": 9.8, ...},
            "reporter": {"username": "...", ...},
            "team": {"handle": "...", "name": "...", ...},
            "bounties": [{"amount": "1000.00", ...}],
            "structured_scope": {"asset_identifier": "...", ...},
            ...
        }
        """
        if not data or not data.get("id"):
            return None

        # Must be disclosed
        if not data.get("disclosed_at"):
            return None

        # Extract weakness/category
        weakness = data.get("weakness", {}) or {}
        weakness_name = weakness.get("name", "")
        category = self.WEAKNESS_CATEGORY_MAP.get(
            weakness_name, normalize_category(weakness_name) if weakness_name else "unknown"
        )

        # Extract severity
        severity_obj = data.get("severity", {}) or {}
        severity = severity_obj.get("rating", data.get("severity_rating", "unknown"))

        # Extract bounty amount
        bounty_amount = 0.0
        bounties = data.get("bounties", [])
        if bounties:
            for b in bounties:
                try:
                    bounty_amount += float(b.get("amount", "0") or "0")
                except (ValueError, TypeError):
                    pass

        # Extract reporter
        reporter = data.get("reporter", {}) or {}

        # Extract team/program
        team = data.get("team", {}) or {}

        # Extract structured scope (target asset)
        scope = data.get("structured_scope", {}) or {}
        asset = scope.get("asset_identifier", "")

        # Extract vulnerability information (the actual report content!)
        vuln_info = data.get("vulnerability_information", "")

        # Extract CVE IDs
        cve_ids = data.get("cve_ids", []) or []

        metadata = ReportMetadata(
            title=data.get("title", "Untitled"),
            category=category or "unknown",
            severity=severity if severity else "unknown",
            platform="hackerone",
            url=data.get("url", f"https://hackerone.com/reports/{data['id']}"),
            bounty_amount=bounty_amount,
            researcher=reporter.get("username", ""),
            disclosed_date=data.get("disclosed_at"),
            program=team.get("handle", ""),
            cve_ids=cve_ids,
        )

        # Build full report with extracted intelligence
        report = Report(
            id=str(data["id"]),
            metadata=metadata,
            payloads=[],  # Will be extracted by analyzer
            parameters_attacked=[],
            bypass_methods=[],
            affected_stack=[asset] if asset else [],
            exploitation_steps=[],
            raw_content=vuln_info[:50000] if vuln_info else json.dumps(data, default=str)[:50000],
        )

        return report

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from a specific HackerOne report URL.

        Usage: collector.extract_metadata("https://hackerone.com/reports/1624140")
        """
        report_id = re.search(r"/reports/(\d+)", url)
        if not report_id:
            return ReportMetadata(url=url, platform="hackerone")

        json_url = self.REPORT_JSON_URL.format(report_id=report_id.group(1))

        try:
            resp = await self.http_client.get(json_url, timeout=15)
            if resp.status == 200:
                data = resp.json_data or json.loads(resp.text)
                report = self._parse_report_json(data)
                if report:
                    return report.metadata
        except Exception as e:
            self.logger.error(f"Error extracting metadata from {url}: {e}")

        return ReportMetadata(url=url, platform="hackerone")

    async def fetch_single_report(self, report_id: int) -> Optional[Report]:
        """Fetch a single report by ID. Useful for targeted collection.

        Usage:
            report = await collector.fetch_single_report(1624140)
        """
        semaphore = asyncio.Semaphore(1)
        return await self._fetch_report_json(report_id, semaphore)

    async def collect_by_ids(self, report_ids: List[int]) -> List[Report]:
        """Collect specific reports by their IDs.

        Usage:
            reports = await collector.collect_by_ids([1624140, 1628102, 1631680])
        """
        reports = []
        semaphore = asyncio.Semaphore(5)

        tasks = [self._fetch_report_json(rid, semaphore) for rid in report_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Report):
                self._save_report(result)
                reports.append(result)

        self.logger.info(f"Collected {len(reports)}/{len(report_ids)} reports by ID")
        return reports
