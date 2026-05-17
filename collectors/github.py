"""GitHub collector - collects security research from repos and issues."""

import re
import json
from typing import List, Optional, Dict, Any

from .base import BaseCollector, Report, ReportMetadata
from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import normalize_category


class GitHubCollector(BaseCollector):
    """Collector for GitHub security research repos, issues, and advisories."""

    PLATFORM_NAME = "github"
    API_BASE = "https://api.github.com"

    # Repos known for security research and payloads
    DEFAULT_REPOS = [
        "projectdiscovery/nuclei-templates",
        "swisskyrepo/PayloadsAllTheThings",
        "portswigger/research",
        "AkamaiDeveloper/akamai-security",
    ]

    # Search queries for bug bounty write-ups
    SEARCH_QUERIES = [
        "bug bounty writeup",
        "security vulnerability disclosure",
        "responsible disclosure",
        "HackerOne report",
    ]

    def __init__(self, config: Config, http_client: AsyncHTTPClient, storage: Storage):
        super().__init__(config, http_client, storage)
        self._search_repos = self._platform_config.search_repos or self.DEFAULT_REPOS

    def _get_headers(self) -> Dict[str, str]:
        """Get GitHub API headers."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.api_token:
            headers["Authorization"] = f"token {self.api_token}"
        return headers

    async def collect(self, limit: int = 100, resume: bool = True) -> List[Report]:
        """Collect security research from GitHub."""
        reports = []
        checkpoint = self._get_checkpoint() if resume else None
        collected = checkpoint["total_collected"] if checkpoint else 0

        self.logger.info(f"Collecting GitHub security research (limit={limit})")

        # Collect from security advisories
        advisory_reports = await self._collect_advisories(limit - collected)
        reports.extend(advisory_reports)
        collected += len(advisory_reports)

        # Collect from known repos (issues with security labels)
        if collected < limit:
            for repo in self._search_repos[:3]:
                if collected >= limit:
                    break
                repo_reports = await self._collect_repo_issues(repo, limit - collected)
                reports.extend(repo_reports)
                collected += len(repo_reports)

        # Collect from code search (writeups)
        if collected < limit:
            search_reports = await self._search_writeups(limit - collected)
            reports.extend(search_reports)
            collected += len(search_reports)

        self._save_checkpoint(0, None, collected)
        self.logger.info(f"Collected {len(reports)} items from GitHub")
        return reports

    async def _collect_advisories(self, limit: int) -> List[Report]:
        """Collect from GitHub Security Advisories."""
        reports = []
        url = f"{self.API_BASE}/advisories"
        params = {
            "per_page": str(min(limit, 100)),
            "type": "reviewed",
            "order": "updated",
            "direction": "desc",
        }

        try:
            resp = await self.http_client.get(url, headers=self._get_headers(), params=params)
            if resp.status == 200 and resp.json_data:
                for adv in resp.json_data[:limit]:
                    report = self._parse_advisory(adv)
                    if report:
                        self._save_report(report)
                        reports.append(report)
        except Exception as e:
            self.logger.error(f"Error fetching GitHub advisories: {e}")

        return reports

    async def _collect_repo_issues(self, repo: str, limit: int) -> List[Report]:
        """Collect security-related issues from a repository."""
        reports = []
        url = f"{self.API_BASE}/repos/{repo}/issues"
        params = {
            "per_page": str(min(limit, 100)),
            "state": "closed",
            "labels": "security,vulnerability,bug",
            "sort": "updated",
            "direction": "desc",
        }

        try:
            resp = await self.http_client.get(url, headers=self._get_headers(), params=params)
            if resp.status == 200 and resp.json_data:
                for issue in resp.json_data[:limit]:
                    report = self._parse_issue(issue, repo)
                    if report:
                        self._save_report(report)
                        reports.append(report)
        except Exception as e:
            self.logger.debug(f"Error fetching issues from {repo}: {e}")

        return reports

    async def _search_writeups(self, limit: int) -> List[Report]:
        """Search GitHub for bug bounty writeups."""
        reports = []

        for query in self.SEARCH_QUERIES[:2]:
            if len(reports) >= limit:
                break

            url = f"{self.API_BASE}/search/repositories"
            params = {
                "q": f"{query} language:markdown",
                "sort": "updated",
                "per_page": str(min(limit - len(reports), 30)),
            }

            try:
                resp = await self.http_client.get(url, headers=self._get_headers(), params=params)
                if resp.status == 200 and resp.json_data:
                    items = resp.json_data.get("items", [])
                    for item in items:
                        report = self._parse_search_result(item)
                        if report:
                            reports.append(report)
            except Exception as e:
                self.logger.debug(f"Error searching GitHub: {e}")

        return reports

    def _parse_advisory(self, adv: Dict[str, Any]) -> Optional[Report]:
        """Parse a GitHub Security Advisory."""
        title = adv.get("summary", "")
        if not title:
            return None

        # Map CWE to category
        cwes = adv.get("cwes", [])
        category = self._cwe_to_category(cwes)

        severity = adv.get("severity", "unknown")
        cve_ids = [v.get("value", "") for v in adv.get("identifiers", []) if v.get("type") == "CVE"]

        metadata = ReportMetadata(
            title=title,
            category=category,
            severity=severity,
            platform="github",
            url=adv.get("html_url", ""),
            disclosed_date=adv.get("published_at"),
            cve_ids=cve_ids,
        )

        return Report(
            id=adv.get("ghsa_id", ""),
            metadata=metadata,
            raw_content=json.dumps(adv, default=str),
        )

    def _parse_issue(self, issue: Dict[str, Any], repo: str) -> Optional[Report]:
        """Parse a GitHub issue into a Report."""
        title = issue.get("title", "")
        if not title:
            return None

        labels = [l.get("name", "").lower() for l in issue.get("labels", [])]
        category = self._labels_to_category(labels)

        metadata = ReportMetadata(
            title=title,
            category=category,
            platform="github",
            url=issue.get("html_url", ""),
            researcher=issue.get("user", {}).get("login", ""),
            disclosed_date=issue.get("closed_at") or issue.get("created_at"),
            program=repo,
        )

        return Report(
            id=str(issue.get("id", "")),
            metadata=metadata,
            raw_content=json.dumps(issue, default=str),
        )

    def _parse_search_result(self, item: Dict[str, Any]) -> Optional[Report]:
        """Parse a GitHub search result."""
        name = item.get("full_name", "")
        description = item.get("description", "") or ""

        if not name:
            return None

        category = self._description_to_category(description)

        metadata = ReportMetadata(
            title=f"{name}: {description[:100]}",
            category=category,
            platform="github",
            url=item.get("html_url", ""),
            researcher=item.get("owner", {}).get("login", ""),
            disclosed_date=item.get("updated_at"),
        )

        return Report(
            id=str(item.get("id", "")),
            metadata=metadata,
            raw_content=json.dumps(item, default=str),
        )

    def _cwe_to_category(self, cwes: List[Any]) -> str:
        """Map CWE IDs to vulnerability categories."""
        cwe_map = {
            "CWE-918": "ssrf", "CWE-79": "xss", "CWE-89": "sqli",
            "CWE-639": "idor", "CWE-94": "rce", "CWE-22": "lfi",
            "CWE-611": "xxe", "CWE-352": "csrf", "CWE-601": "open_redirect",
        }
        for cwe in cwes:
            cwe_id = cwe.get("cwe_id", "") if isinstance(cwe, dict) else str(cwe)
            if cwe_id in cwe_map:
                return cwe_map[cwe_id]
        return "unknown"

    def _labels_to_category(self, labels: List[str]) -> str:
        """Map issue labels to a vulnerability category."""
        label_map = {
            "ssrf": "ssrf", "xss": "xss", "sqli": "sqli", "sql-injection": "sqli",
            "idor": "idor", "rce": "rce", "lfi": "lfi", "xxe": "xxe",
            "csrf": "csrf", "open-redirect": "open_redirect",
        }
        for label in labels:
            if label in label_map:
                return label_map[label]
        return "unknown"

    def _description_to_category(self, description: str) -> str:
        """Guess category from repository description."""
        desc_lower = description.lower()
        keywords = {
            "ssrf": "ssrf", "xss": "xss", "cross-site scripting": "xss",
            "sql injection": "sqli", "sqli": "sqli", "idor": "idor",
            "rce": "rce", "remote code": "rce", "lfi": "lfi",
            "xxe": "xxe", "csrf": "csrf",
        }
        for kw, cat in keywords.items():
            if kw in desc_lower:
                return cat
        return "unknown"

    async def extract_metadata(self, url: str) -> ReportMetadata:
        """Extract metadata from a GitHub URL."""
        resp = await self.http_client.get(url, headers=self._get_headers())
        if resp.status == 200 and resp.json_data:
            title = resp.json_data.get("title", "") or resp.json_data.get("summary", "")
            return ReportMetadata(title=title, platform="github", url=url)
        return ReportMetadata(url=url, platform="github")
