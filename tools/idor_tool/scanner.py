"""IDOR Scanner - tests access control on object references."""

import asyncio
import json
import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from pathlib import Path

import click
from colorama import Fore, Style

from core.config import Config
from core.http_client import AsyncHTTPClient


class IDORScanner:
    """Scanner for Insecure Direct Object Reference vulnerabilities."""

    def __init__(self, target: str, config: Config, proxy: Optional[str] = None,
                 auth_token: Optional[str] = None, victim_token: Optional[str] = None,
                 threads: int = 10):
        self.target = target
        self.config = config
        self.proxy = proxy
        self.auth_token = auth_token
        self.victim_token = victim_token
        self.threads = threads
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("bugrecon.tools.idor")

        if proxy:
            self.config._data.setdefault("proxy", {})["enabled"] = True
            self.config._data["proxy"]["http_proxy"] = proxy

    def _get_auth_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        """Get authentication headers."""
        t = token or self.auth_token
        if not t:
            return {}
        if t.startswith("Bearer "):
            return {"Authorization": t}
        return {"Authorization": f"Bearer {t}"}

    def get_test_ids(self) -> List[Dict[str, Any]]:
        """Generate test IDs for IDOR testing."""
        return [
            # Sequential numeric IDs
            {"value": "1", "type": "numeric", "description": "First user/object"},
            {"value": "2", "type": "numeric", "description": "Second user/object"},
            {"value": "0", "type": "numeric", "description": "Zero ID"},
            {"value": "-1", "type": "numeric", "description": "Negative ID"},
            {"value": "99999", "type": "numeric", "description": "High sequential ID"},
            # Admin/special IDs
            {"value": "admin", "type": "string", "description": "Admin user"},
            {"value": "root", "type": "string", "description": "Root user"},
            {"value": "system", "type": "string", "description": "System user"},
            # Array/object manipulation
            {"value": "1,2,3", "type": "array", "description": "Multiple IDs"},
            {"value": "*", "type": "wildcard", "description": "Wildcard"},
            # Path traversal in ID
            {"value": "../admin", "type": "traversal", "description": "Path traversal"},
        ]

    async def scan(self) -> List[Dict[str, Any]]:
        """Run IDOR scan."""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        # Identify ID-like parameters
        id_params = self._identify_id_params(params, parsed.path)
        test_ids = self.get_test_ids()

        self.logger.info(f"Testing {len(id_params)} ID parameters")

        async with AsyncHTTPClient(self.config) as client:
            # Get authorized response (baseline)
            baseline = await self._get_authorized_response(client)

            semaphore = asyncio.Semaphore(self.threads)
            tasks = []

            # Test parameter-based IDOR
            for param in id_params:
                for test_id in test_ids:
                    tasks.append(
                        self._test_param_idor(client, semaphore, param, test_id, baseline)
                    )

            # Test path-based IDOR
            path_ids = self._extract_path_ids(parsed.path)
            for original_id, position in path_ids:
                for test_id in test_ids:
                    tasks.append(
                        self._test_path_idor(client, semaphore, original_id, position, test_id, baseline)
                    )

            # Test HTTP method-based access control
            tasks.append(self._test_method_bypass(client, baseline))

            await asyncio.gather(*tasks)

        return self.results

    def _identify_id_params(self, params: dict, path: str) -> List[str]:
        """Identify parameters likely to be object identifiers."""
        id_patterns = re.compile(
            r'(.*id$|.*_id$|uid|uuid|guid|ref|num|number|account|user|order|file|doc|key|token|hash)',
            re.I
        )
        id_params = [p for p in params if id_patterns.match(p)]

        # If no ID params found, check all numeric value params
        if not id_params:
            id_params = [p for p, v in params.items() if v and v[0].isdigit()]

        # Fallback: just use all params
        if not id_params:
            id_params = list(params.keys())

        return id_params

    def _extract_path_ids(self, path: str) -> List[tuple]:
        """Extract numeric or UUID IDs from URL path."""
        results = []
        segments = path.split('/')

        for i, segment in enumerate(segments):
            # Numeric ID
            if segment.isdigit():
                results.append((segment, i))
            # UUID
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.I):
                results.append((segment, i))

        return results

    async def _get_authorized_response(self, client: AsyncHTTPClient) -> Dict[str, Any]:
        """Get baseline authorized response."""
        try:
            resp = await client.get(self.target, headers=self._get_auth_headers())
            return {
                "status": resp.status,
                "length": len(resp.text),
                "body": resp.text[:5000],
                "headers": dict(resp.headers),
            }
        except Exception:
            return {"status": 0, "length": 0, "body": "", "headers": {}}

    async def _test_param_idor(self, client: AsyncHTTPClient, semaphore: asyncio.Semaphore,
                               param: str, test_id: Dict, baseline: Dict):
        """Test IDOR by modifying parameter values."""
        async with semaphore:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            original_value = params.get(param, [""])[0]

            # Skip if test ID is same as original
            if str(test_id["value"]) == str(original_value):
                return

            params[param] = [test_id["value"]]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                # Test with attacker's token
                resp = await client.get(test_url, headers=self._get_auth_headers())
                finding = self._analyze_idor_response(resp, param, test_id, baseline, "parameter")
                if finding:
                    self.results.append(finding)
                    self._print_finding(finding)

            except Exception as e:
                self.logger.debug(f"Error testing IDOR {param}={test_id['value']}: {e}")

    async def _test_path_idor(self, client: AsyncHTTPClient, semaphore: asyncio.Semaphore,
                              original_id: str, position: int, test_id: Dict, baseline: Dict):
        """Test IDOR by modifying path segment IDs."""
        async with semaphore:
            if str(test_id["value"]) == original_id:
                return

            parsed = urlparse(self.target)
            segments = parsed.path.split('/')
            segments[position] = str(test_id["value"])
            new_path = '/'.join(segments)
            test_url = urlunparse(parsed._replace(path=new_path))

            try:
                resp = await client.get(test_url, headers=self._get_auth_headers())
                finding = self._analyze_idor_response(
                    resp, f"path[{position}]", test_id, baseline, "path"
                )
                if finding:
                    finding["original_id"] = original_id
                    self.results.append(finding)
                    self._print_finding(finding)

            except Exception as e:
                self.logger.debug(f"Error testing path IDOR: {e}")

    async def _test_method_bypass(self, client: AsyncHTTPClient, baseline: Dict):
        """Test HTTP method-based access control bypass."""
        methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

        for method in methods:
            try:
                resp = await client.request(method, self.target, headers=self._get_auth_headers())
                if resp.status in [200, 201, 204] and resp.status != baseline.get("status"):
                    finding = {
                        "type": "IDOR",
                        "subtype": "method_bypass",
                        "method": method,
                        "confidence": "medium",
                        "indicators": [f"HTTP {method} returned {resp.status} (different from baseline {baseline.get('status')})"],
                        "response_status": resp.status,
                    }
                    self.results.append(finding)
                    self._print_finding(finding)
            except Exception:
                pass

    def _analyze_idor_response(self, resp, param: str, test_id: Dict,
                               baseline: Dict, location: str) -> Optional[Dict[str, Any]]:
        """Analyze response for IDOR indicators."""
        indicators = []
        confidence = "low"

        # 200 OK with different content suggests data from another object
        if resp.status == 200:
            length_diff = abs(len(resp.text) - baseline.get("length", 0))

            if length_diff > 50 and len(resp.text) > 100:
                indicators.append(f"Returned data for different ID (length diff: {length_diff})")
                confidence = "medium"

                # Check if response contains different user data
                pii_patterns = [
                    r'"email":\s*"[^"]+"', r'"username":\s*"[^"]+"',
                    r'"phone":\s*"[^"]+"', r'"address":\s*"[^"]+"',
                ]
                for pattern in pii_patterns:
                    if re.search(pattern, resp.text, re.I):
                        indicators.append("Response contains PII fields")
                        confidence = "high"
                        break

            elif length_diff < 10 and resp.text[:200] != baseline.get("body", "")[:200]:
                indicators.append("Subtle content difference detected")
                confidence = "low"

        # 403/401 is expected (access denied) - not vulnerable
        elif resp.status in [401, 403]:
            return None

        # Unexpected success codes
        elif resp.status in [201, 204] and baseline.get("status") != resp.status:
            indicators.append(f"Unexpected success status: {resp.status}")
            confidence = "medium"

        if indicators:
            return {
                "type": "IDOR",
                "subtype": location,
                "parameter": param,
                "test_id": test_id["value"],
                "test_type": test_id["type"],
                "confidence": confidence,
                "indicators": indicators,
                "response_status": resp.status,
                "response_length": len(resp.text),
            }
        return None

    def _print_finding(self, finding: Dict[str, Any]):
        """Print a finding."""
        color = Fore.RED if finding["confidence"] == "high" else Fore.YELLOW
        print(f"\n{color}[IDOR] [{finding['confidence'].upper()}]{Style.RESET_ALL}")
        if "parameter" in finding:
            print(f"  Parameter: {finding['parameter']}")
        if "test_id" in finding:
            print(f"  Test ID: {finding['test_id']} ({finding.get('test_type', '')})")
        if "method" in finding:
            print(f"  Method: {finding['method']}")
        for ind in finding["indicators"]:
            print(f"  {Fore.CYAN}→ {ind}{Style.RESET_ALL}")


@click.command()
@click.option('--target', '-t', required=True, help='Target URL with ID parameter')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--auth-token', '-a', help='Your auth token (attacker)')
@click.option('--victim-token', help='Victim auth token (for verification)')
@click.option('--threads', default=10, help='Concurrent threads')
@click.option('--output', '-o', default='idor_results.json', help='Output file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, proxy, auth_token, victim_token, threads, output, verbose):
    """IDOR Scanner - Test for Insecure Direct Object References."""
    from core.utils import print_banner, setup_logging

    print_banner()
    print(f"{Fore.CYAN}[*] IDOR Scanner{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print()

    setup_logging("DEBUG" if verbose else "INFO")
    config = Config()

    scanner = IDORScanner(target, config, proxy=proxy, auth_token=auth_token,
                          victim_token=victim_token, threads=threads)
    results = asyncio.run(scanner.scan())

    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}[*] Scan Complete - {len(results)} findings{Style.RESET_ALL}")

    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)
    print(f"[*] Results saved to: {output}")


if __name__ == '__main__':
    scan()
