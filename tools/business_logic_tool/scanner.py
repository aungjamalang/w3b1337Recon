"""Business Logic Scanner - tests for race conditions, price manipulation, and workflow bypasses."""

import asyncio
import json
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

import click
from colorama import Fore, Style

from core.config import Config
from core.http_client import AsyncHTTPClient


class BusinessLogicScanner:
    """Scanner for Business Logic vulnerabilities."""

    def __init__(self, target: str, config: Config, proxy: Optional[str] = None,
                 auth_token: Optional[str] = None, threads: int = 10):
        self.target = target
        self.config = config
        self.proxy = proxy
        self.auth_token = auth_token
        self.threads = threads
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("bugrecon.tools.business_logic")

        if proxy:
            self.config._data.setdefault("proxy", {})["enabled"] = True
            self.config._data["proxy"]["http_proxy"] = proxy

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with auth."""
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    async def scan(self, test_type: str = "all") -> List[Dict[str, Any]]:
        """Run business logic scan."""
        self.logger.info(f"Running business logic tests: {test_type}")

        async with AsyncHTTPClient(self.config) as client:
            if test_type in ("all", "race"):
                await self._test_race_condition(client)

            if test_type in ("all", "numeric"):
                await self._test_numeric_manipulation(client)

            if test_type in ("all", "rate"):
                await self._test_rate_limit(client)

            if test_type in ("all", "method"):
                await self._test_method_override(client)

            if test_type in ("all", "parameter"):
                await self._test_parameter_manipulation(client)

        return self.results

    async def _test_race_condition(self, client: AsyncHTTPClient):
        """Test for race conditions by sending concurrent requests."""
        self.logger.info("Testing for race conditions...")

        # Send multiple concurrent identical requests
        concurrency_levels = [5, 10, 20]

        for level in concurrency_levels:
            tasks = []
            for _ in range(level):
                tasks.append(
                    client.post(self.target, headers=self._get_headers(), json={})
                )

            try:
                start = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start

                # Analyze: check if multiple requests succeeded
                successes = [r for r in responses if hasattr(r, 'status') and r.status in [200, 201]]
                errors = [r for r in responses if hasattr(r, 'status') and r.status >= 400]

                if len(successes) > 1:
                    finding = {
                        "type": "Business Logic",
                        "subtype": "race_condition",
                        "confidence": "medium",
                        "concurrency": level,
                        "successes": len(successes),
                        "errors": len(errors),
                        "elapsed": elapsed,
                        "indicators": [
                            f"{len(successes)}/{level} concurrent requests succeeded",
                            f"Total time: {elapsed:.2f}s (avg {elapsed/level:.3f}s/req)",
                        ],
                    }

                    # High confidence if all succeed (expected: only 1 should)
                    if len(successes) == level:
                        finding["confidence"] = "high"
                        finding["indicators"].append("ALL requests succeeded - likely vulnerable to race condition")

                    self.results.append(finding)
                    self._print_finding(finding)
                    break  # Found race condition, no need to test higher levels

            except Exception as e:
                self.logger.debug(f"Race condition test error: {e}")

    async def _test_numeric_manipulation(self, client: AsyncHTTPClient):
        """Test for numeric parameter manipulation (negative values, overflow)."""
        self.logger.info("Testing numeric manipulation...")

        test_values = [
            {"field": "amount", "values": [0, -1, -100, -999999, 0.001, 99999999]},
            {"field": "quantity", "values": [0, -1, -10, 99999, 0.5]},
            {"field": "price", "values": [0, -1, 0.01, -100]},
            {"field": "discount", "values": [100, 101, 200, -50, 999]},
            {"field": "count", "values": [0, -1, 99999999]},
        ]

        for test in test_values:
            for value in test["values"]:
                try:
                    payload = {test["field"]: value}
                    resp = await client.post(
                        self.target, headers=self._get_headers(), json=payload
                    )

                    if resp.status in [200, 201]:
                        finding = {
                            "type": "Business Logic",
                            "subtype": "numeric_manipulation",
                            "parameter": test["field"],
                            "value": value,
                            "confidence": "medium",
                            "response_status": resp.status,
                            "indicators": [
                                f"Server accepted {test['field']}={value}",
                                f"Response: {resp.status}",
                            ],
                        }

                        if value < 0:
                            finding["confidence"] = "high"
                            finding["indicators"].append("Negative value accepted!")
                        elif value == 0:
                            finding["indicators"].append("Zero value accepted")

                        self.results.append(finding)
                        self._print_finding(finding)

                except Exception as e:
                    self.logger.debug(f"Numeric test error: {e}")

    async def _test_rate_limit(self, client: AsyncHTTPClient):
        """Test for rate limiting on sensitive endpoints."""
        self.logger.info("Testing rate limits...")

        request_count = 50
        successes = 0
        rate_limited = False

        for i in range(request_count):
            try:
                resp = await client.get(self.target, headers=self._get_headers())
                if resp.status == 429:
                    rate_limited = True
                    break
                elif resp.status in [200, 201]:
                    successes += 1
            except Exception:
                break

        if not rate_limited and successes >= request_count:
            finding = {
                "type": "Business Logic",
                "subtype": "missing_rate_limit",
                "confidence": "medium",
                "requests_sent": request_count,
                "successes": successes,
                "indicators": [
                    f"Sent {request_count} requests without rate limiting",
                    f"All {successes} requests succeeded",
                    "No 429 (Too Many Requests) response received",
                ],
            }
            self.results.append(finding)
            self._print_finding(finding)

    async def _test_method_override(self, client: AsyncHTTPClient):
        """Test for HTTP method override bypasses."""
        self.logger.info("Testing method override...")

        override_headers = [
            ("X-HTTP-Method-Override", "PUT"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method-Override", "PATCH"),
            ("X-Method-Override", "PUT"),
            ("X-HTTP-Method", "DELETE"),
        ]

        for header_name, method in override_headers:
            try:
                headers = self._get_headers()
                headers[header_name] = method

                resp = await client.post(self.target, headers=headers, json={})
                if resp.status in [200, 201, 204]:
                    finding = {
                        "type": "Business Logic",
                        "subtype": "method_override",
                        "header": f"{header_name}: {method}",
                        "confidence": "medium",
                        "response_status": resp.status,
                        "indicators": [
                            f"Method override accepted: {header_name}: {method}",
                            f"Response status: {resp.status}",
                        ],
                    }
                    self.results.append(finding)
                    self._print_finding(finding)

            except Exception:
                pass

    async def _test_parameter_manipulation(self, client: AsyncHTTPClient):
        """Test for parameter pollution and hidden parameter injection."""
        self.logger.info("Testing parameter manipulation...")

        # Test adding role/privilege parameters
        privilege_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"admin": True},
            {"role": "superuser"},
            {"permissions": ["admin", "write", "delete"]},
            {"user_type": "admin"},
            {"level": 99},
            {"verified": True},
            {"approved": True},
        ]

        for payload in privilege_payloads:
            try:
                resp = await client.post(
                    self.target, headers=self._get_headers(), json=payload
                )

                if resp.status in [200, 201]:
                    # Check if response indicates elevated access
                    resp_text = resp.text.lower()
                    elevated_indicators = ["admin", "superuser", "elevated", "granted", "success"]

                    for indicator in elevated_indicators:
                        if indicator in resp_text:
                            finding = {
                                "type": "Business Logic",
                                "subtype": "parameter_injection",
                                "payload": payload,
                                "confidence": "medium",
                                "response_status": resp.status,
                                "indicators": [
                                    f"Privilege parameter accepted: {payload}",
                                    f"Response contains '{indicator}'",
                                ],
                            }
                            self.results.append(finding)
                            self._print_finding(finding)
                            break

            except Exception:
                pass

    def _print_finding(self, finding: Dict[str, Any]):
        """Print a finding."""
        color = Fore.RED if finding["confidence"] == "high" else Fore.YELLOW
        print(f"\n{color}[LOGIC] [{finding['confidence'].upper()}] {finding['subtype']}{Style.RESET_ALL}")
        if "parameter" in finding:
            print(f"  Parameter: {finding['parameter']}")
        if "value" in finding:
            print(f"  Value: {finding['value']}")
        if "payload" in finding:
            print(f"  Payload: {finding['payload']}")
        for ind in finding.get("indicators", []):
            print(f"  {Fore.CYAN}→ {ind}{Style.RESET_ALL}")


@click.command()
@click.option('--target', '-t', required=True, help='Target URL/endpoint')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--auth-token', '-a', help='Authorization token')
@click.option('--test-type', default='all', type=click.Choice(['all', 'race', 'numeric', 'rate', 'method', 'parameter']))
@click.option('--threads', default=10, help='Concurrent threads')
@click.option('--output', '-o', default='logic_results.json', help='Output file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, proxy, auth_token, test_type, threads, output, verbose):
    """Business Logic Scanner - Test for logic flaws."""
    from core.utils import print_banner, setup_logging

    print_banner()
    print(f"{Fore.CYAN}[*] Business Logic Scanner{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print(f"[*] Test Type: {test_type}")
    print()

    setup_logging("DEBUG" if verbose else "INFO")
    config = Config()

    scanner = BusinessLogicScanner(target, config, proxy=proxy, auth_token=auth_token, threads=threads)
    results = asyncio.run(scanner.scan(test_type))

    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}[*] Scan Complete - {len(results)} findings{Style.RESET_ALL}")

    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)
    print(f"[*] Results saved to: {output}")


if __name__ == '__main__':
    scan()
