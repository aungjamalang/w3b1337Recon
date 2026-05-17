"""XSS Scanner - tests input parameters for Cross-Site Scripting."""

import asyncio
import json
import re
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote
from pathlib import Path

import click
from colorama import Fore, Style

from core.config import Config
from core.http_client import AsyncHTTPClient


class XSSScanner:
    """Scanner for Cross-Site Scripting vulnerabilities."""

    def __init__(self, target: str, config: Config, proxy: Optional[str] = None,
                 threads: int = 10, context: str = "auto"):
        self.target = target
        self.config = config
        self.proxy = proxy
        self.threads = threads
        self.context = context  # auto, html, attribute, javascript, url
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("bugrecon.tools.xss")
        self._canary = "w3b1337xss"

        if proxy:
            self.config._data.setdefault("proxy", {})["enabled"] = True
            self.config._data["proxy"]["http_proxy"] = proxy

    def get_payloads(self, wordlist: Optional[str] = None) -> List[Dict[str, str]]:
        """Get XSS test payloads organized by context."""
        payloads = [
            # Basic probes
            {"value": f"<{self._canary}>", "type": "html-tag-probe", "context": "html"},
            {"value": f'"{self._canary}', "type": "attr-break-probe", "context": "attribute"},
            {"value": f"'{self._canary}", "type": "js-break-probe", "context": "javascript"},
            # HTML context
            {"value": "<script>alert(1)</script>", "type": "script-tag", "context": "html"},
            {"value": "<img src=x onerror=alert(1)>", "type": "img-error", "context": "html"},
            {"value": "<svg onload=alert(1)>", "type": "svg-load", "context": "html"},
            {"value": "<svg/onload=alert(1)>", "type": "svg-nospace", "context": "html"},
            {"value": "<details open ontoggle=alert(1)>", "type": "details-toggle", "context": "html"},
            {"value": "<iframe srcdoc='<script>alert(1)</script>'>", "type": "iframe-srcdoc", "context": "html"},
            {"value": "<body onload=alert(1)>", "type": "body-load", "context": "html"},
            {"value": "<marquee onstart=alert(1)>", "type": "marquee", "context": "html"},
            # Attribute context
            {"value": '" onmouseover="alert(1)" x="', "type": "attr-event", "context": "attribute"},
            {"value": "' onfocus='alert(1)' autofocus='", "type": "attr-focus", "context": "attribute"},
            {"value": '" ><script>alert(1)</script><"', "type": "attr-break", "context": "attribute"},
            {"value": "javascript:alert(1)", "type": "js-uri", "context": "attribute"},
            # JavaScript context
            {"value": "'-alert(1)-'", "type": "js-string-break", "context": "javascript"},
            {"value": "\\'-alert(1)//", "type": "js-escape-break", "context": "javascript"},
            {"value": "</script><script>alert(1)//", "type": "script-break", "context": "javascript"},
            {"value": "${alert(1)}", "type": "template-literal", "context": "javascript"},
            # Filter bypass
            {"value": "<img src=x onerror=alert`1`>", "type": "backtick-bypass", "context": "html"},
            {"value": "<svg/onload=alert(1)//", "type": "comment-bypass", "context": "html"},
            {"value": "<<script>alert(1)//<</script>", "type": "double-open", "context": "html"},
            {"value": "<scr<script>ipt>alert(1)</scr</script>ipt>", "type": "nested-tag", "context": "html"},
            {"value": "%3Cscript%3Ealert(1)%3C/script%3E", "type": "url-encoded", "context": "html"},
            # DOM XSS triggers
            {"value": "#<img src=x onerror=alert(1)>", "type": "dom-hash", "context": "dom"},
            {"value": "javascript:alert(document.domain)", "type": "dom-js-uri", "context": "dom"},
        ]

        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append({"value": line, "type": "custom", "context": "unknown"})

        return payloads

    async def scan(self, wordlist: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run XSS scan against target."""
        payloads = self.get_payloads(wordlist)
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            xss_params = ["q", "search", "query", "keyword", "name", "username",
                         "email", "comment", "message", "text", "value", "input",
                         "title", "body", "content", "url", "redirect", "next", "ref"]
            params = {p: ["test"] for p in xss_params}

        self.logger.info(f"Testing {len(params)} parameters with {len(payloads)} payloads")

        async with AsyncHTTPClient(self.config) as client:
            # Detect context first
            if self.context == "auto":
                await self._detect_context(client, params)

            semaphore = asyncio.Semaphore(self.threads)
            tasks = []

            for param_name in params:
                for payload in payloads:
                    tasks.append(
                        self._test_payload(client, semaphore, param_name, payload)
                    )

            await asyncio.gather(*tasks)

        return self.results

    async def _detect_context(self, client: AsyncHTTPClient, params: dict):
        """Detect reflection context by injecting a canary."""
        parsed = urlparse(self.target)
        for param in list(params.keys())[:5]:  # Test first 5 params
            test_params = dict(parse_qs(parsed.query))
            test_params[param] = [self._canary]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(test_url)
                if self._canary in resp.text:
                    ctx = self._identify_context(resp.text, self._canary)
                    self.logger.info(f"Parameter '{param}' reflects in {ctx} context")
            except Exception:
                pass

    def _identify_context(self, html: str, canary: str) -> str:
        """Identify the HTML context where canary is reflected."""
        idx = html.find(canary)
        if idx == -1:
            return "none"

        before = html[max(0, idx-100):idx]

        # Check if inside a script tag
        if re.search(r'<script[^>]*>[^<]*$', before, re.I):
            return "javascript"
        # Check if inside an attribute
        if re.search(r'=\s*["\'][^"\']*$', before):
            return "attribute"
        # Check if inside a comment
        if '<!--' in before and '-->' not in before[before.rfind('<!--'):]:
            return "comment"
        # Default: HTML body
        return "html"

    async def _test_payload(self, client: AsyncHTTPClient, semaphore: asyncio.Semaphore,
                           param: str, payload: Dict[str, str]):
        """Test a single XSS payload."""
        async with semaphore:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            params[param] = [payload["value"]]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = await client.get(test_url, timeout=10)
                finding = self._analyze_response(resp, payload, param)
                if finding:
                    self.results.append(finding)
                    self._print_finding(finding)
            except Exception as e:
                self.logger.debug(f"Error testing {param}: {e}")

    def _analyze_response(self, resp, payload: Dict, param: str) -> Optional[Dict[str, Any]]:
        """Analyze response for XSS indicators."""
        body = resp.text
        payload_value = payload["value"]
        confidence = "low"
        indicators = []

        # Check if payload is reflected unmodified
        if payload_value in body:
            indicators.append("Payload reflected unmodified")
            confidence = "high"

            # Verify it's not inside a comment or encoded
            idx = body.find(payload_value)
            surrounding = body[max(0, idx-20):idx+len(payload_value)+20]
            if '<!--' in surrounding[:20]:
                confidence = "low"
                indicators.append("Reflected inside HTML comment")

        # Check for partial reflection (tag/event handler present)
        elif '<script' in payload_value and '<script' in body:
            indicators.append("Script tag detected in response")
            confidence = "medium"
        elif 'onerror=' in payload_value:
            if re.search(r'onerror\s*=', body, re.I):
                indicators.append("Event handler reflected")
                confidence = "medium"

        # Check if angle brackets are encoded
        if '<' in payload_value and '&lt;' in body and payload_value.replace('<', '&lt;') in body:
            indicators.append("HTML entities encoded (likely safe)")
            confidence = "info"

        # Check response headers for protections
        csp = resp.headers.get("Content-Security-Policy", "")
        xss_protection = resp.headers.get("X-XSS-Protection", "")
        if csp:
            indicators.append(f"CSP header present: {csp[:50]}...")
        if "1; mode=block" in xss_protection:
            indicators.append("X-XSS-Protection: 1; mode=block")

        if indicators and confidence != "info":
            return {
                "type": "XSS",
                "parameter": param,
                "payload": payload_value,
                "payload_type": payload["type"],
                "context": payload.get("context", "unknown"),
                "confidence": confidence,
                "indicators": indicators,
                "response_status": resp.status,
            }
        return None

    def _print_finding(self, finding: Dict[str, Any]):
        """Print a finding to console."""
        color = Fore.RED if finding["confidence"] == "high" else Fore.YELLOW
        print(f"\n{color}[XSS] [{finding['confidence'].upper()}]{Style.RESET_ALL}")
        print(f"  Parameter: {finding['parameter']}")
        print(f"  Payload: {finding['payload'][:80]}")
        print(f"  Context: {finding['context']}")
        for ind in finding["indicators"]:
            print(f"  {Fore.CYAN}→ {ind}{Style.RESET_ALL}")


@click.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--threads', default=10, help='Concurrent threads')
@click.option('--wordlist', '-w', help='Custom payload wordlist')
@click.option('--output', '-o', default='xss_results.json', help='Output file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, proxy, threads, wordlist, output, verbose):
    """XSS Scanner - Test for Cross-Site Scripting."""
    from core.utils import print_banner, setup_logging

    print_banner()
    print(f"{Fore.CYAN}[*] XSS Scanner{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print(f"[*] Threads: {threads}")
    print()

    setup_logging("DEBUG" if verbose else "INFO")
    config = Config()

    scanner = XSSScanner(target, config, proxy=proxy, threads=threads)
    results = asyncio.run(scanner.scan(wordlist))

    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}[*] Scan Complete - {len(results)} findings{Style.RESET_ALL}")

    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)
    print(f"[*] Results saved to: {output}")


if __name__ == '__main__':
    scan()
