"""Metadata extraction from bug bounty reports."""

import re
import logging
from typing import List, Dict, Any, Optional, Set
from bs4 import BeautifulSoup

from core.utils import normalize_category


class MetadataExtractor:
    """Extract structured metadata from raw report content."""

    def __init__(self):
        self.logger = logging.getLogger("bugrecon.analyzer.extractor")

        # Regex patterns for payload extraction
        self._url_pattern = re.compile(
            r'https?://[^\s<>"\'`\])}]+', re.IGNORECASE
        )
        self._ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        self._param_pattern = re.compile(
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', re.IGNORECASE
        )
        self._header_pattern = re.compile(
            r'\b(X-[A-Za-z-]+|Authorization|Cookie|Host|Referer|Origin|Content-Type)\b',
            re.IGNORECASE,
        )
        self._endpoint_pattern = re.compile(
            r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s<>"\']+)', re.IGNORECASE
        )
        self._code_block_pattern = re.compile(
            r'```[\s\S]*?```|`[^`]+`'
        )

        # Technology fingerprinting patterns
        self._tech_patterns = {
            "AWS": re.compile(r'\b(aws|s3|ec2|lambda|cloudfront|169\.254\.169\.254)\b', re.I),
            "GCP": re.compile(r'\b(gcp|google cloud|metadata\.google|169\.254\.169\.254)\b', re.I),
            "Azure": re.compile(r'\b(azure|169\.254\.169\.254|metadata\.azure)\b', re.I),
            "PHP": re.compile(r'\b(php|laravel|symfony|wordpress|drupal)\b', re.I),
            "Python": re.compile(r'\b(python|django|flask|fastapi)\b', re.I),
            "Node.js": re.compile(r'\b(node\.?js|express|next\.?js|nuxt)\b', re.I),
            "Java": re.compile(r'\b(java|spring|tomcat|struts)\b', re.I),
            "Ruby": re.compile(r'\b(ruby|rails|sinatra)\b', re.I),
            "Nginx": re.compile(r'\bnginx\b', re.I),
            "Apache": re.compile(r'\bapache\b', re.I),
            "Docker": re.compile(r'\b(docker|kubernetes|k8s)\b', re.I),
            "GraphQL": re.compile(r'\bgraphql\b', re.I),
            "REST API": re.compile(r'\b(rest\s*api|api/v\d)\b', re.I),
            "MySQL": re.compile(r'\b(mysql|mariadb)\b', re.I),
            "PostgreSQL": re.compile(r'\b(postgres|postgresql)\b', re.I),
            "MongoDB": re.compile(r'\b(mongo|mongodb)\b', re.I),
            "Redis": re.compile(r'\bredis\b', re.I),
            "Cloudflare": re.compile(r'\bcloudflare\b', re.I),
            "React": re.compile(r'\breact\b', re.I),
            "Angular": re.compile(r'\bangular\b', re.I),
        }

        # Severity indicators
        self._severity_patterns = {
            "critical": re.compile(r'\b(critical|rce|remote code execution|account takeover|full access)\b', re.I),
            "high": re.compile(r'\b(high|ssrf|sqli|sql injection|privilege escalation|auth bypass)\b', re.I),
            "medium": re.compile(r'\b(medium|xss|idor|information disclosure|stored xss)\b', re.I),
            "low": re.compile(r'\b(low|self-xss|reflected|open redirect|clickjacking)\b', re.I),
        }

    def extract_all(self, content: str, category: Optional[str] = None) -> Dict[str, Any]:
        """Extract all metadata from report content."""
        # Clean HTML if present
        text = self._clean_content(content)

        result = {
            "payloads": self.extract_payloads(text, category),
            "parameters": self.extract_parameters(text),
            "endpoints": self.extract_endpoints(text),
            "technologies": self.extract_technologies(text),
            "bypass_methods": self.extract_bypass_methods(text),
            "headers": self.extract_headers(text),
            "exploitation_steps": self.extract_steps(text),
            "severity_indicators": self.detect_severity(text),
            "urls": self.extract_urls(text),
            "ip_addresses": self.extract_ips(text),
        }

        return result

    def _clean_content(self, content: str) -> str:
        """Clean HTML and normalize text."""
        if "<html" in content.lower() or "<div" in content.lower():
            soup = BeautifulSoup(content, "html.parser")
            # Preserve code blocks
            for code in soup.find_all(["code", "pre"]):
                code.string = f"\n```\n{code.get_text()}\n```\n"
            return soup.get_text(separator="\n")
        return content

    def extract_payloads(self, text: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Extract attack payloads from report content."""
        payloads = []

        # Extract from code blocks
        code_blocks = self._code_block_pattern.findall(text)
        for block in code_blocks:
            clean_block = block.strip('`').strip()
            if self._is_potential_payload(clean_block, category):
                payloads.append({
                    "value": clean_block,
                    "source": "code_block",
                    "category": category or "unknown",
                })

        # Category-specific extraction
        if category:
            category_payloads = self._extract_category_payloads(text, category)
            payloads.extend(category_payloads)

        # Deduplicate
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p["value"] not in seen:
                seen.add(p["value"])
                unique_payloads.append(p)

        return unique_payloads

    def _is_potential_payload(self, text: str, category: Optional[str] = None) -> bool:
        """Determine if text is likely an attack payload."""
        if len(text) < 3 or len(text) > 2000:
            return False

        payload_indicators = [
            r'<script', r'javascript:', r'onerror=', r'onload=',   # XSS
            r"'.*or.*'", r"union.*select", r"--\s*$",               # SQLi
            r'http://169\.254', r'http://localhost', r'file://',     # SSRF
            r'\.\./\.\.',  r'/etc/passwd',                          # LFI
            r'<!ENTITY', r'<!DOCTYPE',                              # XXE
            r'\$\{.*\}', r'{{.*}}',                                 # Template injection
            r'%00', r'%0a', r'%0d',                                 # Encoding attacks
            r'curl\s', r'wget\s', r'nc\s',                         # RCE
        ]

        for pattern in payload_indicators:
            if re.search(pattern, text, re.I):
                return True

        return False

    def _extract_category_payloads(self, text: str, category: str) -> List[Dict[str, Any]]:
        """Extract payloads specific to vulnerability category."""
        payloads = []
        patterns = self._get_category_patterns(category)

        for pattern_info in patterns:
            matches = re.findall(pattern_info["regex"], text, re.I | re.M)
            for match in matches:
                value = match if isinstance(match, str) else match[0] if match else ""
                if value and len(value) > 2:
                    payloads.append({
                        "value": value.strip(),
                        "source": "category_pattern",
                        "category": category,
                        "type": pattern_info.get("type", "generic"),
                    })

        return payloads

    def _get_category_patterns(self, category: str) -> List[Dict[str, Any]]:
        """Get regex patterns for extracting payloads by category."""
        category_patterns = {
            "ssrf": [
                {"regex": r'(https?://(?:169\.254\.\d+\.\d+|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s<>"]*)', "type": "internal_url"},
                {"regex": r'((?:gopher|dict|file|ldap|tftp)://[^\s<>"]+)', "type": "protocol_smuggling"},
                {"regex": r'(http://[a-zA-Z0-9.-]+\.burpcollaborator\.net[^\s]*)', "type": "oob_test"},
            ],
            "xss": [
                {"regex": r'(<script[^>]*>.*?</script>)', "type": "script_tag"},
                {"regex": r'((?:on\w+)\s*=\s*["\'][^"\']+["\'])', "type": "event_handler"},
                {"regex": r'(javascript:[^\s<>"]+)', "type": "javascript_uri"},
                {"regex": r'(<(?:img|svg|iframe|object|embed|video|audio)[^>]+(?:on\w+|src\s*=\s*["\']javascript)[^>]*>)', "type": "html_injection"},
            ],
            "sqli": [
                {"regex": r"('.+(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)[^']*')", "type": "sql_statement"},
                {"regex": r'((?:UNION\s+(?:ALL\s+)?SELECT|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT)[^\n;]+)', "type": "sql_clause"},
                {"regex": r"((?:'\s*(?:OR|AND)\s*'?\s*\d*\s*=\s*\d*|--\s*$|#\s*$))", "type": "auth_bypass"},
            ],
            "idor": [
                {"regex": r'(/(?:api|v\d)/[^\s]+/\d+)', "type": "numeric_id"},
                {"regex": r'((?:user_id|account_id|order_id|id)\s*[=:]\s*\d+)', "type": "id_parameter"},
            ],
            "rce": [
                {"regex": r'((?:;|\||`|&&|\$\().*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc)[^\n]*)', "type": "command_injection"},
                {"regex": r'(\$\{[^}]*\})', "type": "expression_injection"},
            ],
            "lfi": [
                {"regex": r'((?:\.\./){2,}[^\s<>"]+)', "type": "path_traversal"},
                {"regex": r'((?:file|php|data|expect|input|filter)://[^\s<>"]+)', "type": "wrapper"},
            ],
            "xxe": [
                {"regex": r'(<!(?:DOCTYPE|ENTITY)[^>]+>)', "type": "entity_declaration"},
                {"regex": r'(<\?xml[^>]+>.*?<!(?:DOCTYPE|ENTITY).*?>)', "type": "xxe_payload"},
            ],
        }

        return category_patterns.get(category, [])

    def extract_parameters(self, text: str) -> List[str]:
        """Extract parameter names from report content."""
        params: Set[str] = set()

        # From URL query strings
        url_params = self._param_pattern.findall(text)
        params.update(url_params)

        # From JSON keys mentioned in context
        json_key_pattern = re.compile(r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*["{[\d]', re.I)
        json_keys = json_key_pattern.findall(text)
        params.update(json_keys)

        # From form data patterns
        form_pattern = re.compile(r'(?:name|param|field|input)\s*[=:]\s*["\']?([a-zA-Z_]\w*)', re.I)
        form_params = form_pattern.findall(text)
        params.update(form_params)

        # Filter out common non-parameter words
        noise_words = {'the', 'and', 'for', 'that', 'this', 'with', 'from', 'true', 'false', 'null', 'none'}
        return [p for p in sorted(params) if p.lower() not in noise_words and len(p) > 1]

    def extract_endpoints(self, text: str) -> List[str]:
        """Extract API endpoints from report content."""
        endpoints = set()

        # HTTP method + path
        method_paths = self._endpoint_pattern.findall(text)
        endpoints.update(method_paths)

        # URL paths from full URLs
        urls = self._url_pattern.findall(text)
        for url in urls:
            path_match = re.search(r'https?://[^/]+(/[^\s?#<>"]+)', url)
            if path_match:
                path = path_match.group(1)
                if '/api/' in path or '/v1/' in path or '/v2/' in path:
                    endpoints.add(path)

        return sorted(endpoints)

    def extract_technologies(self, text: str) -> List[str]:
        """Fingerprint technologies mentioned in the report."""
        found = []
        for tech, pattern in self._tech_patterns.items():
            if pattern.search(text):
                found.append(tech)
        return found

    def extract_bypass_methods(self, text: str) -> List[str]:
        """Extract WAF/filter bypass techniques mentioned."""
        bypass_patterns = {
            "URL encoding": r'\b(?:url[- ]?encod|%[0-9a-f]{2})',
            "Double encoding": r'\b(?:double[- ]?encod|%%)',
            "Unicode bypass": r'\b(?:unicode|utf-?8|\\u[0-9a-f])',
            "Case variation": r'\b(?:case[- ]?(?:swap|variation|toggle)|mixed[- ]?case)',
            "Null byte injection": r'\b(?:null[- ]?byte|%00|\\x00)',
            "DNS rebinding": r'\b(?:dns[- ]?rebind)',
            "IP obfuscation": r'\b(?:ip[- ]?obfuscat|decimal[- ]?ip|octal|0x[0-9a-f]+\.)',
            "Protocol smuggling": r'\b(?:protocol[- ]?smuggl|gopher://|dict://)',
            "Header injection": r'\b(?:header[- ]?inject|crlf|\\r\\n)',
            "Chunked encoding": r'\b(?:chunk|transfer-encoding)',
            "Parameter pollution": r'\b(?:param(?:eter)?[- ]?pollut|hpp)',
            "Host header attack": r'\b(?:host[- ]?header|x-forwarded)',
            "WAF bypass": r'\b(?:waf[- ]?bypass|firewall[- ]?bypass)',
            "Filter evasion": r'\b(?:filter[- ]?evas|filter[- ]?bypass)',
            "Encoding chain": r'\b(?:encod(?:ing)?[- ]?chain|multi[- ]?encod)',
        }

        methods = []
        for method, pattern in bypass_patterns.items():
            if re.search(pattern, text, re.I):
                methods.append(method)

        return methods

    def extract_headers(self, text: str) -> List[str]:
        """Extract HTTP headers mentioned."""
        headers = self._header_pattern.findall(text)
        return list(set(headers))

    def extract_steps(self, text: str) -> List[str]:
        """Extract exploitation steps (numbered or bulleted lists)."""
        steps = []

        # Numbered steps: 1. xxx, 2. xxx
        numbered = re.findall(r'^\s*\d+[.)]\s*(.+)$', text, re.M)
        if numbered:
            steps.extend(numbered)

        # Steps/PoC section
        section_pattern = re.compile(
            r'(?:steps?\s*(?:to\s+)?reproduc|poc|proof\s*of\s*concept|exploitation|impact).*?(?:\n\n|\Z)',
            re.I | re.S
        )
        sections = section_pattern.findall(text)
        for section in sections:
            lines = [l.strip() for l in section.split('\n') if l.strip() and len(l.strip()) > 10]
            steps.extend(lines[:10])

        return steps[:20]  # Limit to 20 steps

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from content."""
        urls = self._url_pattern.findall(text)
        return list(set(urls))[:50]

    def extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from content."""
        ips = self._ip_pattern.findall(text)
        return list(set(ips))

    def detect_severity(self, text: str) -> str:
        """Detect likely severity based on content."""
        for severity, pattern in self._severity_patterns.items():
            if pattern.search(text):
                return severity
        return "unknown"
