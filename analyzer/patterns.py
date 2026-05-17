"""Pattern detection and attack surface identification."""

import re
import logging
from typing import List, Dict, Any, Optional
from collections import Counter

from core.storage import Storage
from core.utils import normalize_category


class PatternDetector:
    """Detect patterns, attack surfaces, and trends from collected reports."""

    def __init__(self, storage: Storage):
        self.storage = storage
        self.logger = logging.getLogger("bugrecon.analyzer.patterns")

    def analyze_reports(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run full pattern analysis on a set of reports."""
        results = {
            "attack_surfaces": self.identify_attack_surfaces(reports),
            "common_parameters": self.find_common_parameters(reports),
            "technology_trends": self.detect_technology_trends(reports),
            "bypass_techniques": self.aggregate_bypass_methods(reports),
            "severity_distribution": self.severity_distribution(reports),
            "high_value_targets": self.identify_high_value_patterns(reports),
            "detection_signatures": self.generate_detection_rules(reports),
        }
        return results

    def identify_attack_surfaces(self, reports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Identify common attack surfaces by vulnerability category."""
        surfaces: Dict[str, Counter] = {}

        attack_surface_patterns = {
            "ssrf": [
                r'\b(webhook|callback|url|proxy|fetch|redirect|image|avatar|import)\b',
                r'\b(pdf|screenshot|preview|thumbnail|embed|attachment)\b',
            ],
            "xss": [
                r'\b(search|comment|profile|username|message|bio|title|description)\b',
                r'\b(input|form|textarea|rich.?text|markdown|html)\b',
            ],
            "sqli": [
                r'\b(search|filter|sort|order|id|login|query|report)\b',
                r'\b(api|endpoint|parameter|column|table)\b',
            ],
            "idor": [
                r'\b(user.?id|account|order|invoice|document|file|message)\b',
                r'\b(profile|settings|admin|api|endpoint)\b',
            ],
            "business_logic": [
                r'\b(payment|checkout|cart|discount|coupon|referral)\b',
                r'\b(rate.?limit|2fa|mfa|auth|session|token|signup)\b',
            ],
        }

        for report in reports:
            category = report.get("category", "unknown")
            raw_data = report.get("raw_data", "") or report.get("title", "")

            if category not in surfaces:
                surfaces[category] = Counter()

            patterns = attack_surface_patterns.get(category, [])
            for pattern in patterns:
                matches = re.findall(pattern, raw_data, re.I)
                surfaces[category].update([m.lower() for m in matches])

        # Convert to sorted lists
        return {
            cat: [item for item, _ in counter.most_common(20)]
            for cat, counter in surfaces.items()
        }

    def find_common_parameters(self, reports: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Find most commonly attacked parameters per category."""
        param_counts: Dict[str, Counter] = {}

        param_pattern = re.compile(r'[?&]([a-zA-Z_]\w*)=', re.I)
        json_key_pattern = re.compile(r'"([a-zA-Z_]\w*)":', re.I)

        for report in reports:
            category = report.get("category", "unknown")
            raw_data = report.get("raw_data", "") or ""

            if category not in param_counts:
                param_counts[category] = Counter()

            # URL parameters
            params = param_pattern.findall(raw_data)
            param_counts[category].update(params)

            # JSON body parameters
            json_keys = json_key_pattern.findall(raw_data)
            param_counts[category].update(json_keys)

        # Format results
        results = {}
        noise = {'type', 'id', 'page', 'limit', 'offset', 'format', 'version'}
        for category, counter in param_counts.items():
            results[category] = [
                {"name": param, "frequency": count}
                for param, count in counter.most_common(30)
                if param.lower() not in noise and len(param) > 1
            ]

        return results

    def detect_technology_trends(self, reports: List[Dict[str, Any]]) -> Dict[str, int]:
        """Detect technology stack trends across reports."""
        tech_counter = Counter()

        tech_patterns = {
            "AWS": r'\b(aws|s3|ec2|lambda|cloudfront)\b',
            "GCP": r'\b(gcp|google.?cloud)\b',
            "Azure": r'\bazure\b',
            "PHP": r'\b(php|laravel|wordpress)\b',
            "Python": r'\b(python|django|flask)\b',
            "Node.js": r'\b(node\.?js|express)\b',
            "Java": r'\b(java|spring)\b',
            "Ruby": r'\b(ruby|rails)\b',
            "React": r'\breact\b',
            "GraphQL": r'\bgraphql\b',
            "REST": r'\b(rest.?api|api/v\d)\b',
            "Nginx": r'\bnginx\b',
            "Apache": r'\bapache\b',
            "Docker": r'\bdocker\b',
            "Kubernetes": r'\b(k8s|kubernetes)\b',
        }

        for report in reports:
            raw_data = report.get("raw_data", "") or report.get("title", "")
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, raw_data, re.I):
                    tech_counter[tech] += 1

        return dict(tech_counter.most_common(20))

    def aggregate_bypass_methods(self, reports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Aggregate bypass methods found across reports by category."""
        bypasses: Dict[str, set] = {}

        bypass_patterns = {
            "URL encoding": r'%[0-9a-fA-F]{2}',
            "Double URL encoding": r'%25[0-9a-fA-F]{2}',
            "Unicode normalization": r'\\u[0-9a-fA-F]{4}',
            "Case manipulation": r'\b(?:case|mixed.?case|upper|lower)\b',
            "Null byte": r'(?:%00|\\x00|\\0)',
            "IP formats": r'\b(?:0x[0-9a-f]+|0[0-7]+)\b',
            "DNS rebinding": r'\bdns.?rebind',
            "CRLF injection": r'(?:%0[ad]|\\r\\n)',
            "Path normalization": r'(?:\.\./|\.\\\\|%2e%2e)',
            "Protocol abuse": r'(?:gopher|dict|file|ldap|tftp)://',
            "Whitespace bypass": r'(?:/\*\*/|%09|%0b|%0c)',
            "Comment injection": r'(?:--|#|/\*)',
        }

        for report in reports:
            category = report.get("category", "unknown")
            raw_data = report.get("raw_data", "") or ""

            if category not in bypasses:
                bypasses[category] = set()

            for method, pattern in bypass_patterns.items():
                if re.search(pattern, raw_data, re.I):
                    bypasses[category].add(method)

        return {cat: sorted(methods) for cat, methods in bypasses.items()}

    def severity_distribution(self, reports: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
        """Calculate severity distribution per category."""
        dist: Dict[str, Counter] = {}

        for report in reports:
            category = report.get("category", "unknown")
            severity = report.get("severity", "unknown") or "unknown"

            if category not in dist:
                dist[category] = Counter()
            dist[category][severity.lower()] += 1

        return {cat: dict(counter) for cat, counter in dist.items()}

    def identify_high_value_patterns(self, reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify patterns from high-bounty reports."""
        high_value = [r for r in reports if (r.get("bounty_amount") or 0) >= 1000]
        high_value.sort(key=lambda x: x.get("bounty_amount", 0), reverse=True)

        patterns = []
        for report in high_value[:50]:
            patterns.append({
                "title": report.get("title", ""),
                "category": report.get("category", ""),
                "bounty": report.get("bounty_amount", 0),
                "severity": report.get("severity", ""),
                "platform": report.get("platform", ""),
            })

        return patterns

    def generate_detection_rules(self, reports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate regex detection rules from patterns found in reports."""
        rules: Dict[str, List[str]] = {}

        # Base detection rules by category
        base_rules = {
            "ssrf": [
                r'(?:https?://)?(?:169\.254\.\d+\.\d+|127\.0\.0\.1|localhost|0\.0\.0\.0)',
                r'(?:gopher|dict|file|ldap)://',
                r'http://(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.',
            ],
            "xss": [
                r'<script[^>]*>',
                r'(?:on(?:error|load|click|mouse\w+|focus|blur))\s*=',
                r'javascript:',
                r'<(?:img|svg|iframe)[^>]+(?:onerror|onload)',
            ],
            "sqli": [
                r"(?:'|\")?\s*(?:OR|AND)\s+\d+\s*=\s*\d+",
                r'UNION\s+(?:ALL\s+)?SELECT',
                r"(?:--|#)\s*$",
                r'(?:SLEEP|BENCHMARK|WAITFOR)\s*\(',
            ],
            "lfi": [
                r'(?:\.\./){2,}',
                r'(?:etc/passwd|etc/shadow|proc/self)',
                r'(?:php|data|expect|input)://',
            ],
            "xxe": [
                r'<!ENTITY\s+',
                r'<!DOCTYPE\s+\w+\s+\[',
                r'SYSTEM\s+["\'](?:file|http|ftp)://',
            ],
        }

        rules.update(base_rules)
        return rules

    def find_correlations(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find correlations between vulnerability types and targets."""
        correlations = {
            "category_bounty_avg": {},
            "category_platform_dist": {},
            "severity_by_tech": {},
        }

        # Average bounty per category
        category_bounties: Dict[str, List[float]] = {}
        for report in reports:
            cat = report.get("category", "unknown")
            bounty = report.get("bounty_amount", 0) or 0
            if bounty > 0:
                category_bounties.setdefault(cat, []).append(bounty)

        for cat, bounties in category_bounties.items():
            correlations["category_bounty_avg"][cat] = {
                "average": sum(bounties) / len(bounties),
                "max": max(bounties),
                "count": len(bounties),
            }

        return correlations
