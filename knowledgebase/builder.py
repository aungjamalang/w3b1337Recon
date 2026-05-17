"""Knowledgebase builder - generates structured methodology documentation."""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.storage import Storage
from .templates import CATEGORY_TEMPLATES


class KnowledgebaseBuilder:
    """Build structured knowledgebase documentation from analyzed data."""

    def __init__(self, storage: Storage, output_dir: str = "knowledgebase/categories"):
        self.storage = storage
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger("bugrecon.knowledgebase")

    def build(self, categories: Optional[List[str]] = None):
        """Build knowledgebase for specified categories."""
        if not categories:
            categories = list(CATEGORY_TEMPLATES.keys())

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Building knowledgebase for: {categories}")

        for category in categories:
            if category in CATEGORY_TEMPLATES:
                self._build_category(category)
            else:
                self.logger.warning(f"No template for category: {category}")

        # Build index
        self._build_index(categories)
        self.logger.info("Knowledgebase build complete")

    def _build_category(self, category: str):
        """Build documentation for a single category."""
        template = CATEGORY_TEMPLATES[category]
        reports = self.storage.search_reports(category=category, limit=500)
        top_params = self.storage.get_top_parameters(category=category, limit=20)
        payloads = self.storage.get_payloads(category=category, limit=50)

        # Render template with data
        content = self._render_template(template, {
            "reports": reports,
            "parameters": top_params,
            "payloads": payloads,
            "report_count": len(reports),
        })

        output_path = self.output_dir / f"{category}.md"
        with open(output_path, "w") as f:
            f.write(content)

        self.logger.info(f"Built knowledgebase: {output_path}")

    def _render_template(self, template: Dict[str, Any], data: Dict[str, Any]) -> str:
        """Render a category template with collected data."""
        sections = []

        # Header
        sections.append(f"# {template['title']}\n")
        sections.append(f"> {template['description']}\n")
        sections.append(f"**Reports Analyzed:** {data['report_count']}\n")

        # Overview
        sections.append("## Overview\n")
        sections.append(template.get("overview", "") + "\n")

        # Methodology
        sections.append("## Testing Methodology\n")
        for i, step in enumerate(template.get("methodology", []), 1):
            sections.append(f"### Step {i}: {step['title']}\n")
            sections.append(f"{step['description']}\n")
            if step.get("tools"):
                sections.append("**Tools:**\n")
                for tool in step["tools"]:
                    sections.append(f"- {tool}\n")
            sections.append("")

        # Attack Vectors
        sections.append("## Attack Vectors\n")
        for vector in template.get("attack_vectors", []):
            sections.append(f"### {vector['name']}\n")
            sections.append(f"{vector['description']}\n")
            if vector.get("example"):
                sections.append(f"```\n{vector['example']}\n```\n")

        # Common Parameters (from data)
        if data["parameters"]:
            sections.append("## Common Target Parameters\n")
            sections.append("| Parameter | Frequency |\n|---|---|\n")
            for param in data["parameters"][:15]:
                sections.append(f"| `{param.get('name', '')}` | {param.get('total_freq', param.get('frequency', 0))} |\n")
            sections.append("")

        # Bypass Techniques
        sections.append("## Bypass Techniques\n")
        for bypass in template.get("bypasses", []):
            sections.append(f"### {bypass['name']}\n")
            sections.append(f"{bypass['description']}\n")
            if bypass.get("payload"):
                sections.append(f"```\n{bypass['payload']}\n```\n")

        # Automation
        sections.append("## Automation Tips\n")
        for tip in template.get("automation", []):
            sections.append(f"- {tip}\n")

        # Checklist
        sections.append("\n## Testing Checklist\n")
        for item in template.get("checklist", []):
            sections.append(f"- [ ] {item}\n")

        # References
        sections.append("\n## References\n")
        for ref in template.get("references", []):
            sections.append(f"- [{ref['title']}]({ref['url']})\n")

        return "\n".join(sections)

    def _build_index(self, categories: List[str]):
        """Build index page for the knowledgebase."""
        content = ["# Bug Bounty Knowledgebase\n"]
        content.append("## Categories\n")

        for category in sorted(categories):
            if category in CATEGORY_TEMPLATES:
                title = CATEGORY_TEMPLATES[category]["title"]
                content.append(f"- [{title}](./{category}.md)\n")

        content.append("\n## Quick Reference\n")
        content.append("| Category | Severity | Common Impact |\n|---|---|---|\n")

        severity_map = {
            "ssrf": ("High-Critical", "Internal access, cloud metadata, RCE"),
            "xss": ("Medium-High", "Account takeover, data theft, phishing"),
            "sqli": ("High-Critical", "Data breach, auth bypass, RCE"),
            "idor": ("Medium-High", "Data exposure, unauthorized actions"),
            "business_logic": ("Medium-Critical", "Financial loss, privilege escalation"),
            "rce": ("Critical", "Full system compromise"),
            "lfi": ("High-Critical", "Source code disclosure, RCE"),
            "xxe": ("High-Critical", "File read, SSRF, DoS"),
        }

        for cat in sorted(categories):
            if cat in severity_map:
                sev, impact = severity_map[cat]
                content.append(f"| {cat.upper()} | {sev} | {impact} |\n")

        index_path = self.output_dir / "README.md"
        with open(index_path, "w") as f:
            f.write("\n".join(content))
