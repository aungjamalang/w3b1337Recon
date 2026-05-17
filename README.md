# W3b1337Recon - Bug Bounty Recon Framework

```
 __        ____  _     _ _____ ____ _____ ____                      
 \ \      / /___|_) __/ |___ /|___ \___  |  _ \ ___  ___ ___  _ __  
  \ \ /\ / /__  \| '_ \_| |_ \ __) / / | |_) / _ \/ __/ _ \| '_ \ 
   \ V  V / ___) | |_) | |___) / __/ / /|  _ <  __/ (_| (_) | | | |
    \_/\_/ |____/|_.__/|_|____/_____|_/ |_| \_\___|\___\___/|_| |_|
```

> Automated Bug Bounty Report Collection, Analysis, and Weaponization Framework

## Overview

W3b1337Recon is a comprehensive Python framework that collects disclosed bug bounty reports from multiple platforms, extracts actionable intelligence (payloads, parameters, bypass techniques), generates scanning tools, and provides a searchable dashboard for security researchers.

**Key Features:**
- Multi-platform report collection (HackerOne, Bugcrowd, Intigriti, YesWeHack, GitHub)
- Automated payload and wordlist extraction from real-world reports
- Category-specific vulnerability scanners (SSRF, XSS, SQLi, IDOR, Business Logic)
- Structured knowledgebase with testing methodologies
- Web dashboard with search, filtering, and visualization
- Async HTTP with proxy rotation and rate limiting
- SQLite database with checkpoint/resume support

---

## Installation

```bash
# Clone the repository
git clone https://github.com/aungjamalang/w3b1337Recon.git
cd w3b1337Recon

# Install dependencies
pip install -r requirements.txt

# Initialize the framework
python main.py init
```

### Requirements
- Python 3.10+
- pip packages (see requirements.txt)

---

## Quick Start

```bash
# 1. Initialize project structure and config
python main.py init

# 2. Configure API tokens (optional, enables full API access)
# Edit config.yaml with your tokens

# 3. Collect reports from platforms
python main.py collect --platform hackerone --limit 100

# 4. Analyze reports and generate artifacts
python main.py analyze

# 5. Build knowledgebase documentation
python main.py build-kb

# 6. Launch the web dashboard
python main.py dashboard --port 5000

# 7. Run vulnerability scanners
python main.py scan-ssrf --target https://example.com/fetch?url=test
python main.py scan-xss --target https://example.com/search?q=test
python main.py scan-sqli --target https://example.com/item?id=1
```

---

## Architecture

```
w3b1337Recon/
├── core/                    # Shared utilities and base classes
│   ├── config.py           # YAML configuration + env overrides
│   ├── http_client.py      # Async HTTP (aiohttp) + proxy + rate limiting
│   ├── storage.py          # SQLite storage layer with checkpoints
│   └── utils.py            # Logging, banner, helpers
├── collectors/             # Report collection modules
│   ├── base.py            # BaseCollector ABC + data models
│   ├── hackerone.py       # HackerOne (GraphQL + scraping)
│   ├── bugcrowd.py        # Bugcrowd (VRT mapping)
│   ├── intigriti.py       # Intigriti
│   ├── yeswehack.py       # YesWeHack
│   └── github.py          # GitHub (advisories + repos + search)
├── analyzer/              # Report analysis engine
│   ├── extractor.py       # Metadata/payload extraction (regex + context)
│   ├── patterns.py        # Pattern detection & trend analysis
│   └── generator.py       # Artifact generation (payloads, wordlists, rules)
├── knowledgebase/         # Methodology documentation builder
│   ├── builder.py         # Markdown doc generator
│   └── templates.py       # Category methodology templates
├── tools/                 # Vulnerability scanners
│   ├── ssrf_tool/         # SSRF scanner (cloud metadata, protocol smuggling)
│   ├── xss_tool/          # XSS scanner (context detection, filter bypass)
│   ├── sqli_tool/         # SQLi scanner (error/blind/time/union)
│   ├── idor_tool/         # IDOR scanner (horizontal/vertical escalation)
│   └── business_logic_tool/ # Logic scanner (race condition, manipulation)
├── dashboard/             # Web UI
│   ├── app.py            # Flask application + REST API
│   └── templates/        # HTML templates (Bootstrap 5 dark theme)
├── data/                  # Generated data (auto-created)
│   ├── payloads/         # Category-specific payload JSONs
│   ├── wordlists/        # Fuzzing wordlists
│   └── rules/            # Detection rules
├── main.py               # Main CLI entry point
├── config.yaml           # Configuration (auto-generated)
└── requirements.txt      # Python dependencies
```

---

## CLI Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `python main.py init` | Initialize framework (create dirs, default config) |
| `python main.py collect` | Collect reports from bug bounty platforms |
| `python main.py analyze` | Analyze reports and generate payloads/wordlists |
| `python main.py build-kb` | Build knowledgebase methodology docs |
| `python main.py dashboard` | Start the web dashboard |
| `python main.py search` | Search collected reports |
| `python main.py stats` | Show database statistics |

### Scanner Commands

| Command | Description |
|---------|-------------|
| `python main.py scan-ssrf` | Run SSRF scanner |
| `python main.py scan-xss` | Run XSS scanner |
| `python main.py scan-sqli` | Run SQL Injection scanner |
| `python main.py scan-idor` | Run IDOR scanner |
| `python main.py scan-logic` | Run Business Logic scanner |

### Examples

```bash
# Collect from specific platform
python main.py collect --platform hackerone --limit 500

# Collect from all platforms
python main.py collect --platform all --limit 200

# Analyze specific categories
python main.py analyze --categories ssrf,xss,sqli

# Search reports
python main.py search --category ssrf --severity critical
python main.py search --keyword "metadata" --json-output

# Run scanners with proxy (Burp Suite)
python main.py scan-ssrf -t "https://target.com/api/fetch?url=x" -p http://127.0.0.1:8080
python main.py scan-xss -t "https://target.com/search?q=test" --threads 20
python main.py scan-sqli -t "https://target.com/item?id=1" --technique time
python main.py scan-idor -t "https://target.com/api/users/123" -a "Bearer TOKEN"
python main.py scan-logic -t "https://target.com/api/transfer" --test-type race
```

---

## Configuration

The framework uses `config.yaml` for settings. Generate a default one with `python main.py init`.

### Environment Variables

```bash
export BUGRECON_HACKERONE_TOKEN="your_token"
export BUGRECON_HACKERONE_USER="your_username"
export BUGRECON_BUGCROWD_TOKEN="your_token"
export BUGRECON_GITHUB_TOKEN="your_github_pat"
export BUGRECON_HTTP_PROXY="http://127.0.0.1:8080"
```

### Config File (config.yaml)

```yaml
general:
  output_dir: data
  log_level: INFO
  max_concurrent_requests: 50

proxy:
  enabled: false
  http_proxy: http://127.0.0.1:8080

rate_limit:
  requests_per_second: 5
  burst_size: 10
  retry_attempts: 3

platforms:
  hackerone:
    enabled: true
    api_token: null
    api_username: null
  github:
    enabled: true
    api_token: null

dashboard:
  host: 0.0.0.0
  port: 5000
```

---

## Dashboard

The web dashboard provides:
- **Overview** - Statistics, charts (category/platform distribution)
- **Reports** - Searchable/filterable table with pagination
- **Payloads** - Browse extracted payloads by category
- **Parameters** - Top attacked parameters with frequency
- **Patterns** - Detected attack patterns and bypass techniques
- **Statistics** - Detailed analytics and breakdowns

Access at `http://localhost:5000` after running `python main.py dashboard`.

### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/reports?category=ssrf&severity=high` | Search reports |
| `GET /api/stats` | Get statistics |
| `GET /api/payloads/<category>` | Get payloads |
| `GET /api/export` | Export all data as JSON |

---

## Vulnerability Scanners

### SSRF Scanner
Tests for Server-Side Request Forgery with:
- Cloud metadata endpoints (AWS, GCP, Azure)
- IP bypass formats (decimal, hex, octal, IPv6)
- Protocol smuggling (gopher, dict, file)
- DNS rebinding detection
- OOB (out-of-band) callback support

### XSS Scanner
Tests for Cross-Site Scripting with:
- Automatic context detection (HTML, attribute, JavaScript)
- Event handler payloads
- Filter bypass techniques
- Template injection detection
- CSP header analysis

### SQLi Scanner
Tests for SQL Injection with:
- Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite fingerprinting)
- Boolean blind
- Time-based blind
- UNION-based column enumeration

### IDOR Scanner
Tests for Insecure Direct Object References:
- Horizontal privilege escalation
- Vertical escalation
- Path-based IDOR
- HTTP method bypass
- UUID prediction

### Business Logic Scanner
Tests for logic vulnerabilities:
- Race conditions (concurrent request testing)
- Numeric manipulation (negative values, overflow)
- Rate limit enforcement
- HTTP method override
- Parameter/privilege injection

---

## Generated Artifacts

After running `python main.py analyze`, the framework generates:

| Artifact | Path | Description |
|----------|------|-------------|
| Payloads | `data/payloads/<category>_payloads.json` | Category-specific attack payloads |
| Wordlists | `data/wordlists/<category>_wordlist.txt` | Fuzzing wordlists |
| Detection Rules | `data/rules/<category>_rules.json` | Regex detection rules |

---

## Supported Vulnerability Categories

| Category | ID | Scanner |
|----------|-----|---------|
| Server-Side Request Forgery | `ssrf` | scan-ssrf |
| Cross-Site Scripting | `xss` | scan-xss |
| SQL Injection | `sqli` | scan-sqli |
| Insecure Direct Object Reference | `idor` | scan-idor |
| Business Logic | `business_logic` | scan-logic |
| Remote Code Execution | `rce` | - |
| Local File Inclusion | `lfi` | - |
| XML External Entity | `xxe` | - |
| Cross-Site Request Forgery | `csrf` | - |
| Open Redirect | `open_redirect` | - |

---

## Ethical Usage

**This framework is designed for authorized security testing only.**

- Only use scanners on targets where you have explicit authorization
- Respect rate limits and responsible disclosure policies
- All tools display warning banners on startup
- No automated exploitation capabilities (scanning/detection only)
- Follow your platform's rules of engagement

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-collector`)
3. Implement your changes
4. Submit a pull request

### Extension Points
- **New Collectors**: Inherit from `BaseCollector` in `collectors/base.py`
- **New Scanners**: Follow the pattern in `tools/` directory
- **New Categories**: Add templates in `knowledgebase/templates.py`

---

## License

This project is for educational and authorized security testing purposes only.
Use responsibly and in compliance with applicable laws.

---

## Author

**Aung Ja Malang** - Security Researcher

---

## Acknowledgments

- OWASP Testing Methodology
- HackerOne Disclosed Reports
- PayloadsAllTheThings
- PortSwigger Research
- The Bug Bounty Community
