#!/usr/bin/env python3
"""W3b1337Recon - Bug Bounty Recon Framework - Main CLI Entry Point."""

import sys
import asyncio
import json
import logging
from pathlib import Path

import click
from colorama import Fore, Style

from core.config import Config
from core.http_client import AsyncHTTPClient
from core.storage import Storage
from core.utils import print_banner, setup_logging


@click.group()
@click.option('--config', '-c', 'config_path', default=None, help='Path to config file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config_path, verbose):
    """W3b1337Recon - Bug Bounty Recon Framework.

    Collect, analyze, and weaponize bug bounty reports for security research.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = Config(config_path)
    ctx.obj['verbose'] = verbose
    if verbose:
        setup_logging("DEBUG")
    else:
        setup_logging("INFO")


# === COLLECT COMMAND ===

@cli.command()
@click.option('--platform', '-p', type=click.Choice(['hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'github', 'all']), default='all')
@click.option('--limit', '-l', default=100, help='Maximum reports to collect')
@click.option('--resume/--no-resume', default=True, help='Resume from checkpoint')
@click.pass_context
def collect(ctx, platform, limit, resume):
    """Collect disclosed bug bounty reports from platforms."""
    print_banner()
    config = ctx.obj['config']
    storage = Storage(config.get("database", "path", default="data/recon.db"))

    click.echo(f"{Fore.CYAN}[*] Collecting reports{Style.RESET_ALL}")
    click.echo(f"    Platform: {platform}")
    click.echo(f"    Limit: {limit}")
    click.echo(f"    Resume: {resume}")
    click.echo()

    async def _collect():
        async with AsyncHTTPClient(config) as client:
            collectors = []

            if platform in ('all', 'hackerone'):
                from collectors.hackerone import HackerOneCollector
                collectors.append(HackerOneCollector(config, client, storage))
            if platform in ('all', 'bugcrowd'):
                from collectors.bugcrowd import BugcrowdCollector
                collectors.append(BugcrowdCollector(config, client, storage))
            if platform in ('all', 'intigriti'):
                from collectors.intigriti import IntigritiCollector
                collectors.append(IntigritiCollector(config, client, storage))
            if platform in ('all', 'yeswehack'):
                from collectors.yeswehack import YesWeHackCollector
                collectors.append(YesWeHackCollector(config, client, storage))
            if platform in ('all', 'github'):
                from collectors.github import GitHubCollector
                collectors.append(GitHubCollector(config, client, storage))

            total_collected = 0
            for collector in collectors:
                click.echo(f"{Fore.GREEN}[+] Running {collector.PLATFORM_NAME} collector...{Style.RESET_ALL}")
                try:
                    reports = await collector.collect(limit=limit, resume=resume)
                    total_collected += len(reports)
                    click.echo(f"    Collected: {len(reports)} reports")
                except Exception as e:
                    click.echo(f"{Fore.RED}    Error: {e}{Style.RESET_ALL}")

            return total_collected

    total = asyncio.run(_collect())
    click.echo(f"\n{Fore.GREEN}[+] Total collected: {total} reports{Style.RESET_ALL}")
    click.echo(f"[*] Database: {config.get('database', 'path', default='data/recon.db')}")


# === ANALYZE COMMAND ===

@cli.command()
@click.option('--categories', '-cat', default=None, help='Comma-separated categories (e.g., ssrf,xss,sqli)')
@click.option('--output', '-o', default='data', help='Output directory')
@click.pass_context
def analyze(ctx, categories, output):
    """Analyze collected reports and generate artifacts."""
    print_banner()
    config = ctx.obj['config']
    storage = Storage(config.get("database", "path", default="data/recon.db"))

    from analyzer.generator import ArtifactGenerator

    cat_list = categories.split(',') if categories else None
    click.echo(f"{Fore.CYAN}[*] Analyzing reports{Style.RESET_ALL}")
    click.echo(f"    Categories: {cat_list or 'all'}")
    click.echo(f"    Output: {output}/")
    click.echo()

    generator = ArtifactGenerator(storage, output_dir=output)
    generator.generate_all(categories=cat_list)

    click.echo(f"\n{Fore.GREEN}[+] Analysis complete{Style.RESET_ALL}")
    click.echo(f"    Payloads: {output}/payloads/")
    click.echo(f"    Wordlists: {output}/wordlists/")
    click.echo(f"    Rules: {output}/rules/")


# === GENERATE-TOOL COMMAND ===

@cli.command('generate-tool')
@click.option('--category', '-cat', required=True, type=click.Choice(['ssrf', 'xss', 'sqli', 'idor', 'business_logic']))
@click.option('--output', '-o', default=None, help='Output directory')
@click.pass_context
def generate_tool(ctx, category, output):
    """Generate a standalone scanning tool for a category."""
    print_banner()

    if not output:
        output = f"tools/{category}_tool"

    click.echo(f"{Fore.CYAN}[*] Tool ready: {category}{Style.RESET_ALL}")
    click.echo(f"    Location: {output}/scanner.py")
    click.echo(f"\n    Usage:")
    click.echo(f"    python {output}/scanner.py --target <URL> --proxy http://127.0.0.1:8080")


# === BUILD-KB COMMAND ===

@cli.command('build-kb')
@click.option('--categories', '-cat', default=None, help='Comma-separated categories')
@click.option('--output', '-o', default='knowledgebase/categories', help='Output directory')
@click.pass_context
def build_kb(ctx, categories, output):
    """Build the knowledgebase documentation."""
    print_banner()
    config = ctx.obj['config']
    storage = Storage(config.get("database", "path", default="data/recon.db"))

    from knowledgebase.builder import KnowledgebaseBuilder

    cat_list = categories.split(',') if categories else None
    click.echo(f"{Fore.CYAN}[*] Building knowledgebase{Style.RESET_ALL}")
    click.echo(f"    Categories: {cat_list or 'all'}")
    click.echo(f"    Output: {output}/")
    click.echo()

    builder = KnowledgebaseBuilder(storage, output_dir=output)
    builder.build(categories=cat_list)

    click.echo(f"\n{Fore.GREEN}[+] Knowledgebase built{Style.RESET_ALL}")
    click.echo(f"    Location: {output}/")


# === DASHBOARD COMMAND ===

@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Dashboard host')
@click.option('--port', '-p', default=5000, help='Dashboard port')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def dashboard(ctx, host, port, debug):
    """Start the web dashboard."""
    print_banner()
    config = ctx.obj['config']

    click.echo(f"{Fore.CYAN}[*] Starting dashboard{Style.RESET_ALL}")
    click.echo(f"    URL: http://{host}:{port}")
    click.echo()

    from dashboard.app import create_app
    app = create_app(config)
    app.run(host=host, port=port, debug=debug)


# === SEARCH COMMAND ===

@cli.command()
@click.option('--category', '-cat', default=None, help='Filter by category')
@click.option('--platform', '-p', default=None, help='Filter by platform')
@click.option('--severity', '-s', default=None, help='Filter by severity')
@click.option('--keyword', '-k', default=None, help='Search keyword')
@click.option('--limit', '-l', default=20, help='Results limit')
@click.option('--json-output', '-j', is_flag=True, help='Output as JSON')
@click.pass_context
def search(ctx, category, platform, severity, keyword, limit, json_output):
    """Search collected reports."""
    config = ctx.obj['config']
    storage = Storage(config.get("database", "path", default="data/recon.db"))

    results = storage.search_reports(
        category=category, platform=platform,
        severity=severity, keyword=keyword, limit=limit,
    )

    if json_output:
        click.echo(json.dumps(results, indent=2, default=str))
    else:
        if not results:
            click.echo(f"{Fore.YELLOW}No reports found.{Style.RESET_ALL}")
            return

        click.echo(f"\n{Fore.GREEN}Found {len(results)} reports:{Style.RESET_ALL}\n")
        for report in results:
            sev = report.get('severity', 'unknown')
            sev_colors = {'critical': Fore.RED, 'high': Fore.LIGHTRED_EX, 'medium': Fore.YELLOW, 'low': Fore.GREEN}
            color = sev_colors.get(sev, Fore.WHITE)
            click.echo(
                f"  {color}[{sev.upper():8s}]{Style.RESET_ALL} "
                f"{report.get('title', 'Untitled')[:70]}"
            )
            click.echo(
                f"           {Fore.CYAN}{report.get('category', '?')}{Style.RESET_ALL} | "
                f"{report.get('platform', '?')} | "
                f"{'$'+str(int(report.get('bounty_amount', 0))) if report.get('bounty_amount') else 'No bounty'}"
            )


# === STATS COMMAND ===

@cli.command()
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    config = ctx.obj['config']
    storage = Storage(config.get("database", "path", default="data/recon.db"))
    statistics = storage.get_statistics()

    print_banner()
    click.echo(f"{Fore.CYAN}Database Statistics{Style.RESET_ALL}")
    click.echo(f"{'='*40}")
    click.echo(f"  Total Reports:    {statistics['total_reports']}")
    click.echo(f"  Total Payloads:   {statistics['total_payloads']}")
    click.echo(f"  Total Parameters: {statistics['total_parameters']}")
    click.echo(f"  Total Patterns:   {statistics['total_patterns']}")
    click.echo()

    if statistics.get('reports_by_category'):
        click.echo(f"{Fore.GREEN}By Category:{Style.RESET_ALL}")
        for cat, count in statistics['reports_by_category'].items():
            bar = '#' * min(count, 30)
            click.echo(f"  {cat:20s} {count:5d}  {Fore.BLUE}{bar}{Style.RESET_ALL}")

    if statistics.get('reports_by_platform'):
        click.echo(f"\n{Fore.GREEN}By Platform:{Style.RESET_ALL}")
        for plat, count in statistics['reports_by_platform'].items():
            bar = '#' * min(count, 30)
            click.echo(f"  {plat:20s} {count:5d}  {Fore.CYAN}{bar}{Style.RESET_ALL}")


# === SCAN COMMANDS (Shortcuts to individual tools) ===

@cli.command('scan-ssrf')
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--callback', '-c', help='OOB callback URL')
@click.option('--threads', default=10, help='Threads')
@click.option('--wordlist', '-w', help='Custom wordlist')
@click.option('--output', '-o', default='ssrf_results.json', help='Output file')
@click.pass_context
def scan_ssrf(ctx, target, proxy, callback, threads, wordlist, output):
    """Run SSRF scanner against a target."""
    print_banner()
    config = ctx.obj['config']
    from tools.ssrf_tool.scanner import SSRFScanner

    scanner = SSRFScanner(target, config, proxy=proxy, callback_url=callback, threads=threads)
    results = asyncio.run(scanner.scan(wordlist))

    click.echo(f"\n{Fore.GREEN}[+] SSRF Scan: {len(results)} findings{Style.RESET_ALL}")
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)


@cli.command('scan-xss')
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--threads', default=10, help='Threads')
@click.option('--wordlist', '-w', help='Custom wordlist')
@click.option('--output', '-o', default='xss_results.json', help='Output file')
@click.pass_context
def scan_xss(ctx, target, proxy, threads, wordlist, output):
    """Run XSS scanner against a target."""
    print_banner()
    config = ctx.obj['config']
    from tools.xss_tool.scanner import XSSScanner

    scanner = XSSScanner(target, config, proxy=proxy, threads=threads)
    results = asyncio.run(scanner.scan(wordlist))

    click.echo(f"\n{Fore.GREEN}[+] XSS Scan: {len(results)} findings{Style.RESET_ALL}")
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)


@cli.command('scan-sqli')
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--technique', default='all', type=click.Choice(['all', 'error', 'blind', 'time', 'union']))
@click.option('--threads', default=10, help='Threads')
@click.option('--output', '-o', default='sqli_results.json', help='Output file')
@click.pass_context
def scan_sqli(ctx, target, proxy, technique, threads, output):
    """Run SQLi scanner against a target."""
    print_banner()
    config = ctx.obj['config']
    from tools.sqli_tool.scanner import SQLiScanner

    scanner = SQLiScanner(target, config, proxy=proxy, threads=threads, technique=technique)
    results = asyncio.run(scanner.scan())

    click.echo(f"\n{Fore.GREEN}[+] SQLi Scan: {len(results)} findings{Style.RESET_ALL}")
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)


@cli.command('scan-idor')
@click.option('--target', '-t', required=True, help='Target URL with ID parameter')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--auth-token', '-a', help='Auth token')
@click.option('--threads', default=10, help='Threads')
@click.option('--output', '-o', default='idor_results.json', help='Output file')
@click.pass_context
def scan_idor(ctx, target, proxy, auth_token, threads, output):
    """Run IDOR scanner against a target."""
    print_banner()
    config = ctx.obj['config']
    from tools.idor_tool.scanner import IDORScanner

    scanner = IDORScanner(target, config, proxy=proxy, auth_token=auth_token, threads=threads)
    results = asyncio.run(scanner.scan())

    click.echo(f"\n{Fore.GREEN}[+] IDOR Scan: {len(results)} findings{Style.RESET_ALL}")
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)


@cli.command('scan-logic')
@click.option('--target', '-t', required=True, help='Target endpoint')
@click.option('--proxy', '-p', help='Proxy URL')
@click.option('--auth-token', '-a', help='Auth token')
@click.option('--test-type', default='all', type=click.Choice(['all', 'race', 'numeric', 'rate', 'method', 'parameter']))
@click.option('--output', '-o', default='logic_results.json', help='Output file')
@click.pass_context
def scan_logic(ctx, target, proxy, auth_token, test_type, output):
    """Run business logic scanner against a target."""
    print_banner()
    config = ctx.obj['config']
    from tools.business_logic_tool.scanner import BusinessLogicScanner

    scanner = BusinessLogicScanner(target, config, proxy=proxy, auth_token=auth_token)
    results = asyncio.run(scanner.scan(test_type))

    click.echo(f"\n{Fore.GREEN}[+] Logic Scan: {len(results)} findings{Style.RESET_ALL}")
    with open(output, 'w') as f:
        json.dump({"target": target, "findings": results}, f, indent=2)


# === INIT COMMAND ===

@cli.command()
@click.pass_context
def init(ctx):
    """Initialize the framework (create config and data directories)."""
    print_banner()

    # Create directories
    dirs = ['data', 'data/payloads', 'data/wordlists', 'data/rules', 'knowledgebase/categories']
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
        click.echo(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Created: {d}/")

    # Create default config if not exists
    config_path = Path("config.yaml")
    if not config_path.exists():
        config = Config()
        config.save("config.yaml")
        click.echo(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Created: config.yaml")
    else:
        click.echo(f"  {Fore.YELLOW}[~]{Style.RESET_ALL} config.yaml already exists")

    click.echo(f"\n{Fore.GREEN}[+] Framework initialized!{Style.RESET_ALL}")
    click.echo(f"\nNext steps:")
    click.echo(f"  1. Edit config.yaml with your API tokens")
    click.echo(f"  2. Run: python main.py collect --platform hackerone")
    click.echo(f"  3. Run: python main.py analyze")
    click.echo(f"  4. Run: python main.py dashboard")


if __name__ == '__main__':
    cli()
