#!/usr/bin/env python3
"""
Argus - The All-Seeing Recon Framework

A modular, CLI-based reconnaissance framework for Red Team operations.
Named after Argus Panoptes, the hundred-eyed giant of Greek mythology
who sees everything and misses nothing.

Usage:
    python main.py -t example.com --all
    python main.py -t example.com --dns --whois
    python main.py -t example.com --ports --output ./reports
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules import (
    WhoisLookup,
    DNSEnumerator,
    SubdomainEnumerator,
    PortScanner,
    HTTPProbe,
)
from modules.reporter import ReportGenerator

VERSION = "1.0.0"

BANNER = r"""
[bold cyan]
     ___                           
    /   |  _________ ___  _______  
   / /| | / ___/ __ `/ / / / ___/ 
  / ___ |/ /  / /_/ / /_/ (__  )  
 /_/  |_/_/   \__, /\__,_/____/   
              /____/               
[/bold cyan]
[dim white]  The All-Seeing Recon Framework[/dim white]
[dim white]  v{version} | github.com/argus-recon[/dim white]
"""

console = Console()


def display_banner() -> None:
    """Render the Argus ASCII banner with version info."""
    formatted_banner = BANNER.format(version=VERSION)
    console.print(formatted_banner)


def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments with target and scan flags.
    """
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus - The All-Seeing Recon Framework",
        epilog="Example: python main.py -t example.com --all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target domain or IP address to scan",
    )

    scan_group = parser.add_argument_group("Scan Modules")
    scan_group.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Run all reconnaissance modules",
    )
    scan_group.add_argument(
        "--whois",
        action="store_true",
        default=False,
        help="Perform WHOIS lookup on the target",
    )
    scan_group.add_argument(
        "--dns",
        action="store_true",
        default=False,
        help="Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)",
    )
    scan_group.add_argument(
        "--sub",
        action="store_true",
        default=False,
        help="Brute-force subdomain enumeration using wordlist",
    )
    scan_group.add_argument(
        "--ports",
        nargs="?",
        const="default",
        default=None,
        metavar="RANGE",
        help="Scan TCP ports (default: top 100). Accepts: 1-1024, 80,443,8080, or mixed",
    )
    scan_group.add_argument(
        "--http",
        action="store_true",
        default=False,
        help="Probe HTTP/HTTPS endpoints for server fingerprinting",
    )

    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output",
        type=str,
        default=None,
        help="Custom output directory for reports (default: ./output)",
    )

    args = parser.parse_args()

    scan_flags = [args.whois, args.dns, args.sub, args.ports is not None, args.http]
    if not args.all and not any(scan_flags):
        console.print(
            "[bold red][!] Error:[/bold red] No scan module selected. "
            "Use [cyan]--all[/cyan] or specify at least one module flag.\n"
        )
        parser.print_help()
        sys.exit(1)

    return args


def build_scan_plan(args: argparse.Namespace) -> list[dict]:
    """Build an ordered list of scan tasks based on selected flags.

    Args:
        args: Parsed command-line arguments.

    Returns:
        list[dict]: Scan tasks with module name, class, and constructor kwargs.
    """
    run_all = args.all
    wordlist_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "wordlists", "subdomains.txt"
    )

    scan_registry = [
        {
            "key": "whois",
            "name": "Whois Lookup",
            "enabled": run_all or args.whois,
            "cls": WhoisLookup,
            "kwargs": {},
        },
        {
            "key": "dns",
            "name": "DNS Enumeration",
            "enabled": run_all or args.dns,
            "cls": DNSEnumerator,
            "kwargs": {},
        },
        {
            "key": "subdomains",
            "name": "Subdomain Enumeration",
            "enabled": run_all or args.sub,
            "cls": SubdomainEnumerator,
            "kwargs": {"wordlist_path": wordlist_path},
        },
        {
            "key": "ports",
            "name": "Port Scan",
            "enabled": run_all or args.ports is not None,
            "cls": PortScanner,
            "kwargs": {"ports": args.ports or "default"},
        },
        {
            "key": "http",
            "name": "HTTP Probe",
            "enabled": run_all or args.http,
            "cls": HTTPProbe,
            "kwargs": {},
        },
    ]

    return [task for task in scan_registry if task["enabled"]]


def _enrich_scan_plan(scan_plan: list[dict], current_idx: int, results: dict) -> None:
    """Pass discovered data from completed modules to upcoming modules.

    After each module finishes, this function inspects the accumulated
    results and injects relevant data into the kwargs of subsequent
    modules that can benefit from it. Currently enriches:
      - HTTPProbe: receives discovered subdomains and open ports.

    Args:
        scan_plan: Mutable list of scan task descriptors.
        current_idx: Index of the module that just completed.
        results: Master results dictionary with all completed module outputs.
    """
    modules = results.get("modules", {})

    for future_task in scan_plan[current_idx + 1:]:
        if future_task["key"] == "http":
            sub_data = modules.get("subdomains", {})
            if isinstance(sub_data, dict):
                discovered = sub_data.get("discovered", [])
                future_task["kwargs"]["subdomains"] = [
                    s["subdomain"] for s in discovered
                ]

            port_data = modules.get("ports", {})
            if isinstance(port_data, dict):
                open_ports = port_data.get("open_ports", [])
                future_task["kwargs"]["open_ports"] = [
                    p["port"] for p in open_ports
                ]


def execute_scan(target: str, scan_plan: list[dict]) -> dict:
    """Execute each scan module in order and aggregate results.

    Runs modules sequentially, enriching later modules with data
    discovered by earlier ones (e.g., subdomains and open ports
    are forwarded to the HTTP probe module).

    Args:
        target: The target domain or IP address.
        scan_plan: Ordered list of scan task descriptors.

    Returns:
        dict: Master results dictionary with all module outputs.
    """
    results = {
        "target": target,
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "modules": {},
    }

    summary_table = Table(
        title="Scan Execution Summary",
        show_header=True,
        header_style="bold magenta",
    )
    summary_table.add_column("Module", style="cyan", min_width=24)
    summary_table.add_column("Status", justify="center", min_width=10)
    summary_table.add_column("Duration", justify="right", min_width=10)

    for idx, task in enumerate(scan_plan):
        module_name = task["name"]
        module_key = task["key"]
        console.print(f"\n[bold yellow][*] Running: {module_name}...[/bold yellow]")

        start_time = time.time()
        try:
            instance = task["cls"](target, **task["kwargs"])
            module_result = instance.run()
            elapsed = time.time() - start_time

            results["modules"][module_key] = module_result
            _enrich_scan_plan(scan_plan, idx, results)
            summary_table.add_row(
                module_name,
                "[bold green]✓ Done[/bold green]",
                f"{elapsed:.2f}s",
            )
        except Exception as exc:
            elapsed = time.time() - start_time
            results["modules"][module_key] = {"error": str(exc)}
            summary_table.add_row(
                module_name,
                "[bold red]✗ Failed[/bold red]",
                f"{elapsed:.2f}s",
            )
            console.print(
                f"[bold red][!] {module_name} failed:[/bold red] {exc}"
            )

    results["scan_end"] = datetime.now(timezone.utc).isoformat()

    console.print()
    console.print(summary_table)

    return results


def main() -> None:
    """Argus entry point — parse arguments, execute scans, and save reports."""
    display_banner()
    args = parse_arguments()

    target = args.target
    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [green]{target}[/green]",
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
        )
    )

    scan_plan = build_scan_plan(args)

    console.print(
        f"\n[bold cyan][+] Launching {len(scan_plan)} module(s) "
        f"against [green]{target}[/green]...[/bold cyan]"
    )

    results = execute_scan(target, scan_plan)

    default_output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "output"
    )
    reporter = ReportGenerator(
        results=results,
        target=target,
        output_path=args.output,
        default_output_dir=default_output_dir,
    )
    reporter.generate()

    console.print("\n[bold green][✓] Argus scan complete.[/bold green]\n")


if __name__ == "__main__":
    main()
