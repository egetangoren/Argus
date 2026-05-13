#!/usr/bin/env python3
"""
Subdomain Enumeration Module

Discovers subdomains through dictionary-based brute-force resolution.
Uses a wordlist of common subdomain prefixes and resolves each candidate
against DNS to identify live subdomains of the target domain.

Leverages concurrent.futures.ThreadPoolExecutor for parallel DNS
resolution with configurable thread count and timeout values.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich.table import Table

console = Console()

DEFAULT_THREAD_COUNT = 20
DEFAULT_TIMEOUT = 3.0


class SubdomainEnumerator:
    """Brute-forces subdomain discovery using wordlist-driven DNS resolution.

    Attributes:
        target: The base domain to enumerate subdomains for.
        wordlist_path: Path to the wordlist file containing subdomain prefixes.
        thread_count: Number of concurrent resolution threads.
        timeout: DNS query timeout in seconds per subdomain.
    """

    def __init__(
        self,
        target: str,
        wordlist_path: str | None = None,
        thread_count: int = DEFAULT_THREAD_COUNT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.target = target
        self.wordlist_path = wordlist_path
        self.thread_count = thread_count
        self.timeout = timeout
        self._results_lock = threading.Lock()
        self._found: list[dict] = []

    def _load_wordlist(self) -> list[str]:
        """Load and validate the subdomain wordlist from disk.

        Reads the wordlist file line by line, stripping whitespace and
        ignoring blank lines and comments (lines starting with #).

        Returns:
            list[str]: Cleaned list of subdomain prefixes.

        Raises:
            FileNotFoundError: If the wordlist file does not exist.
        """
        if not self.wordlist_path or not os.path.isfile(self.wordlist_path):
            fallback = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..",
                "wordlists",
                "subdomains.txt",
            )
            if os.path.isfile(fallback):
                self.wordlist_path = fallback
            else:
                console.print(
                    "[bold red][!] Wordlist not found. Cannot perform "
                    "subdomain enumeration.[/bold red]"
                )
                return []

        with open(self.wordlist_path, "r", encoding="utf-8") as wl:
            words = [
                line.strip()
                for line in wl
                if line.strip() and not line.strip().startswith("#")
            ]

        return words

    def _resolve_subdomain(self, prefix: str) -> dict | None:
        """Attempt DNS A-record resolution for a single subdomain candidate.

        Constructs the FQDN from the prefix and the target domain, then
        queries for an A record. Thread-safe: appends results under a lock.

        Args:
            prefix: The subdomain prefix to test (e.g., 'www', 'mail').

        Returns:
            dict | None: Subdomain data with FQDN and resolved IPs on
                         success, or None if the subdomain does not resolve.
        """
        fqdn = f"{prefix}.{self.target}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [rdata.address for rdata in answers]

            result = {
                "subdomain": fqdn,
                "prefix": prefix,
                "ips": ips,
                "ttl": answers.rrset.ttl,
            }

            with self._results_lock:
                self._found.append(result)

            return result

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None

    def _display_results(self) -> None:
        """Render discovered subdomains as a formatted Rich table."""
        if not self._found:
            console.print(
                f"  [yellow][!] No subdomains discovered for "
                f"{self.target}[/yellow]"
            )
            return

        sorted_results = sorted(self._found, key=lambda r: r["subdomain"])

        table = Table(
            title=f"Subdomains — {self.target}",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("#", style="dim", justify="right", min_width=4)
        table.add_column("Subdomain", style="cyan", min_width=30)
        table.add_column("IP Address(es)", style="green", min_width=20)
        table.add_column("TTL", justify="right", style="dim", min_width=6)

        for idx, entry in enumerate(sorted_results, start=1):
            ips = ", ".join(entry["ips"])
            table.add_row(
                str(idx),
                entry["subdomain"],
                ips,
                str(entry["ttl"]),
            )

        console.print()
        console.print(table)

    def run(self) -> dict:
        """Execute multithreaded subdomain brute-force enumeration.

        Loads the wordlist, distributes DNS resolution tasks across a
        thread pool, tracks progress in real time, and aggregates all
        discovered subdomains into a structured dictionary.

        Returns:
            dict: Enumeration results containing discovered subdomains,
                  total candidates tested, and configuration metadata.
                  Contains an 'error' key on critical failure.
        """
        console.print(
            f"  [dim]→ Loading wordlist from "
            f"[white]{self.wordlist_path or 'default'}[/white]...[/dim]"
        )

        wordlist = self._load_wordlist()
        if not wordlist:
            return {
                "error": "Empty or missing wordlist",
                "discovered": [],
                "total_tested": 0,
            }

        total = len(wordlist)
        console.print(
            f"  [dim]→ Loaded [white]{total}[/white] subdomain candidates[/dim]"
        )
        console.print(
            f"  [dim]→ Threads: [white]{self.thread_count}[/white] | "
            f"Timeout: [white]{self.timeout}s[/white][/dim]"
        )

        self._found = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("[green]{task.fields[found]} found[/green]"),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(
                f"  Bruteforcing {self.target}",
                total=total,
                found=0,
            )

            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_map = {
                    executor.submit(self._resolve_subdomain, prefix): prefix
                    for prefix in wordlist
                }

                for future in as_completed(future_map):
                    result = future.result()
                    found_count = len(self._found)

                    if result is not None:
                        progress.console.print(
                            f"  [bold green]  ✓ {result['subdomain']} "
                            f"→ {', '.join(result['ips'])}[/bold green]"
                        )

                    progress.update(task_id, advance=1, found=found_count)

        found_count = len(self._found)
        console.print(
            f"\n  [bold cyan][+] Discovered {found_count} subdomain(s) "
            f"out of {total} candidates[/bold cyan]"
        )

        self._display_results()

        sorted_results = sorted(self._found, key=lambda r: r["subdomain"])

        return {
            "discovered": sorted_results,
            "total_tested": total,
            "total_found": found_count,
            "thread_count": self.thread_count,
            "timeout": self.timeout,
            "wordlist": self.wordlist_path,
        }
