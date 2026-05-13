#!/usr/bin/env python3
"""
DNS Enumeration Module

Performs comprehensive DNS record enumeration against target domains.
Queries A, AAAA, MX, NS, TXT, CNAME, and SOA record types
to map out the DNS infrastructure of the target.

Each record type is queried independently with its own error handling,
ensuring a single failed lookup does not prevent other records from
being collected (graceful degradation).
"""

from __future__ import annotations

import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSEnumerator:
    """Enumerates DNS records for a target domain across multiple record types."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0

    def _query_a(self) -> list[dict]:
        """Resolve A (IPv4) records for the target domain.

        Returns:
            list[dict]: Each entry contains the IPv4 address and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "A")
            return [
                {"address": rdata.address, "ttl": answers.rrset.ttl}
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            console.print(
                f"  [yellow][!] Domain {self.target} does not exist (NXDOMAIN)[/yellow]"
            )
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] A record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for A record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] A record query failed: {exc}[/red]")
            return []

    def _query_aaaa(self) -> list[dict]:
        """Resolve AAAA (IPv6) records for the target domain.

        Returns:
            list[dict]: Each entry contains the IPv6 address and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "AAAA")
            return [
                {"address": rdata.address, "ttl": answers.rrset.ttl}
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] AAAA record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for AAAA record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] AAAA record query failed: {exc}[/red]")
            return []

    def _query_mx(self) -> list[dict]:
        """Resolve MX (Mail Exchange) records for the target domain.

        Returns:
            list[dict]: Each entry contains the mail server hostname,
                        priority value, and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "MX")
            records = []
            for rdata in answers:
                records.append(
                    {
                        "exchange": str(rdata.exchange).rstrip("."),
                        "priority": rdata.preference,
                        "ttl": answers.rrset.ttl,
                    }
                )
            return sorted(records, key=lambda r: r["priority"])
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] MX record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for MX record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] MX record query failed: {exc}[/red]")
            return []

    def _query_ns(self) -> list[dict]:
        """Resolve NS (Name Server) records for the target domain.

        Returns:
            list[dict]: Each entry contains the nameserver hostname and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "NS")
            return [
                {
                    "nameserver": str(rdata.target).rstrip("."),
                    "ttl": answers.rrset.ttl,
                }
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] NS record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for NS record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] NS record query failed: {exc}[/red]")
            return []

    def _query_txt(self) -> list[dict]:
        """Resolve TXT records for the target domain.

        TXT records often contain SPF policies, DKIM selectors,
        domain verification tokens, and other security-relevant data.

        Returns:
            list[dict]: Each entry contains the TXT string content and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "TXT")
            return [
                {
                    "text": str(rdata).strip('"'),
                    "ttl": answers.rrset.ttl,
                }
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] TXT record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for TXT record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] TXT record query failed: {exc}[/red]")
            return []

    def _query_cname(self) -> list[dict]:
        """Resolve CNAME (Canonical Name) records for the target domain.

        Returns:
            list[dict]: Each entry contains the canonical name alias and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "CNAME")
            return [
                {
                    "cname": str(rdata.target).rstrip("."),
                    "ttl": answers.rrset.ttl,
                }
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] CNAME record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for CNAME record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] CNAME record query failed: {exc}[/red]")
            return []

    def _query_soa(self) -> list[dict]:
        """Resolve SOA (Start of Authority) records for the target domain.

        SOA records reveal the primary nameserver, the responsible
        administrator's email, and zone timing parameters.

        Returns:
            list[dict]: Each entry contains SOA fields (mname, rname,
                        serial, refresh, retry, expire, minimum) and TTL.
        """
        try:
            answers = self.resolver.resolve(self.target, "SOA")
            return [
                {
                    "mname": str(rdata.mname).rstrip("."),
                    "rname": str(rdata.rname).rstrip("."),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                    "ttl": answers.rrset.ttl,
                }
                for rdata in answers
            ]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.exception.Timeout:
            console.print("  [yellow][!] SOA record query timed out[/yellow]")
            return []
        except dns.resolver.NoNameservers:
            console.print(
                "  [yellow][!] No nameservers available for SOA record query[/yellow]"
            )
            return []
        except Exception as exc:
            console.print(f"  [red][!] SOA record query failed: {exc}[/red]")
            return []

    def _display_results(self, results: dict) -> None:
        """Render DNS enumeration results as a formatted Rich table.

        Args:
            results: DNS records organized by record type.
        """
        table = Table(
            title=f"DNS Records — {self.target}",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("Type", style="bold cyan", min_width=8)
        table.add_column("Record", style="white", min_width=44)
        table.add_column("TTL", justify="right", style="dim", min_width=6)

        record_found = False
        for rtype in RECORD_TYPES:
            records = results.get(rtype, [])
            if not records:
                continue
            record_found = True
            for i, record in enumerate(records):
                display_type = rtype if i == 0 else ""
                ttl = str(record.get("ttl", ""))
                display_value = self._format_record_value(rtype, record)
                table.add_row(display_type, display_value, ttl)

        if not record_found:
            table.add_row("[dim]—[/dim]", "[dim]No records found[/dim]", "")

        console.print()
        console.print(table)

    def _format_record_value(self, rtype: str, record: dict) -> str:
        """Format a single DNS record into a human-readable string.

        Args:
            rtype: The DNS record type (A, MX, etc.).
            record: The record data dictionary.

        Returns:
            str: Formatted record string.
        """
        if rtype == "A":
            return record["address"]
        if rtype == "AAAA":
            return record["address"]
        if rtype == "MX":
            return f"[{record['priority']}] {record['exchange']}"
        if rtype == "NS":
            return record["nameserver"]
        if rtype == "TXT":
            text = record["text"]
            if len(text) > 72:
                return text[:69] + "..."
            return text
        if rtype == "CNAME":
            return record["cname"]
        if rtype == "SOA":
            return (
                f"{record['mname']} | admin: {record['rname']} | "
                f"serial: {record['serial']}"
            )
        return str(record)

    def run(self) -> dict:
        """Execute DNS enumeration across all supported record types.

        Queries each record type independently. A failure in one type
        does not block enumeration of the remaining types. Results are
        grouped by record type with empty lists for types that returned
        no data.

        Returns:
            dict: DNS records organized by record type
                  (A, AAAA, MX, NS, TXT, CNAME, SOA).
                  Contains an 'error' key only on catastrophic failure.
        """
        console.print(
            f"  [dim]→ Enumerating DNS records for "
            f"[white]{self.target}[/white]...[/dim]"
        )

        query_methods = {
            "A": self._query_a,
            "AAAA": self._query_aaaa,
            "MX": self._query_mx,
            "NS": self._query_ns,
            "TXT": self._query_txt,
            "CNAME": self._query_cname,
            "SOA": self._query_soa,
        }

        results = {}
        total_records = 0

        for rtype, query_fn in query_methods.items():
            records = query_fn()
            results[rtype] = records
            count = len(records)
            total_records += count
            if count > 0:
                console.print(
                    f"  [green]  ✓ {rtype}: {count} record(s) found[/green]"
                )

        console.print(
            f"  [bold cyan][+] Total: {total_records} DNS record(s) "
            f"discovered[/bold cyan]"
        )

        self._display_results(results)
        return results
