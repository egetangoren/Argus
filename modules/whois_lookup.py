#!/usr/bin/env python3
"""
Whois Lookup Module

Queries WHOIS databases to retrieve domain registration information
including registrar, creation/expiration dates, nameservers, and
registrant contact details.
"""

from __future__ import annotations

from datetime import datetime

import whois
from rich.console import Console
from rich.table import Table

console = Console()


class WhoisLookup:
    """Performs WHOIS queries against target domains to retrieve registration data."""

    def __init__(self, target: str) -> None:
        self.target = target

    def _safe_get(self, value: object, default: str = "N/A") -> str | list:
        """Safely extract a value, returning a default string if None or empty.

        Handles scalar values and lists uniformly. For lists, returns the
        first element as a string unless it is a multi-value field.

        Args:
            value: Raw value from the WHOIS response object.
            default: Fallback string when the value is missing.

        Returns:
            str | list: Cleaned value ready for reporting.
        """
        if value is None:
            return default
        if isinstance(value, list):
            return [str(item) for item in value] if value else default
        return str(value) if value else default

    def _format_date(self, date_value: datetime | list | None) -> str:
        """Convert a date or list of dates into a human-readable string.

        Some WHOIS servers return multiple dates for the same field.
        This method normalises them to a single formatted string.

        Args:
            date_value: A datetime, a list of datetimes, or None.

        Returns:
            str: Formatted date string or 'N/A'.
        """
        if date_value is None:
            return "N/A"
        if isinstance(date_value, list):
            if not date_value:
                return "N/A"
            date_value = date_value[0]
        if isinstance(date_value, datetime):
            return date_value.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(date_value)

    def _format_nameservers(self, nameservers: list | str | None) -> list[str]:
        """Normalize nameservers to a deduplicated, sorted lowercase list.

        Args:
            nameservers: Raw nameserver data from the WHOIS response.

        Returns:
            list[str]: Cleaned nameserver list or ['N/A'] if unavailable.
        """
        if nameservers is None:
            return ["N/A"]
        if isinstance(nameservers, str):
            return [nameservers.lower()]
        return sorted(set(ns.lower() for ns in nameservers))

    def _format_status(self, status: list | str | None) -> list[str]:
        """Normalize domain status codes to a clean list.

        Args:
            status: Raw status data from the WHOIS response.

        Returns:
            list[str]: Status codes or ['N/A'] if unavailable.
        """
        if status is None:
            return ["N/A"]
        if isinstance(status, str):
            return [status]
        return list(status) if status else ["N/A"]

    def _display_results(self, results: dict) -> None:
        """Render WHOIS results as a formatted Rich table in the terminal.

        Args:
            results: Parsed WHOIS data dictionary.
        """
        table = Table(
            title=f"WHOIS — {self.target}",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("Field", style="cyan", min_width=22)
        table.add_column("Value", style="white", min_width=36)

        field_labels = {
            "domain_name": "Domain Name",
            "registrar": "Registrar",
            "whois_server": "WHOIS Server",
            "creation_date": "Creation Date",
            "expiration_date": "Expiration Date",
            "updated_date": "Updated Date",
            "nameservers": "Nameservers",
            "status": "Status",
            "registrant_country": "Registrant Country",
            "dnssec": "DNSSEC",
            "org": "Organization",
            "emails": "Contact Emails",
        }

        for key, label in field_labels.items():
            value = results.get(key, "N/A")
            if isinstance(value, list):
                value = "\n".join(str(v) for v in value)
            table.add_row(label, str(value))

        console.print()
        console.print(table)

    def run(self) -> dict:
        """Execute WHOIS lookup and return parsed registration data.

        Connects to the appropriate WHOIS server for the target domain,
        parses all available registration fields, and normalises missing
        values to 'N/A' for consistent downstream processing.

        Returns:
            dict: Structured WHOIS information including registrar,
                  dates, nameservers, and contact details.
                  Contains an 'error' key on failure.
        """
        try:
            console.print(
                f"  [dim]→ Querying WHOIS for [white]{self.target}[/white]...[/dim]"
            )
            raw = whois.whois(self.target)

            if raw.domain_name is None:
                console.print(
                    f"  [yellow][!] No WHOIS data returned for {self.target}. "
                    f"The domain may not be registered.[/yellow]"
                )
                return {"error": "No WHOIS data returned", "target": self.target}

            results = {
                "domain_name": self._safe_get(raw.domain_name),
                "registrar": self._safe_get(raw.registrar),
                "whois_server": self._safe_get(raw.whois_server),
                "creation_date": self._format_date(raw.creation_date),
                "expiration_date": self._format_date(raw.expiration_date),
                "updated_date": self._format_date(raw.updated_date),
                "nameservers": self._format_nameservers(raw.name_servers),
                "status": self._format_status(raw.status),
                "registrant_country": self._safe_get(raw.country),
                "dnssec": self._safe_get(raw.dnssec),
                "org": self._safe_get(raw.org),
                "emails": self._safe_get(raw.emails),
            }

            self._display_results(results)
            return results

        except whois.parser.PywhoisError as exc:
            console.print(
                f"  [bold red][!] WHOIS query rejected for "
                f"{self.target}: {exc}[/bold red]"
            )
            return {"error": f"WHOIS query rejected: {exc}", "target": self.target}

        except ConnectionError as exc:
            console.print(
                f"  [bold red][!] Connection failed to WHOIS server: {exc}[/bold red]"
            )
            return {"error": f"Connection failed: {exc}", "target": self.target}

        except TimeoutError as exc:
            console.print(
                f"  [bold red][!] WHOIS query timed out for "
                f"{self.target}: {exc}[/bold red]"
            )
            return {"error": f"Timeout: {exc}", "target": self.target}

        except Exception as exc:
            console.print(
                f"  [bold red][!] Unexpected error during WHOIS lookup: {exc}[/bold red]"
            )
            return {"error": f"Unexpected error: {exc}", "target": self.target}
