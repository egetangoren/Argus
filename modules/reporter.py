#!/usr/bin/env python3
"""
Report Generator Module

Consolidates results from all reconnaissance modules into structured
reports. Supports JSON (machine-readable) and TXT (human-readable)
output formats with automatic filename generation and custom output paths.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

console = Console()

SECTION_WIDTH = 70
HEADER_CHAR = "="
DIVIDER_CHAR = "─"


class ReportGenerator:
    """Generates JSON and TXT reports from consolidated scan results.

    Handles output path resolution, supporting both directory paths
    (auto-generates filenames) and explicit file paths with extension
    detection.

    Attributes:
        results: Master results dictionary from all scan modules.
        target: Original target domain or IP string.
        output_path: User-specified output path (file or directory).
        default_output_dir: Fallback output directory.
    """

    def __init__(
        self,
        results: dict,
        target: str,
        output_path: str | None = None,
        default_output_dir: str = "output",
    ) -> None:
        self.results = results
        self.target = target
        self.output_path = output_path
        self.default_output_dir = default_output_dir

    def _generate_base_name(self) -> str:
        """Generate a timestamped base filename from the target string.

        Returns:
            str: Base filename like 'argus_example_com_20260513_120000'.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = (
            self.target.replace(".", "_")
            .replace("/", "_")
            .replace(":", "_")
            .replace(" ", "_")
        )
        return f"argus_{safe_target}_{timestamp}"

    def _resolve_output_paths(self) -> tuple[str, str]:
        """Resolve output file paths from the user-provided output path.

        Supports three modes:
          1. No output specified → use default_output_dir with auto names.
          2. Path with .json/.txt extension → use as explicit filename,
             generate the other format alongside it.
          3. Directory path → auto-generate both filenames inside it.

        Returns:
            tuple[str, str]: Resolved (json_path, txt_path).
        """
        if not self.output_path:
            output_dir = self.default_output_dir
            os.makedirs(output_dir, exist_ok=True)
            base = self._generate_base_name()
            return (
                os.path.join(output_dir, f"{base}.json"),
                os.path.join(output_dir, f"{base}.txt"),
            )

        _, ext = os.path.splitext(self.output_path)
        ext_lower = ext.lower()

        if ext_lower == ".json":
            output_dir = os.path.dirname(self.output_path) or "."
            os.makedirs(output_dir, exist_ok=True)
            json_path = self.output_path
            txt_path = self.output_path.rsplit(".json", 1)[0] + ".txt"
            return json_path, txt_path

        if ext_lower == ".txt":
            output_dir = os.path.dirname(self.output_path) or "."
            os.makedirs(output_dir, exist_ok=True)
            txt_path = self.output_path
            json_path = self.output_path.rsplit(".txt", 1)[0] + ".json"
            return json_path, txt_path

        output_dir = self.output_path
        os.makedirs(output_dir, exist_ok=True)
        base = self._generate_base_name()
        return (
            os.path.join(output_dir, f"{base}.json"),
            os.path.join(output_dir, f"{base}.txt"),
        )

    def _write_json(self, filepath: str) -> None:
        """Serialize scan results to a formatted JSON file.

        Args:
            filepath: Absolute path for the JSON output file.
        """
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(
                self.results, fh, indent=2, ensure_ascii=False, default=str
            )

    def _write_txt(self, filepath: str) -> None:
        """Generate a structured, human-readable plaintext report.

        Organizes output into clearly labelled sections for each module
        with consistent indentation and divider lines.

        Args:
            filepath: Absolute path for the TXT output file.
        """
        lines: list[str] = []

        lines.append(HEADER_CHAR * SECTION_WIDTH)
        lines.append(self._center("ARGUS RECON REPORT"))
        lines.append(self._center("The All-Seeing Reconnaissance Framework"))
        lines.append(HEADER_CHAR * SECTION_WIDTH)
        lines.append("")
        lines.append(f"  Target     : {self.results.get('target', 'N/A')}")
        lines.append(f"  Scan Start : {self.results.get('scan_start', 'N/A')}")
        lines.append(f"  Scan End   : {self.results.get('scan_end', 'N/A')}")
        lines.append("")

        modules = self.results.get("modules", {})

        if "whois" in modules:
            self._section_whois(modules["whois"], lines)

        if "dns" in modules:
            self._section_dns(modules["dns"], lines)

        if "subdomains" in modules:
            self._section_subdomains(modules["subdomains"], lines)

        if "ports" in modules:
            self._section_ports(modules["ports"], lines)

        if "http" in modules:
            self._section_http(modules["http"], lines)

        lines.append("")
        lines.append(HEADER_CHAR * SECTION_WIDTH)
        lines.append(self._center("END OF REPORT"))
        lines.append(HEADER_CHAR * SECTION_WIDTH)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def _center(self, text: str) -> str:
        """Center a text string within the report section width.

        Args:
            text: The text to center.

        Returns:
            str: Padded centered text.
        """
        return text.center(SECTION_WIDTH)

    def _section_header(self, title: str, lines: list[str]) -> None:
        """Append a formatted section header to the report lines.

        Args:
            title: Section title text.
            lines: Accumulator list of report lines.
        """
        lines.append(DIVIDER_CHAR * SECTION_WIDTH)
        lines.append(f"  [ {title} ]")
        lines.append(DIVIDER_CHAR * SECTION_WIDTH)

    def _section_whois(self, data: dict, lines: list[str]) -> None:
        """Format WHOIS module results into the TXT report.

        Args:
            data: WHOIS results dictionary.
            lines: Accumulator list of report lines.
        """
        self._section_header("WHOIS LOOKUP", lines)
        if "error" in data:
            lines.append(f"    Error: {data['error']}")
            lines.append("")
            return

        field_map = {
            "domain_name": "Domain Name",
            "registrar": "Registrar",
            "whois_server": "WHOIS Server",
            "creation_date": "Creation Date",
            "expiration_date": "Expiration Date",
            "updated_date": "Updated Date",
            "registrant_country": "Country",
            "dnssec": "DNSSEC",
            "org": "Organization",
        }

        for key, label in field_map.items():
            value = data.get(key, "N/A")
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            lines.append(f"    {label:<20}: {value}")

        nameservers = data.get("nameservers", [])
        if isinstance(nameservers, list):
            lines.append(f"    {'Nameservers':<20}:")
            for ns in nameservers:
                lines.append(f"      - {ns}")

        status = data.get("status", [])
        if isinstance(status, list):
            lines.append(f"    {'Status':<20}:")
            for s in status:
                lines.append(f"      - {s}")

        emails = data.get("emails", "N/A")
        if isinstance(emails, list):
            lines.append(f"    {'Emails':<20}:")
            for e in emails:
                lines.append(f"      - {e}")
        else:
            lines.append(f"    {'Emails':<20}: {emails}")

        lines.append("")

    def _section_dns(self, data: dict, lines: list[str]) -> None:
        """Format DNS enumeration results into the TXT report.

        Args:
            data: DNS results dictionary organized by record type.
            lines: Accumulator list of report lines.
        """
        self._section_header("DNS ENUMERATION", lines)
        if "error" in data:
            lines.append(f"    Error: {data['error']}")
            lines.append("")
            return

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        for rtype in record_types:
            records = data.get(rtype, [])
            if not records:
                continue
            lines.append(f"    {rtype} Records ({len(records)}):")
            for rec in records:
                if rtype == "A":
                    lines.append(f"      {rec.get('address', 'N/A')}  (TTL: {rec.get('ttl', '-')})")
                elif rtype == "AAAA":
                    lines.append(f"      {rec.get('address', 'N/A')}  (TTL: {rec.get('ttl', '-')})")
                elif rtype == "MX":
                    lines.append(
                        f"      [{rec.get('priority', '-')}] "
                        f"{rec.get('exchange', 'N/A')}  (TTL: {rec.get('ttl', '-')})"
                    )
                elif rtype == "NS":
                    lines.append(f"      {rec.get('nameserver', 'N/A')}  (TTL: {rec.get('ttl', '-')})")
                elif rtype == "TXT":
                    text = rec.get("text", "N/A")
                    lines.append(f"      \"{text}\"")
                elif rtype == "CNAME":
                    lines.append(f"      {rec.get('cname', 'N/A')}  (TTL: {rec.get('ttl', '-')})")
                elif rtype == "SOA":
                    lines.append(f"      Primary NS : {rec.get('mname', 'N/A')}")
                    lines.append(f"      Admin      : {rec.get('rname', 'N/A')}")
                    lines.append(f"      Serial     : {rec.get('serial', 'N/A')}")

        lines.append("")

    def _section_subdomains(self, data: dict, lines: list[str]) -> None:
        """Format subdomain enumeration results into the TXT report.

        Args:
            data: Subdomain results dictionary.
            lines: Accumulator list of report lines.
        """
        self._section_header("SUBDOMAIN ENUMERATION", lines)
        if "error" in data:
            lines.append(f"    Error: {data['error']}")
            lines.append("")
            return

        total_tested = data.get("total_tested", 0)
        total_found = data.get("total_found", 0)
        lines.append(f"    Tested: {total_tested} | Found: {total_found}")
        lines.append("")

        discovered = data.get("discovered", [])
        for entry in discovered:
            sub = entry.get("subdomain", "N/A")
            ips = ", ".join(entry.get("ips", []))
            lines.append(f"    {sub:<35} → {ips}")

        lines.append("")

    def _section_ports(self, data: dict, lines: list[str]) -> None:
        """Format port scan results into the TXT report.

        Args:
            data: Port scan results dictionary.
            lines: Accumulator list of report lines.
        """
        self._section_header("PORT SCAN", lines)
        if "error" in data:
            lines.append(f"    Error: {data['error']}")
            lines.append("")
            return

        target_ip = data.get("target_ip", "N/A")
        total_scanned = data.get("total_scanned", 0)
        total_open = data.get("total_open", 0)
        lines.append(f"    Target IP: {target_ip}")
        lines.append(f"    Scanned: {total_scanned} | Open: {total_open}")
        lines.append("")
        lines.append(f"    {'PORT':<10} {'STATE':<10} {'PROTOCOL':<10} {'SERVICE'}")
        lines.append(f"    {'-' * 50}")

        for port in data.get("open_ports", []):
            lines.append(
                f"    {port.get('port', '-'):<10} "
                f"{port.get('state', '-'):<10} "
                f"{port.get('protocol', '-'):<10} "
                f"{port.get('service', 'unknown')}"
            )

        lines.append("")

    def _section_http(self, data: dict, lines: list[str]) -> None:
        """Format HTTP probe and banner grabbing results into the TXT report.

        Args:
            data: HTTP probe results dictionary.
            lines: Accumulator list of report lines.
        """
        self._section_header("HTTP PROBE & BANNER GRABBING", lines)
        if "error" in data:
            lines.append(f"    Error: {data['error']}")
            lines.append("")
            return

        http_results = data.get("http_results", [])
        successful = [r for r in http_results if r.get("status_code") is not None]

        if successful:
            lines.append("    HTTP/HTTPS Responses:")
            lines.append("")
            for entry in successful:
                url = entry.get("url", "N/A")
                status = entry.get("status_code", "N/A")
                title = entry.get("title", "N/A")
                server = entry.get("server", "N/A")
                x_powered = entry.get("x_powered_by", "N/A")

                lines.append(f"    URL         : {url}")
                lines.append(f"    Status      : {status}")
                lines.append(f"    Title       : {title}")
                lines.append(f"    Server      : {server}")
                if x_powered != "N/A":
                    lines.append(f"    X-Powered-By: {x_powered}")

                redirects = entry.get("redirect_chain", [])
                if redirects:
                    lines.append(f"    Redirects   :")
                    for redir in redirects:
                        lines.append(
                            f"      {redir.get('status_code', '?')} → "
                            f"{redir.get('url', 'N/A')}"
                        )
                lines.append("")

        banners = data.get("banners", [])
        captured = [b for b in banners if b.get("banner")]

        if captured:
            lines.append("    Service Banners:")
            lines.append("")
            for entry in captured:
                port = entry.get("port", "N/A")
                first_line = entry.get("banner_first_line", "N/A")
                lines.append(f"    Port {port:<6} → {first_line}")
            lines.append("")

    def generate(self) -> tuple[str, str]:
        """Generate both JSON and TXT reports and write them to disk.

        Resolves output paths, writes both report formats, and displays
        the saved file paths to the console.

        Returns:
            tuple[str, str]: Absolute paths to the saved (JSON, TXT) files.
        """
        json_path, txt_path = self._resolve_output_paths()

        self._write_json(json_path)
        self._write_txt(txt_path)

        json_abs = os.path.abspath(json_path)
        txt_abs = os.path.abspath(txt_path)

        console.print(
            Panel(
                f"[bold white]JSON:[/bold white] [green]{json_abs}[/green]\n"
                f"[bold white]TXT :[/bold white] [green]{txt_abs}[/green]",
                title="[bold cyan]Reports Saved[/bold cyan]",
                border_style="green",
            )
        )

        return json_abs, txt_abs
