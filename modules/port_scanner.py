#!/usr/bin/env python3
"""
Port Scanner Module

Performs TCP connect scanning against target hosts to identify open ports.
Supports configurable port ranges, a curated top-100 common ports list,
and uses concurrent threads for efficient scanning across large port spaces.

Open ports are enriched with service name detection via socket.getservbyport().
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich.table import Table

console = Console()

DEFAULT_THREAD_COUNT = 100
DEFAULT_TIMEOUT = 1.5

TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    81, 88, 110, 111, 113, 119, 123, 135, 137, 138,
    139, 143, 161, 162, 179, 194, 389, 443, 445, 464,
    465, 514, 515, 520, 521, 587, 593, 623, 626, 636,
    873, 902, 993, 995, 1025, 1026, 1080, 1194, 1433, 1434,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2222,
    2483, 2484, 3128, 3306, 3389, 3690, 4443, 4848, 5000, 5432,
    5800, 5900, 5901, 6000, 6379, 6667, 7001, 7002, 8000, 8008,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 9999,
    10000, 10250, 11211, 27017, 27018, 28017, 32768, 49152, 49153, 49154,
]


class PortScanner:
    """Scans TCP ports on the target host to discover open services.

    Attributes:
        target: Target hostname or IP address.
        ports: Port specification string ('default', '1-1024', '80,443,8080').
        thread_count: Number of concurrent scanning threads.
        timeout: TCP connection timeout in seconds per port.
    """

    def __init__(
        self,
        target: str,
        ports: str = "default",
        thread_count: int = DEFAULT_THREAD_COUNT,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.target = target
        self.ports = ports
        self.thread_count = thread_count
        self.timeout = timeout
        self._results_lock = threading.Lock()
        self._open_ports: list[dict] = []
        self._target_ip: str = ""

    def _resolve_target(self) -> str:
        """Resolve the target hostname to an IP address.

        If the target is already an IP address, it is returned as-is.
        DNS resolution failures are caught and reported gracefully.

        Returns:
            str: Resolved IP address or empty string on failure.
        """
        try:
            ip = socket.gethostbyname(self.target)
            if ip != self.target:
                console.print(
                    f"  [dim]→ Resolved [white]{self.target}[/white] "
                    f"→ [white]{ip}[/white][/dim]"
                )
            return ip
        except socket.gaierror as exc:
            console.print(
                f"  [bold red][!] Cannot resolve {self.target}: {exc}[/bold red]"
            )
            return ""

    def _parse_ports(self) -> list[int]:
        """Parse the port specification string into a sorted list of port numbers.

        Supported formats:
            - 'default': Use the curated TOP_100_PORTS list.
            - '1-1024': Inclusive range of ports.
            - '80,443,8080': Comma-separated specific ports.
            - '1-100,443,8080-8090': Mixed ranges and individual ports.

        Returns:
            list[int]: Sorted, deduplicated list of port numbers.
        """
        if self.ports == "default":
            return sorted(TOP_100_PORTS)

        port_set: set[int] = set()
        segments = self.ports.replace(" ", "").split(",")

        for segment in segments:
            if "-" in segment:
                parts = segment.split("-", 1)
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    start = max(1, min(start, 65535))
                    end = max(1, min(end, 65535))
                    if start > end:
                        start, end = end, start
                    port_set.update(range(start, end + 1))
                except ValueError:
                    console.print(
                        f"  [yellow][!] Invalid port range: {segment}, "
                        f"skipping[/yellow]"
                    )
            else:
                try:
                    port = int(segment)
                    if 1 <= port <= 65535:
                        port_set.add(port)
                    else:
                        console.print(
                            f"  [yellow][!] Port {port} out of range "
                            f"(1-65535), skipping[/yellow]"
                        )
                except ValueError:
                    console.print(
                        f"  [yellow][!] Invalid port value: {segment}, "
                        f"skipping[/yellow]"
                    )

        return sorted(port_set)

    def _get_service_name(self, port: int) -> str:
        """Attempt to identify the service running on a given port.

        Uses the system's services database (typically /etc/services)
        to map port numbers to well-known service names.

        Args:
            port: The TCP port number.

        Returns:
            str: Service name or 'unknown' if not found.
        """
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    def _scan_port(self, port: int) -> dict | None:
        """Perform a TCP connect scan on a single port.

        Creates a socket, sets the timeout, and attempts a connection.
        If the connection succeeds (port is open), the result is recorded
        thread-safely. Closed and filtered ports return None silently.

        Args:
            port: TCP port number to scan.

        Returns:
            dict | None: Port data dict on open port, None otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result_code = sock.connect_ex((self._target_ip, port))
            if result_code == 0:
                service = self._get_service_name(port)
                entry = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "protocol": "tcp",
                }
                with self._results_lock:
                    self._open_ports.append(entry)
                return entry
            return None
        except socket.timeout:
            return None
        except OSError:
            return None
        finally:
            sock.close()

    def _display_results(self) -> None:
        """Render discovered open ports as a formatted Rich table."""
        if not self._open_ports:
            console.print(
                f"  [yellow][!] No open ports found on "
                f"{self.target}[/yellow]"
            )
            return

        sorted_ports = sorted(self._open_ports, key=lambda p: p["port"])

        table = Table(
            title=f"Open Ports — {self.target} ({self._target_ip})",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("Port", style="bold cyan", justify="right", min_width=8)
        table.add_column("State", style="bold green", min_width=8)
        table.add_column("Protocol", style="white", min_width=10)
        table.add_column("Service", style="yellow", min_width=16)

        for entry in sorted_ports:
            table.add_row(
                str(entry["port"]),
                entry["state"],
                entry["protocol"],
                entry["service"],
            )

        console.print()
        console.print(table)

    def run(self) -> dict:
        """Execute TCP port scan across the configured port specification.

        Resolves the target to an IP address, parses the port list,
        distributes scan tasks across the thread pool, and tracks
        progress in real time with a Rich progress bar.

        Returns:
            dict: Scan results containing open ports, total scanned count,
                  target IP, and scan configuration metadata.
                  Contains an 'error' key on critical failure.
        """
        self._target_ip = self._resolve_target()
        if not self._target_ip:
            return {
                "error": f"Cannot resolve target: {self.target}",
                "open_ports": [],
                "total_scanned": 0,
            }

        port_list = self._parse_ports()
        if not port_list:
            console.print(
                "  [bold red][!] No valid ports to scan.[/bold red]"
            )
            return {
                "error": "No valid ports in specification",
                "open_ports": [],
                "total_scanned": 0,
            }

        total = len(port_list)
        console.print(
            f"  [dim]→ Scanning [white]{total}[/white] port(s) on "
            f"[white]{self._target_ip}[/white][/dim]"
        )
        console.print(
            f"  [dim]→ Threads: [white]{self.thread_count}[/white] | "
            f"Timeout: [white]{self.timeout}s[/white][/dim]"
        )

        self._open_ports = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("[green]{task.fields[open_count]} open[/green]"),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(
                f"  Scanning {self._target_ip}",
                total=total,
                open_count=0,
            )

            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                future_map = {
                    executor.submit(self._scan_port, port): port
                    for port in port_list
                }

                for future in as_completed(future_map):
                    result = future.result()
                    open_count = len(self._open_ports)

                    if result is not None:
                        progress.console.print(
                            f"  [bold green]  ✓ Port {result['port']}/tcp "
                            f"open → {result['service']}[/bold green]"
                        )

                    progress.update(task_id, advance=1, open_count=open_count)

        open_count = len(self._open_ports)
        console.print(
            f"\n  [bold cyan][+] Found {open_count} open port(s) "
            f"out of {total} scanned[/bold cyan]"
        )

        self._display_results()

        sorted_ports = sorted(self._open_ports, key=lambda p: p["port"])

        return {
            "target_ip": self._target_ip,
            "open_ports": sorted_ports,
            "total_scanned": total,
            "total_open": open_count,
            "port_spec": self.ports,
            "thread_count": self.thread_count,
            "timeout": self.timeout,
        }
