#!/usr/bin/env python3
"""
HTTP Probe & Banner Grabbing Module

Two-pronged reconnaissance module:
  1) HTTP/HTTPS Probing — sends requests to the target domain and any
     discovered subdomains, collecting status codes, page titles,
     server headers, technology fingerprints, and redirect chains.
  2) Banner Grabbing — connects to open TCP ports with raw sockets
     and captures service banners for software identification.

Designed to run after subdomain enumeration and port scanning so it
can leverage their results for broader coverage.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
from rich.console import Console
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

DEFAULT_TIMEOUT = 7.0
DEFAULT_THREAD_COUNT = 10

BANNER_PROBE_PAYLOADS = {
    "http": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "generic": b"\r\n",
}

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 3128, 5000, 9090}


class HTTPProbe:
    """Probes HTTP/HTTPS endpoints and grabs banners from open ports.

    Attributes:
        target: Primary target domain or IP address.
        subdomains: List of discovered subdomain FQDNs to probe.
        open_ports: List of open port numbers for banner grabbing.
        timeout: Request and socket timeout in seconds.
        thread_count: Concurrent threads for HTTP probing.
    """

    def __init__(
        self,
        target: str,
        subdomains: list[str] | None = None,
        open_ports: list[int] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        thread_count: int = DEFAULT_THREAD_COUNT,
    ) -> None:
        self.target = target
        self.subdomains = subdomains or []
        self.open_ports = open_ports or []
        self.timeout = timeout
        self.thread_count = thread_count

    def _build_target_list(self) -> list[str]:
        """Build a deduplicated list of hosts to probe.

        Combines the primary target with any discovered subdomains,
        removing duplicates while preserving the target as the first entry.

        Returns:
            list[str]: Unique hostnames to probe.
        """
        hosts = [self.target]
        for sub in self.subdomains:
            if sub not in hosts:
                hosts.append(sub)
        return hosts

    def _extract_title(self, html: str) -> str:
        """Extract the page title from raw HTML content.

        Uses regex to avoid adding BeautifulSoup as a dependency.
        Handles multiline titles and strips excess whitespace.

        Args:
            html: Raw HTML response body.

        Returns:
            str: Extracted page title or 'N/A' if not found.
        """
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            if len(title) > 80:
                return title[:77] + "..."
            return title
        return "N/A"

    def _probe_single_url(self, url: str) -> dict:
        """Send an HTTP request to a single URL and collect response metadata.

        Captures status code, server headers, page title, redirect chain,
        and technology fingerprints from the response.

        Args:
            url: Full URL to probe (http:// or https://).

        Returns:
            dict: Response metadata or error information.
        """
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Argus Recon Framework)"
                },
            )

            redirect_chain = []
            for hist in response.history:
                redirect_chain.append(
                    {
                        "url": hist.url,
                        "status_code": hist.status_code,
                    }
                )

            title = self._extract_title(response.text)
            server = response.headers.get("Server", "N/A")
            x_powered = response.headers.get("X-Powered-By", "N/A")
            content_type = response.headers.get("Content-Type", "N/A")

            return {
                "url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "title": title,
                "server": server,
                "x_powered_by": x_powered,
                "content_type": content_type,
                "redirect_chain": redirect_chain,
                "headers_count": len(response.headers),
                "content_length": len(response.content),
            }

        except requests.exceptions.SSLError:
            return {
                "url": url,
                "status_code": None,
                "error": "SSL certificate error",
            }
        except requests.exceptions.ConnectionError:
            return {
                "url": url,
                "status_code": None,
                "error": "Connection refused",
            }
        except requests.exceptions.Timeout:
            return {
                "url": url,
                "status_code": None,
                "error": f"Timeout ({self.timeout}s)",
            }
        except requests.exceptions.RequestException as exc:
            return {
                "url": url,
                "status_code": None,
                "error": str(exc),
            }

    def _probe_host(self, host: str) -> list[dict]:
        """Probe a single host over both HTTP and HTTPS.

        Args:
            host: Hostname or IP to probe.

        Returns:
            list[dict]: Results for HTTP and HTTPS probes.
        """
        results = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            result = self._probe_single_url(url)
            results.append(result)
        return results

    def _probe_all_hosts(self) -> list[dict]:
        """Probe all target hosts concurrently over HTTP and HTTPS.

        Returns:
            list[dict]: Aggregated probe results for all hosts.
        """
        hosts = self._build_target_list()
        all_results = []

        console.print(
            f"  [dim]→ Probing [white]{len(hosts)}[/white] host(s) "
            f"over HTTP/HTTPS...[/dim]"
        )

        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            future_map = {
                executor.submit(self._probe_host, host): host
                for host in hosts
            }

            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    host_results = future.result()
                    for result in host_results:
                        all_results.append(result)
                        status = result.get("status_code")
                        error = result.get("error")
                        url = result.get("url", "")

                        if status is not None:
                            color = "green" if status < 400 else "yellow"
                            console.print(
                                f"  [{color}]  ✓ {url} → "
                                f"{status}[/{color}]"
                            )
                        elif error:
                            console.print(
                                f"  [dim]  ✗ {url} → {error}[/dim]"
                            )
                except Exception as exc:
                    console.print(
                        f"  [red][!] Probe failed for {host}: {exc}[/red]"
                    )

        return all_results

    def _grab_banner(self, host: str, port: int) -> dict:
        """Connect to an open port and capture the service banner.

        Sends an appropriate probe payload based on whether the port
        is a known HTTP port or a generic service port.

        Args:
            host: Target IP or hostname.
            port: Open TCP port number.

        Returns:
            dict: Port number, captured banner text, and metadata.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            ip = socket.gethostbyname(host)
            sock.connect((ip, port))

            if port in HTTP_PORTS:
                payload = BANNER_PROBE_PAYLOADS["http"].replace(
                    b"{host}", host.encode()
                )
            else:
                payload = BANNER_PROBE_PAYLOADS["generic"]

            sock.sendall(payload)
            banner_raw = sock.recv(1024)
            banner = banner_raw.decode(errors="replace").strip()

            first_line = banner.split("\n")[0].strip() if banner else ""

            return {
                "port": port,
                "banner": banner[:512],
                "banner_first_line": first_line[:128],
                "banner_length": len(banner_raw),
            }

        except socket.timeout:
            return {
                "port": port,
                "banner": "",
                "banner_first_line": "N/A (timeout)",
                "banner_length": 0,
            }
        except ConnectionRefusedError:
            return {
                "port": port,
                "banner": "",
                "banner_first_line": "N/A (refused)",
                "banner_length": 0,
            }
        except OSError as exc:
            return {
                "port": port,
                "banner": "",
                "banner_first_line": f"N/A ({exc})",
                "banner_length": 0,
            }
        finally:
            sock.close()

    def _grab_all_banners(self) -> list[dict]:
        """Grab banners from all discovered open ports concurrently.

        Returns:
            list[dict]: Banner data for each open port.
        """
        if not self.open_ports:
            console.print(
                "  [dim]→ No open ports provided, skipping banner grabbing[/dim]"
            )
            return []

        console.print(
            f"  [dim]→ Grabbing banners from [white]{len(self.open_ports)}"
            f"[/white] open port(s)...[/dim]"
        )

        banners = []

        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            future_map = {
                executor.submit(self._grab_banner, self.target, port): port
                for port in self.open_ports
            }

            for future in as_completed(future_map):
                port = future_map[future]
                try:
                    result = future.result()
                    banners.append(result)
                    first_line = result.get("banner_first_line", "")
                    if first_line and not first_line.startswith("N/A"):
                        console.print(
                            f"  [green]  ✓ Port {port} → "
                            f"{first_line[:64]}[/green]"
                        )
                    else:
                        console.print(
                            f"  [dim]  ○ Port {port} → "
                            f"{first_line}[/dim]"
                        )
                except Exception as exc:
                    console.print(
                        f"  [red][!] Banner grab failed on port {port}: "
                        f"{exc}[/red]"
                    )

        return sorted(banners, key=lambda b: b["port"])

    def _display_http_results(self, results: list[dict]) -> None:
        """Render HTTP probe results as a formatted Rich table.

        Args:
            results: List of HTTP probe result dictionaries.
        """
        successful = [r for r in results if r.get("status_code") is not None]
        if not successful:
            console.print(
                f"  [yellow][!] No HTTP responses received for "
                f"{self.target}[/yellow]"
            )
            return

        table = Table(
            title=f"HTTP Probe — {self.target}",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("URL", style="cyan", min_width=28, max_width=40)
        table.add_column("Status", justify="center", style="bold", min_width=8)
        table.add_column("Title", style="white", min_width=20, max_width=32)
        table.add_column("Server", style="yellow", min_width=14)

        for entry in successful:
            status = entry["status_code"]
            status_color = "green" if status < 400 else "yellow" if status < 500 else "red"
            url = entry.get("url", "")
            if len(url) > 40:
                url = url[:37] + "..."

            table.add_row(
                url,
                f"[{status_color}]{status}[/{status_color}]",
                entry.get("title", "N/A"),
                entry.get("server", "N/A"),
            )

        console.print()
        console.print(table)

    def _display_banner_results(self, banners: list[dict]) -> None:
        """Render banner grabbing results as a formatted Rich table.

        Args:
            banners: List of banner data dictionaries.
        """
        captured = [b for b in banners if b.get("banner")]
        if not captured:
            return

        table = Table(
            title=f"Banners — {self.target}",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
            min_width=60,
        )
        table.add_column("Port", style="bold cyan", justify="right", min_width=8)
        table.add_column("Banner", style="white", min_width=48)

        for entry in captured:
            first_line = entry.get("banner_first_line", "")
            if first_line and not first_line.startswith("N/A"):
                table.add_row(str(entry["port"]), first_line)

        console.print()
        console.print(table)

    def run(self) -> dict:
        """Execute HTTP probing and banner grabbing against the target.

        Phase 1: Probes the target domain and all discovered subdomains
        over HTTP and HTTPS, collecting response metadata.

        Phase 2: Connects to all discovered open ports and captures
        service banners for software fingerprinting.

        Returns:
            dict: Combined results from HTTP probing and banner grabbing.
                  Contains 'http_results' and 'banners' keys.
        """
        console.print(
            f"  [dim]→ HTTP Probe & Banner Grab targeting "
            f"[white]{self.target}[/white][/dim]"
        )

        if self.subdomains:
            console.print(
                f"  [dim]→ {len(self.subdomains)} subdomain(s) "
                f"queued for probing[/dim]"
            )
        if self.open_ports:
            console.print(
                f"  [dim]→ {len(self.open_ports)} open port(s) "
                f"queued for banner grabbing[/dim]"
            )

        http_results = self._probe_all_hosts()
        self._display_http_results(http_results)

        banners = self._grab_all_banners()
        self._display_banner_results(banners)

        successful_probes = sum(
            1 for r in http_results if r.get("status_code") is not None
        )
        captured_banners = sum(1 for b in banners if b.get("banner"))

        console.print(
            f"\n  [bold cyan][+] HTTP: {successful_probes} response(s) | "
            f"Banners: {captured_banners} captured[/bold cyan]"
        )

        return {
            "http_results": http_results,
            "banners": banners,
            "total_hosts_probed": len(self._build_target_list()),
            "total_http_responses": successful_probes,
            "total_banners_captured": captured_banners,
        }
