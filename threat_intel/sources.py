
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Set, Tuple

import requests

FetchFn = Callable[..., requests.Response]


@dataclass(frozen=True)
class Indicator:
    ip: str
    port: Optional[int] = None
    source: str = ""


class ThreatSource:
    """Interface for a threat-intel source."""

    def refresh(self) -> None:
        raise NotImplementedError

    def iter_indicators(self) -> Iterable[Indicator]:
        raise NotImplementedError

    def name(self) -> str:
        raise NotImplementedError


class TorExitNodesSource(ThreatSource):
    """
    Fetches Tor exit node IPs from https://check.torproject.org/torbulkexitlist
    Produces Indicators with only IP populated.
    """

    URL = "https://check.torproject.org/torbulkexitlist"

    def __init__(self, fetch_fn: FetchFn | None = None, timeout: float = 10.0):
        self._fetch = fetch_fn or requests.get
        self._timeout = timeout
        self._ips: Set[str] = set()
        self._lock = threading.Lock()

    def name(self) -> str:
        return "tor_exit_nodes"

    def refresh(self) -> None:
        resp = self._fetch(self.URL, timeout=self._timeout)
        resp.raise_for_status()
        lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip() and not ln.startswith("#")]
        with self._lock:
            self._ips = set(lines)

    def iter_indicators(self) -> Iterable[Indicator]:
        with self._lock:
            for ip in self._ips:
                yield Indicator(ip=ip, port=None, source=self.name())


class ThreatFoxRecentIPPortSource(ThreatSource):
    """
    Fetches recent IP:port IOCs from ThreatFox JSON export:
      https://threatfox.abuse.ch/export/json/ip-port/recent/
    Produces Indicators with IP and port populated.
    """

    URL = "https://threatfox.abuse.ch/export/json/ip-port/recent/"

    def __init__(self, fetch_fn: FetchFn | None = None, timeout: float = 10.0):
        self._fetch = fetch_fn or requests.get
        self._timeout = timeout
        self._ip_ports: Set[Tuple[str, int]] = set()
        self._lock = threading.Lock()

    def name(self) -> str:
        return "threatfox_ip_port_recent"

    def refresh(self) -> None:
        resp = self._fetch(self.URL, timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()
        ip_ports: Set[Tuple[str, int]] = set()

        # ThreatFox JSON export format contains "data" array with dicts holding ioc_value and port
        for item in data.get("data", []):
            ip = item.get("ioc_value")
            port = item.get("port")
            if not ip:
                continue
            try:
                port_int = int(port) if port is not None else None
            except (TypeError, ValueError):
                continue
            if port_int is not None:
                ip_ports.add((ip, port_int))

        with self._lock:
            self._ip_ports = ip_ports

    def iter_indicators(self) -> Iterable[Indicator]:
        with self._lock:
            for ip, port in self._ip_ports:
                yield Indicator(ip=ip, port=port, source=self.name())


class PeriodicRefresher(threading.Thread):
    """
    Background refresher for threat sources with jitter and error handling.
    """

    def __init__(self, sources: list[ThreatSource], interval_seconds: int = 300, *, daemon: bool = True):
        super().__init__(daemon=daemon)
        self._sources = sources
        self._interval = interval_seconds
        self._stop = threading.Event()

    def run(self) -> None:
        # Initial load
        for src in self._sources:
            self._safe_refresh(src)

        while not self._stop.wait(self._interval):
            for src in self._sources:
                self._safe_refresh(src)

    def stop(self) -> None:
        self._stop.set()

    @staticmethod
    def _safe_refresh(src: ThreatSource) -> None:
        try:
            src.refresh()
        except Exception as e:
            # In a real system, log with severity and metrics
            print(f"[WARN] Failed to refresh {src.name()}: {e}")
