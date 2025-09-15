
from __future__ import annotations

import threading
from typing import Iterable, Optional, Set, Tuple

from .sources import ThreatSource, Indicator


class IntelAggregator:
    """
    Aggregates indicators from multiple sources into fast lookup sets.
    - _ips: set of IPs (for sources like Tor exit nodes)
    - _ip_ports: set of (ip, port) tuples (for sources like ThreatFox IP:port)
    """

    def __init__(self, sources: Iterable[ThreatSource]):
        self._sources = list(sources)
        self._ips: Set[str] = set()
        self._ip_ports: Set[Tuple[str, int]] = set()
        self._lock = threading.Lock()
        # Perform first aggregation
        self.rebuild()

    def rebuild(self) -> None:
        ips: Set[str] = set()
        ip_ports: Set[Tuple[str, int]] = set()
        for src in self._sources:
            for ind in src.iter_indicators():
                if ind.port is None:
                    ips.add(ind.ip)
                else:
                    ip_ports.add((ind.ip, int(ind.port)))

        with self._lock:
            self._ips = ips
            self._ip_ports = ip_ports

    def is_malicious_ip(self, ip: str) -> bool:
        with self._lock:
            return ip in self._ips

    def is_malicious_ip_port(self, ip: str, port: int) -> bool:
        with self._lock:
            return (ip, int(port)) in self._ip_ports
