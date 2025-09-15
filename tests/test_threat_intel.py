
import json
import types
from typing import Any

from alerting.sinks import ListSink, Alert
from threat_intel.aggregator import IntelAggregator
from threat_intel.sources import TorExitNodesSource, ThreatFoxRecentIPPortSource


class DummyResp:
    def __init__(self, text: str = "", json_data: Any = None, status: int = 200):
        self._text = text
        self._json = json_data
        self.status_code = status

    @property
    def text(self):
        return self._text

    def json(self):
        return self._json

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            raise RuntimeError(f"HTTP {self.status_code}")


def test_tor_source_parsing():
    data = "# comment\n1.1.1.1\n2.2.2.2\n"
    src = TorExitNodesSource(fetch_fn=lambda url, timeout=10.0: DummyResp(text=data))
    src.refresh()
    inds = list(src.iter_indicators())
    ips = {i.ip for i in inds}
    assert ips == {"1.1.1.1", "2.2.2.2"}


def test_threatfox_parsing():
    payload = {
        "data": [
            {"ioc_value": "5.5.5.5", "port": 80},
            {"ioc_value": "6.6.6.6", "port": "443"},
            {"ioc_value": "7.7.7.7", "port": None},  # ignored
            {"ioc_value": None, "port": 22},         # ignored
        ]
    }
    src = ThreatFoxRecentIPPortSource(fetch_fn=lambda url, timeout=10.0: DummyResp(json_data=payload))
    src.refresh()
    inds = list(src.iter_indicators())
    pairs = {(i.ip, i.port) for i in inds}
    assert pairs == {("5.5.5.5", 80), ("6.6.6.6", 443)}


def test_aggregator_lookup():
    tor = TorExitNodesSource(fetch_fn=lambda u, timeout=10.0: DummyResp(text="1.1.1.1\n"))
    tfox = ThreatFoxRecentIPPortSource(fetch_fn=lambda u, timeout=10.0: DummyResp(json_data={"data":[{"ioc_value":"9.9.9.9","port":8080}]}))
    tor.refresh(); tfox.refresh()
    agg = IntelAggregator([tor, tfox])
    assert agg.is_malicious_ip("1.1.1.1")
    assert not agg.is_malicious_ip("2.2.2.2")
    assert agg.is_malicious_ip_port("9.9.9.9", 8080)
    assert not agg.is_malicious_ip_port("9.9.9.9", 22)
