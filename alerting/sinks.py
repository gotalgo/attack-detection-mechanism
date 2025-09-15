
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Protocol


@dataclass
class Alert:
    reason: str            # e.g., "tor_exit_node" or "threatfox_ip_port_recent"
    ip: str
    port: int | None
    topology: Dict[str, Any]


class AlertSink(Protocol):
    def send(self, alert: Alert) -> None:  # pragma: no cover - interface
        ...


class StdoutSink:
    def send(self, alert: Alert) -> None:
        port_part = f":{alert.port}" if alert.port is not None else ""
        print(f"[ALERT] {alert.reason} match: {alert.ip}{port_part} | topology={alert.topology}")


class ListSink:
    """Testing sink to capture alerts in-memory."""
    def __init__(self) -> None:
        self.items: List[Alert] = []

    def send(self, alert: Alert) -> None:
        self.items.append(alert)


# Placeholders for future sinks
class KafkaSink:
    def __init__(self, topic: str) -> None:
        self.topic = topic
    def send(self, alert: Alert) -> None:
        # In real life, serialize and publish to Kafka
        print(f"[KAFKA:{self.topic}] {alert}")

class DBSink:
    def __init__(self, table: str) -> None:
        self.table = table
    def send(self, alert: Alert) -> None:
        # In real life, insert into DB
        print(f"[DB:{self.table}] {alert}")
