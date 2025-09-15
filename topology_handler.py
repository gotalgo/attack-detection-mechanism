from typing import Iterable

from topology_generator import create_topologies_datasource
from threat_intel.sources import TorExitNodesSource, ThreatFoxRecentIPPortSource, PeriodicRefresher
from threat_intel.aggregator import IntelAggregator
from alerting.sinks import StdoutSink, Alert


class TopologyHandler:
    def __init__(self, topologies_datasource: Iterable[dict]):
        self._topologies_datasource = topologies_datasource
        # Initialize sources and background refresher
        self._tor = TorExitNodesSource()
        self._tfox = ThreatFoxRecentIPPortSource()
        self._refresher = PeriodicRefresher([self._tor, self._tfox], interval_seconds=300)
        self._refresher.start()
        self._aggregator = IntelAggregator([self._tor, self._tfox])
        self._sink = StdoutSink()

    def _handle_topology(self, topology: dict):
        # Rebuild aggregator after each refresh cycle (cheap vs network fetch)
        self._aggregator.rebuild()

        src_ip = topology.get('source_ip')
        dst_ip = topology.get('destination_ip')
        src_port = topology.get('source_port')
        dst_port = topology.get('destination_port')

        # IP-only matches (e.g., Tor exit nodes)
        if self._aggregator.is_malicious_ip(src_ip):
            self._sink.send(Alert(reason='tor_exit_nodes', ip=src_ip, port=None, topology=topology))
        if self._aggregator.is_malicious_ip(dst_ip):
            self._sink.send(Alert(reason='tor_exit_nodes', ip=dst_ip, port=None, topology=topology))

        # IP:port matches (e.g., ThreatFox)
        if isinstance(src_port, int) and self._aggregator.is_malicious_ip_port(src_ip, src_port):
            self._sink.send(Alert(reason='threatfox_ip_port_recent', ip=src_ip, port=src_port, topology=topology))
        if isinstance(dst_port, int) and self._aggregator.is_malicious_ip_port(dst_ip, dst_port):
            self._sink.send(Alert(reason='threatfox_ip_port_recent', ip=dst_ip, port=dst_port, topology=topology))

    @staticmethod
    def _validate_topology(topology: dict) -> bool:
        return {"source_ip", "source_port", "destination_ip", "destination_port", "topology_timestamp"}.issubset(topology.keys())

    def handle_topologies(self):
        filtered_topologies = (topology for topology in self._topologies_datasource if
                               self._validate_topology(topology))

        for topology in filtered_topologies:
            print("Handling topology.")
            self._handle_topology(topology)
            print("Done handling topology.")


def main():
    topologies_datasource = create_topologies_datasource()
    TopologyHandler(topologies_datasource).handle_topologies()


if __name__ == "__main__":
    main()
