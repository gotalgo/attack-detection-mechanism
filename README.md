## Home exercise


The Cynerio collector receives data from the wire at the customer site and sends it for processing in the cloud. Our cloud platform receives a data we call `topology`, which is the metadata of the packet, and contains the following information - source IP, destination IP, source port, destination port and transport (TCP or UDP).

As part of our attack detection mechanism, we want to identify known malicious IPs that are observed in the traffic and alert on them. You will need to implement a mechanism that fetches information about such malicious IPs and compares each topology to them.

As part of the beta version of this, we want to implement this mechanism using 2 data sources:
1. Tor exit nodes - https://check.torproject.org/torbulkexitlist
2. threatfox - https://threatfox.abuse.ch/export/json/ip-port/recent/

You are provided with basic code that receives objects of type `topology` in an endless stream and processes each one as it's coming. You're required to add functionality to the code that fetches data from those 2 data sources and alerts when a malicious IP is observed in the data. When an IP is observed in a topology that appears in one of those feeds an alert needs to be issued. At this stage, the alert can be printed to the screen but in the future we would want to have it sent to different systems.

Points to think about and should be reflected in your implementation and design:
1. How easy would it be to add more sources on top of the 2 listed?
2. How easy would it be to have alerts sent to different destinations, such as a DB, a Kafka topic, etc?
3. Remember you're working with external data fetched from the internet. What considerations are required?
4. Testing.

#### Prerequisites

- Python 3.9+

#### General Guidelines
1. You can add files and change existing files and directories as you see fit (except for files under topologies_generation and enrichment_sources)
2. The exercise should be submitted in a zip file containing the entire repository along with your changes + tests (committed)



---

## Added by Candidate

### How it works

- `threat_intel/` implements two updatable feeds:
  - Tor exit nodes (IP only)
  - ThreatFox recent IP:port (IP+port)
- `alerting/` contains pluggable alert sinks (`StdoutSink`, `ListSink` for tests, and stubs for Kafka/DB).
- `TopologyHandler._handle_topology` checks each topology against both IP-only and IP:port indicators and emits alerts.

### Extensibility

- Add a new feed by implementing `ThreatSource` in `threat_intel/sources.py` and registering it in `TopologyHandler.__init__`.
- Add a new alert destination by implementing `AlertSink` in `alerting/sinks.py` and swapping it in `TopologyHandler.__init__`.

### External-data considerations

- Network requests use timeouts and raise for HTTP errors.
- Background `PeriodicRefresher` updates the feeds every 5 minutes (configurable). Failures are contained and logged with warnings.
- Parsing guards against malformed rows/fields.
- All matching happens on in-memory sets for O(1) lookups; rebuild after refresh is cheap relative to network fetch.

### Testing

Run unit tests:

```bash
python -m pytest -q
```

The tests stub network calls and verify:
- Tor parsing
- ThreatFox parsing
- Aggregator lookups
