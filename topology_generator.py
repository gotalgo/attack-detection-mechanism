import itertools
import json
import pathlib
from time import sleep
from typing import Iterable
from datetime import datetime, timedelta


_TOPOLOGIES_GENERATION_TIME = timedelta(seconds=1).seconds


def _generate_topology(topology_template: dict) -> dict:
    return {**topology_template} | {"topology_timestamp": datetime.utcnow().timestamp()}


def create_topologies_datasource() -> Iterable[dict]:
    topologies_generation_directory_path = pathlib.Path(__file__).resolve().parent

    with (topologies_generation_directory_path / "topology_templates.json").open("r") as topology_templates_file:
        topology_templates = json.load(topology_templates_file)

    topologies = (_generate_topology(topology_template) for topology_template in itertools.cycle(topology_templates))

    for topology in topologies:
        sleep(_TOPOLOGIES_GENERATION_TIME)
        yield topology
