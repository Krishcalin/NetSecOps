"""Topology and path analysis (FR-TOPO-01 … FR-TOPO-07).

``graph``    the layer-3 graph, assembled from the forwarding tables in the NCM.
``path``     walking a packet across it, with the two-axis result.
``missing``  which unmanaged next hops obscure the most reachability.

Nothing in this package contacts a device. Every edge was read out of a configuration
that was already collected, which is what lets multi-device reachability exist inside a
product that never sends a probe.
"""

from netsecops.topology.graph import DeviceNode, TopologyGraph, build_graph
from netsecops.topology.missing import MissingDevice, missing_devices
from netsecops.topology.path import PathResult, PolicyVerdict, RoutingConfidence, walk

__all__ = [
    "DeviceNode",
    "MissingDevice",
    "PathResult",
    "PolicyVerdict",
    "RoutingConfidence",
    "TopologyGraph",
    "build_graph",
    "missing_devices",
    "walk",
]
