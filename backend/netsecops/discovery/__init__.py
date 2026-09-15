"""Discovery (SRS §3.4, FR-DISC-01 … FR-DISC-06).

Finding devices nobody put in the inventory, without becoming a scanner.

SRS §1.2 puts this out of scope explicitly: *no active exploitation, no password
brute-forcing, no traffic-based vulnerability scanning, no Nmap/Nessus-style port and
service sweeps*. Discovery is "lightweight reachability and fingerprinting probes" and
nothing else. That is a narrower remit than most discovery tooling, and the narrowness
is the product decision — NetSecOps is pointed at production network infrastructure by
customers who will not accept a sweep against it.

So the package is shaped the way :mod:`netsecops.adapters.readonly` is: the guard exists
before anything that could probe, and there is no unguarded path to the network.

``scopes``   What may be probed — ranges, exclusions, and a ceiling (FR-DISC-01).
``probes``   What may be sent to it (FR-DISC-02).
"""

from __future__ import annotations

__all__: list[str] = []
