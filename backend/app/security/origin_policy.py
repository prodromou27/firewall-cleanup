"""Runtime-mutable allow-list of origin IP subnets (CIDRs).

CORS/CSRF normally take exact origin strings. This module lets an operator
allow whole IP subnets (e.g. for LAN access) and change them at runtime from
the Settings UI without a backend restart. The CSRF middleware consults
``origin_in_allowed_subnet`` on every mutating request, so updates take effect
immediately for the (same-origin, proxied) app flow.
"""
from __future__ import annotations

import ipaddress
import threading
from typing import List, Tuple
from urllib.parse import urlparse

_lock = threading.Lock()
_networks: list = []


def parse_cidrs(cidrs: List[str]) -> Tuple[list, List[str]]:
    """Parse a list of CIDR strings. Returns (networks, invalid_entries)."""
    nets, invalid = [], []
    for c in cidrs:
        c = (c or "").strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            invalid.append(c)
    return nets, invalid


def set_subnets(cidrs: List[str]) -> List[str]:
    """Replace the active subnet list. Invalid entries are skipped and returned."""
    nets, invalid = parse_cidrs(cidrs)
    with _lock:
        global _networks
        _networks = nets
    return invalid


def get_cidrs() -> List[str]:
    """Return the active subnets as CIDR strings (for display)."""
    with _lock:
        return [str(n) for n in _networks]


def origin_in_allowed_subnet(origin: str) -> bool:
    """True if the origin's host IP falls within an allowed subnet."""
    with _lock:
        nets = list(_networks)
    if not origin or not nets:
        return False
    try:
        host = urlparse(origin).hostname
        if not host:
            return False
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in nets)
