"""IP address utility functions for firewall rule comparison."""
import ipaddress
from typing import Optional


def parse_ip_network(value: str) -> Optional[ipaddress.IPv4Network]:
    """Parse a string into an IPv4Network. Returns None on failure."""
    if not value:
        return None
    value = value.strip()
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Network(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def network_contains(outer: str, inner: str) -> bool:
    """True if outer network contains or equals inner network."""
    if outer in ("any", "all", "0.0.0.0/0"):
        return True
    net_outer = parse_ip_network(outer)
    net_inner = parse_ip_network(inner)
    if net_outer is None or net_inner is None:
        return False
    return net_inner.subnet_of(net_outer)


def networks_overlap(a: str, b: str) -> bool:
    """True if two networks overlap at all."""
    if a in ("any", "all", "0.0.0.0/0") or b in ("any", "all", "0.0.0.0/0"):
        return True
    net_a = parse_ip_network(a)
    net_b = parse_ip_network(b)
    if net_a is None or net_b is None:
        return False
    return net_a.overlaps(net_b)


def networks_equal(a: str, b: str) -> bool:
    """True if two networks are exactly equal."""
    if a == b:
        return True
    net_a = parse_ip_network(a)
    net_b = parse_ip_network(b)
    if net_a is None or net_b is None:
        return False
    return net_a == net_b


def is_any(value: str) -> bool:
    """True if value represents 'any' traffic."""
    if not value:
        return False
    v = value.strip().lower()
    return v in ("any", "all", "0.0.0.0/0", "0.0.0.0")


def network_prefix_length(value: str) -> Optional[int]:
    """Return prefix length of a network."""
    net = parse_ip_network(value)
    if net is None:
        return None
    return net.prefixlen


def is_broad_network(value: str, threshold: int = 16) -> bool:
    """True if network prefix is smaller than threshold (i.e., very large network)."""
    prefix = network_prefix_length(value)
    if prefix is None:
        return False
    return prefix <= threshold


def is_public_network(value: str) -> bool:
    """True if the value includes public (internet-routable) address space.

    'any' (0.0.0.0/0) is treated as public. RFC1918 private ranges, loopback,
    and link-local are not. Unparseable / named objects return False so that
    only sources we can positively confirm as public are flagged.
    """
    if not value:
        return False
    if is_any(value):
        return True
    net = parse_ip_network(value)
    if net is None:
        return False
    # is_private is True only when the entire network is within private space.
    return not net.is_private


def parse_ip_range(start: str, end: str):
    """Return list of networks covering an IP range."""
    try:
        return list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start),
            ipaddress.IPv4Address(end)
        ))
    except ValueError:
        return []


def ip_range_to_network(start: str, end: str) -> str:
    """Convert an IP range to the broadest single CIDR (approximate)."""
    nets = parse_ip_range(start, end)
    if not nets:
        return f"{start}-{end}"
    return str(nets[0])
