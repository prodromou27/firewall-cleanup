"""Unit tests for IP utility functions."""
import pytest
from app.analysis.ip_utils import (
    network_contains, networks_overlap, networks_equal,
    is_any, is_broad_network, parse_ip_network
)


def test_network_contains_exact():
    assert network_contains("10.10.0.0/24", "10.10.0.0/24")


def test_network_contains_subnet():
    assert network_contains("10.10.0.0/16", "10.10.5.0/24")


def test_network_contains_host():
    assert network_contains("10.10.0.0/16", "10.10.5.20")


def test_network_not_contains():
    assert not network_contains("10.10.5.0/24", "10.10.0.0/16")


def test_network_any_contains_all():
    assert network_contains("any", "10.10.5.20")
    assert network_contains("0.0.0.0/0", "192.168.1.1")


def test_networks_overlap():
    assert networks_overlap("10.10.0.0/16", "10.10.5.0/24")
    assert networks_overlap("10.10.5.0/24", "10.10.0.0/16")
    assert not networks_overlap("10.10.5.0/24", "10.11.0.0/24")


def test_networks_equal():
    assert networks_equal("10.10.0.0/24", "10.10.0.0/24")
    assert networks_equal("10.10.0.5", "10.10.0.5/32")
    assert not networks_equal("10.10.0.0/24", "10.10.1.0/24")


def test_is_any():
    assert is_any("any")
    assert is_any("Any")
    assert is_any("0.0.0.0/0")
    assert not is_any("10.10.0.0/24")


def test_is_broad_network():
    assert is_broad_network("10.0.0.0/8")
    assert is_broad_network("172.16.0.0/12")
    assert not is_broad_network("10.10.0.0/24")
