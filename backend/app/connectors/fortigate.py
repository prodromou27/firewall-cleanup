"""
FortiGate REST API connector — FortiOS 6.2 / 6.4 / 7.0 / 7.2 / 7.4 / 7.6.

Authentication
--------------
  Option A (preferred): API token
    Header: Authorization: Bearer <token>
    Created via: System › Administrators › Create REST API Admin
    Requires: Trusted hosts set, read-only profile (no write permissions needed)

  Option B: username + password session
    POST /logincheck
    form-body: username=<u>&secretkey=<p>&ajax=1
    Session cookie: APSCOOKIE_<n>
    CSRF token: X-CSRFTOKEN from ccsrftoken cookie (needed for write ops, harmless for read)

Endpoints used
--------------
  CMDB  GET /api/v2/cmdb/firewall/policy                → IPv4 firewall rules
  CMDB  GET /api/v2/cmdb/firewall/policy6               → IPv6 firewall rules
  CMDB  GET /api/v2/cmdb/firewall/address               → address objects (hosts, nets, FQDNs, ranges)
  CMDB  GET /api/v2/cmdb/firewall/addrgrp               → address group objects
  CMDB  GET /api/v2/cmdb/firewall/address6              → IPv6 address objects
  CMDB  GET /api/v2/cmdb/firewall/addrgrp6              → IPv6 address groups
  CMDB  GET /api/v2/cmdb/firewall/service/custom        → custom service objects
  CMDB  GET /api/v2/cmdb/firewall/service/group         → service group objects
  CMDB  GET /api/v2/cmdb/firewall/vip                   → virtual IPs (DNAT/port-forward targets)
  CMDB  GET /api/v2/cmdb/firewall/vipgrp                → VIP groups
  CMDB  GET /api/v2/cmdb/firewall/ippool                → IP pools (SNAT sources)
  CMDB  GET /api/v2/cmdb/firewall/schedule/onetime      → one-time schedule objects
  CMDB  GET /api/v2/cmdb/firewall/schedule/recurring    → recurring schedule objects
  CMDB  GET /api/v2/cmdb/system/interface               → interface list (for zone-to-iface mapping)
  CMDB  GET /api/v2/cmdb/system/zone                    → zone definitions
  MON   GET /api/v2/monitor/firewall/policy             → live hit counts / bytes / sessions
  MON   GET /api/v2/monitor/system/status               → firmware version, serial, hostname

Pagination
----------
CMDB endpoints accept ?start=<n>&count=<m> (default count=1000 which is sufficient for most
deployments; for >1000 rules we loop).  Response includes "results" list.

Hit count fields (vary by FortiOS version)
------------------------------------------
  FortiOS 6.x:  hit_count  /  first_used / last_used   (integer unix timestamps)
  FortiOS 7.x:  hit_count  /  first_used / last_used   (same)
  Aliases seen: hitcount, byte/bytes, pkts/packets, sesscount/active_sessions

Ref: https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/940602/using-apis
"""

import logging
import ipaddress
import urllib3
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

CMDB_PAGE_SIZE = 1000   # FortiGate default, sufficient for most deployments


class FortiGateConnector:
    """
    Read-only FortiGate REST API client.

    SAFETY: This connector only performs read (GET) requests and the login POST.
    It never modifies, creates, or deletes any firewall object or rule.
    """

    def __init__(
        self,
        host: str,
        *,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        vdom: str = "root",
        timeout: int = 30,
    ):
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}"
        self.api_token = api_token
        self.username = username
        self.password = password
        self.vdom = vdom
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "SSL certificate verification DISABLED for FortiGate %s — "
                "set verify_ssl=True or provide a trusted CA bundle in production.",
                host,
            )
        self._logged_in = False
        self._firmware_version: Optional[str] = None

    # ── Authentication ──────────────────────────────────────────────────────

    def connect(self) -> dict:
        """Authenticate and return device info."""
        if self.api_token:
            self._session.headers.update({"Authorization": f"Bearer {self.api_token}"})
            self._logged_in = True
        else:
            self._password_login()

        status = self._get_monitor("system/status")
        version = status.get("version", status.get("Version", "unknown"))
        self._firmware_version = version
        serial = status.get("serial", status.get("Serial-Number", "unknown"))
        hostname = status.get("hostname", status.get("Hostname", "unknown"))

        logger.info(
            "FortiGate connected: host=%s vdom=%s version=%s serial=%s",
            self.base_url, self.vdom, version, serial,
        )
        return {
            "version": version,
            "serial": serial,
            "hostname": hostname,
            "vdom": self.vdom,
        }

    def _password_login(self):
        """Session-cookie based login (fallback when no API token is configured)."""
        url = f"{self.base_url}/logincheck"
        resp = self._session.post(
            url,
            data=f"username={self.username}&secretkey={self.password}&ajax=1",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        body = resp.text.strip()
        # FortiGate returns "1" on success when ajax=1
        if body == "0" or "Invalid credentials" in body:
            raise ConnectionError("FortiGate login failed — invalid credentials")
        if "Set-Cookie" not in resp.headers and not self._session.cookies:
            raise ConnectionError("FortiGate login failed — no session cookie received")
        # Extract CSRF token (needed by FGT even for read-only requests in some versions)
        for cookie in self._session.cookies:
            if cookie.name.startswith("ccsrftoken"):
                token_val = cookie.value.strip('"')
                self._session.headers.update({"X-CSRFTOKEN": token_val})
                break
        self._logged_in = True

    def disconnect(self):
        """Logout (session auth only — API tokens don't need logout)."""
        if self._logged_in and not self.api_token:
            try:
                self._session.post(
                    f"{self.base_url}/logout",
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except Exception:
                pass
        self._logged_in = False

    # ── CMDB helpers ─────────────────────────────────────────────────────────

    def _get_cmdb(self, path: str, params: dict = None) -> list:
        """
        GET /api/v2/cmdb/{path} with automatic pagination.
        Returns the full results list.
        """
        url = f"{self.base_url}/api/v2/cmdb/{path}"
        base_params = {"vdom": self.vdom}
        if params:
            base_params.update(params)

        all_results: list = []
        start = 0
        while True:
            qp = {**base_params, "start": start, "count": CMDB_PAGE_SIZE}
            resp = self._session.get(url, params=qp, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 404:
                logger.debug("CMDB path not found (404): %s — skipping", path)
                return []
            if resp.status_code == 400:
                logger.warning(
                    "CMDB path returned 400 Bad Request: %s — endpoint may not be supported "
                    "on this FortiOS version or the API profile lacks read permission. Skipping.",
                    path,
                )
                return []
            resp.raise_for_status()
            data = resp.json()

            results = data.get("results", [])
            all_results.extend(results)

            # Stop if we got fewer than the page size (last page)
            if len(results) < CMDB_PAGE_SIZE:
                break
            start += CMDB_PAGE_SIZE

        return all_results

    def _get_monitor(self, path: str, params: dict = None) -> dict:
        """GET /api/v2/monitor/{path} — returns full JSON response body."""
        url = f"{self.base_url}/api/v2/monitor/{path}"
        qp = {"vdom": self.vdom}
        if params:
            qp.update(params)
        resp = self._session.get(url, params=qp, timeout=self.timeout, verify=self.verify_ssl)
        if resp.status_code == 404:
            logger.debug("Monitor path not found (404): %s", path)
            return {}
        resp.raise_for_status()
        return resp.json()

    # ── Policy fetchers ──────────────────────────────────────────────────────

    def get_policies(self) -> list[dict]:
        """IPv4 firewall policies from CMDB."""
        return self._get_cmdb("firewall/policy")

    def get_policies6(self) -> list[dict]:
        """IPv6 firewall policies (informational — included in object count)."""
        try:
            return self._get_cmdb("firewall/policy6")
        except Exception as e:
            logger.debug("IPv6 policies not available: %s", e)
            return []

    # ── Address objects ──────────────────────────────────────────────────────

    def get_addresses(self) -> list[dict]:
        """Address objects (host, subnet, FQDN, IP range, geography, wildcard)."""
        return self._get_cmdb("firewall/address")

    def get_address_groups(self) -> list[dict]:
        """Address group objects (may contain nested groups)."""
        return self._get_cmdb("firewall/addrgrp")

    def get_addresses6(self) -> list[dict]:
        """IPv6 address objects."""
        try:
            return self._get_cmdb("firewall/address6")
        except Exception:
            return []

    def get_address_groups6(self) -> list[dict]:
        """IPv6 address group objects."""
        try:
            return self._get_cmdb("firewall/addrgrp6")
        except Exception:
            return []

    # ── Service objects ──────────────────────────────────────────────────────

    def get_services(self) -> list[dict]:
        """Custom service objects (TCP/UDP/ICMP/IP)."""
        try:
            return self._get_cmdb("firewall/service/custom")
        except Exception as e:
            logger.warning("Custom services not available: %s", e)
            return []

    def get_service_groups(self) -> list[dict]:
        """Service group objects."""
        try:
            return self._get_cmdb("firewall/service/group")
        except Exception as e:
            logger.warning("Service groups not available: %s", e)
            return []

    # ── NAT / VIP objects ────────────────────────────────────────────────────

    def get_vips(self) -> list[dict]:
        """
        Virtual IP objects — DNAT / port-forwarding rules.
        VIPs appear as destinations in firewall policies; understanding them
        is critical for analysing over-permissive inbound access rules.
        """
        try:
            return self._get_cmdb("firewall/vip")
        except Exception as e:
            logger.debug("VIPs not available: %s", e)
            return []

    def get_vip_groups(self) -> list[dict]:
        """VIP group objects."""
        try:
            return self._get_cmdb("firewall/vipgrp")
        except Exception:
            return []

    def get_ip_pools(self) -> list[dict]:
        """
        IP pool objects — SNAT / overload NAT sources.
        Used in outbound rules with NAT enabled.
        """
        try:
            return self._get_cmdb("firewall/ippool")
        except Exception as e:
            logger.debug("IP pools not available: %s", e)
            return []

    # ── Schedule objects ─────────────────────────────────────────────────────

    def get_schedules(self) -> list[dict]:
        """Both one-time and recurring schedule objects."""
        schedules: list[dict] = []
        try:
            schedules += self._get_cmdb("firewall/schedule/onetime")
        except Exception:
            pass
        try:
            schedules += self._get_cmdb("firewall/schedule/recurring")
        except Exception:
            pass
        return schedules

    # ── Topology helpers ─────────────────────────────────────────────────────

    def get_interfaces(self) -> list[dict]:
        """System interfaces — used to map zones to physical/VLAN interfaces."""
        try:
            return self._get_cmdb("system/interface")
        except Exception as e:
            logger.debug("Interfaces not available: %s", e)
            return []

    def get_zones(self) -> list[dict]:
        """Zone objects — maps logical zones to member interfaces."""
        try:
            return self._get_cmdb("system/zone")
        except Exception as e:
            logger.debug("Zones not available: %s", e)
            return []

    # ── Live hit counts ──────────────────────────────────────────────────────

    def get_policy_hit_counts(self) -> dict[int, dict]:
        """
        Fetch live per-policy hit statistics from the monitor API.

        Handles field-name variations across FortiOS versions:
          hit_count / hitcount
          bytes / byte
          pkts / packets
          active_sessions / sesscount
          first_used / first_hit
          last_used / last_hit
        """
        data = self._get_monitor("firewall/policy")
        results = data.get("results", [])

        hit_map: dict[int, dict] = {}
        for r in results:
            pid = r.get("policyid", r.get("id"))
            if pid is None:
                continue
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                continue

            hit_map[pid] = {
                "hit_count":       _first_defined(r, "hit_count", "hitcount", default=0),
                "bytes":           _first_defined(r, "bytes", "byte", default=0),
                "pkts":            _first_defined(r, "pkts", "packets", default=0),
                "active_sessions": _first_defined(r, "active_sessions", "sesscount", default=0),
                "first_used":      _first_defined(r, "first_used", "first_hit", default=None),
                "last_used":       _first_defined(r, "last_used", "last_hit", default=None),
            }
        return hit_map

    # ── Full fetch ───────────────────────────────────────────────────────────

    def get_all(self) -> dict:
        """
        Fetch all data required for complete policy analysis.

        Returns:
          policies       — IPv4 firewall rules
          policies6      — IPv6 firewall rules
          addresses      — address objects
          address_groups — address group objects
          addresses6     — IPv6 address objects
          address_groups6 — IPv6 address group objects
          services       — custom service objects
          service_groups — service group objects
          vips           — virtual IP (DNAT) objects
          vip_groups     — VIP group objects
          ip_pools       — IP pool (SNAT) objects
          schedules      — schedule objects
          interfaces     — system interfaces
          zones          — zone definitions
          hit_counts     — {policyid: {hit_count, bytes, pkts, ...}}
        """
        # Hit counts — always try, non-fatal if unavailable
        hit_counts: dict = {}
        try:
            hit_counts = self.get_policy_hit_counts()
            logger.info("Hit counts fetched: %d policies", len(hit_counts))
        except Exception as e:
            logger.warning("Could not fetch hit counts (monitor API): %s", e)

        policies   = self.get_policies()
        policies6  = self.get_policies6()
        logger.info("Policies: %d IPv4, %d IPv6", len(policies), len(policies6))

        addresses       = self.get_addresses()
        address_groups  = self.get_address_groups()
        addresses6      = self.get_addresses6()
        address_groups6 = self.get_address_groups6()
        logger.info(
            "Address objects: %d addrs, %d groups, %d addrs6, %d groups6",
            len(addresses), len(address_groups), len(addresses6), len(address_groups6),
        )

        services       = self.get_services()
        service_groups = self.get_service_groups()
        logger.info("Services: %d custom, %d groups", len(services), len(service_groups))

        vips       = self.get_vips()
        vip_groups = self.get_vip_groups()
        ip_pools   = self.get_ip_pools()
        logger.info("NAT objects: %d VIPs, %d VIP groups, %d IP pools", len(vips), len(vip_groups), len(ip_pools))

        schedules  = self.get_schedules()
        interfaces = self.get_interfaces()
        zones      = self.get_zones()

        return {
            "policies":        policies,
            "policies6":       policies6,
            "addresses":       addresses,
            "address_groups":  address_groups,
            "addresses6":      addresses6,
            "address_groups6": address_groups6,
            "services":        services,
            "service_groups":  service_groups,
            "vips":            vips,
            "vip_groups":      vip_groups,
            "ip_pools":        ip_pools,
            "schedules":       schedules,
            "interfaces":      interfaces,
            "zones":           zones,
            "hit_counts":      hit_counts,
        }


# ── Utilities ────────────────────────────────────────────────────────────────

def _first_defined(d: dict, *keys, default=None):
    """Return the value of the first key found in d, or default."""
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v
    return default


def fgt_subnet_to_cidr(subnet_str: str) -> str:
    """
    Convert FortiGate subnet string '10.0.0.0 255.255.0.0' → '10.0.0.0/16'.
    Returns original string if conversion fails.
    """
    parts = subnet_str.split()
    if len(parts) == 2:
        try:
            net = ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
            return str(net)
        except Exception:
            pass
    return subnet_str
