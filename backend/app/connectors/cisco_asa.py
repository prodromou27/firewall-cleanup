"""
Cisco ASA REST API connector.

Authentication:
  Token: POST /api/tokenservices  (Basic auth header)
  Response header: X-Auth-Token: <token>
  All subsequent requests: X-Auth-Token: <token>
  Logout: DELETE /api/tokenservices/<token>

  Fallback: Basic auth on every request (no token).

Key endpoints:
  GET /api/access/in/{ifName}/rules   — inbound ACL rules per interface
  GET /api/access/out/{ifName}/rules  — outbound ACL rules per interface
  GET /api/access/global/rules        — global rules
  GET /api/objects/networkobjects     — network/host objects
  GET /api/objects/networkgroups      — object groups
  GET /api/objects/serviceobjects     — service objects
  GET /api/objects/servicegroups      — service groups
  GET /api/interfaces                 — list interface names
  POST /api/cli                       — run "show access-list" to get hit counts

Docs: https://www.cisco.com/c/en/us/td/docs/security/asa/api/qsg-asa-api.html
"""
import logging
import urllib3
import re
from typing import Optional
import requests
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

PAGE_SIZE = 100


class CiscoASAConnector:
    """Read-only Cisco ASA REST API client."""

    def __init__(
        self,
        host: str,
        *,
        username: str,
        password: str,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({"Content-Type": "application/json"})

    # ── Auth ──────────────────────────────────────────────────────────────────

    def connect(self) -> dict:
        """Authenticate and return device info."""
        try:
            resp = self._session.post(
                f"{self.base_url}/api/tokenservices",
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if resp.status_code in (200, 204):
                self._token = resp.headers.get("X-Auth-Token") or resp.text.strip('"')
                if self._token:
                    self._session.headers.update({"X-Auth-Token": self._token})
        except Exception as e:
            logger.warning("Token auth failed, falling back to basic auth: %s", e)

        if not self._token:
            self._session.auth = HTTPBasicAuth(self.username, self.password)

        # Get version info
        try:
            info_resp = self._session.get(
                f"{self.base_url}/api/monitoring/serialno",
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            info = info_resp.json() if info_resp.ok else {}
        except Exception:
            info = {}

        return {
            "serial": info.get("serialno", "unknown"),
            "host": self.base_url,
        }

    def disconnect(self):
        if self._token:
            try:
                self._session.delete(
                    f"{self.base_url}/api/tokenservices/{self._token}",
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            except Exception:
                pass
            self._token = None

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get_paged(self, path: str) -> list:
        """GET with pagination via offset/limit."""
        results = []
        offset = 0
        while True:
            url = f"{self.base_url}{path}"
            params = {"offset": offset, "limit": PAGE_SIZE}
            resp = self._session.get(url, params=params, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 404:
                return results
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("items", data.get("results", []))
            results.extend(batch)
            if len(results) >= data.get("rangeInfo", {}).get("total", len(results)):
                break
            offset += PAGE_SIZE
        return results

    def _cli(self, command: str) -> str:
        """Execute a CLI command via /api/cli and return the output text."""
        resp = self._session.post(
            f"{self.base_url}/api/cli",
            json={"commands": [command]},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        if not resp.ok:
            return ""
        data = resp.json()
        response_list = data.get("response", [])
        return response_list[0] if response_list else ""

    # ── Data fetchers ─────────────────────────────────────────────────────────

    def get_interfaces(self) -> list[dict]:
        return self._get_paged("/api/interfaces")

    def get_global_rules(self) -> list[dict]:
        return self._get_paged("/api/access/global/rules")

    def get_in_rules(self, iface: str) -> list[dict]:
        rules = self._get_paged(f"/api/access/in/{iface}/rules")
        for r in rules:
            r["_interface"] = iface
            r["_direction"] = "in"
        return rules

    def get_out_rules(self, iface: str) -> list[dict]:
        rules = self._get_paged(f"/api/access/out/{iface}/rules")
        for r in rules:
            r["_interface"] = iface
            r["_direction"] = "out"
        return rules

    def get_network_objects(self) -> list[dict]:
        return self._get_paged("/api/objects/networkobjects")

    def get_network_groups(self) -> list[dict]:
        return self._get_paged("/api/objects/networkgroups")

    def get_service_objects(self) -> list[dict]:
        return self._get_paged("/api/objects/serviceobjects")

    def get_service_groups(self) -> list[dict]:
        return self._get_paged("/api/objects/servicegroups")

    def get_hit_counts(self) -> dict[str, int]:
        """
        Parse 'show access-list' CLI output to extract hit counts per ACL entry.
        Returns dict: {"acl_name:line_num" -> hit_count}
        """
        output = self._cli("show access-list")
        hit_map: dict[str, int] = {}
        # Pattern: "access-list ACLNAME line N ... (hitcnt=123) 0x..."
        pattern = re.compile(r"access-list\s+(\S+)\s+line\s+(\d+).*?\(hitcnt=(\d+)\)", re.IGNORECASE)
        for m in pattern.finditer(output):
            acl_name, line_num, hitcnt = m.group(1), m.group(2), m.group(3)
            hit_map[f"{acl_name}:{line_num}"] = int(hitcnt)
        return hit_map

    def get_all(self) -> dict:
        """Fetch everything needed for full analysis."""
        # Get all rules across all interfaces
        all_rules: list[dict] = []
        all_rules.extend(self.get_global_rules())

        try:
            ifaces = self.get_interfaces()
            for iface in ifaces:
                name = iface.get("name") or iface.get("nameif", "")
                if not name:
                    continue
                try:
                    all_rules.extend(self.get_in_rules(name))
                except Exception:
                    pass
                try:
                    all_rules.extend(self.get_out_rules(name))
                except Exception:
                    pass
        except Exception as e:
            logger.warning("Could not enumerate interfaces: %s", e)

        hit_counts = {}
        try:
            hit_counts = self.get_hit_counts()
        except Exception as e:
            logger.warning("Could not fetch ASA hit counts: %s", e)

        return {
            "rules": all_rules,
            "network_objects": self.get_network_objects(),
            "network_groups": self.get_network_groups(),
            "service_objects": self.get_service_objects(),
            "service_groups": self.get_service_groups(),
            "hit_counts": hit_counts,
        }


# ── Translation helper ────────────────────────────────────────────────────────

def translate(raw: dict) -> dict:
    """Convert Cisco ASA REST API output to normalised format."""
    rules_raw = raw.get("rules", [])
    net_objs = {o.get("name", ""): o for o in raw.get("network_objects", [])}
    net_grps = {g.get("name", ""): g for g in raw.get("network_groups", [])}
    svc_objs = {s.get("name", ""): s for s in raw.get("service_objects", [])}
    svc_grps = {g.get("name", ""): g for g in raw.get("service_groups", [])}
    hit_counts = raw.get("hit_counts", {})

    obj_map: dict[str, dict] = {}

    for name, o in net_objs.items():
        kind = o.get("kind", "")
        if kind == "IPv4Network":
            host = o.get("host", {})
            value = f"{host.get('value', '')}/{host.get('prefix', '32')}"
            obj_map[name] = {"type": "network", "value": value, "members": [], "comment": o.get("description", "")}
        elif kind == "IPv4Address":
            obj_map[name] = {"type": "host", "value": o.get("host", {}).get("value", ""), "members": [], "comment": o.get("description", "")}
        elif kind == "IPv4Range":
            r = o.get("host", {})
            obj_map[name] = {"type": "range", "value": f"{r.get('firstAddress', '')}-{r.get('lastAddress', '')}", "members": [], "comment": o.get("description", "")}
        else:
            obj_map[name] = {"type": "host", "value": "", "members": [], "comment": o.get("description", "")}

    for name, g in net_grps.items():
        members = [m.get("value", {}).get("name", "") for m in g.get("members", {}).get("items", [])]
        obj_map[name] = {"type": "group", "value": None, "members": [m for m in members if m], "comment": g.get("description", "")}

    for name, s in svc_objs.items():
        proto = s.get("protocol", "TCP").upper()
        port = s.get("destinationPort", {}).get("value", "0")
        lo, hi = _parse_port(str(port))
        obj_map[name] = {"type": "service", "protocol": proto, "port_start": lo, "port_end": hi, "members": [], "comment": s.get("description", "")}

    for name, g in svc_grps.items():
        members = [m.get("value", {}).get("name", "") for m in g.get("members", {}).get("items", [])]
        obj_map[name] = {"type": "service-group", "value": None, "members": [m for m in members if m], "comment": g.get("description", "")}

    rules: list[dict] = []
    for seq, r in enumerate(rules_raw):
        rule_id = str(r.get("objectId", seq + 1))
        iface = r.get("_interface", "")
        direction = r.get("_direction", "in")
        acl_key = f"{iface}:{r.get('lineNum', seq+1)}"

        src = _asa_addr(r.get("sourceAddress", {}))
        dst = _asa_addr(r.get("destinationAddress", {}))
        svc = _asa_svc_name(r.get("service", {}))

        rule = {
            "rule_id": rule_id,
            "rule_name": r.get("remarks", [f"rule_{rule_id}"])[0] if r.get("remarks") else f"rule_{rule_id}",
            "section": f"{iface}/{direction}" if iface else "global",
            "sources": [src],
            "destinations": [dst],
            "services": [svc] if svc else ["any"],
            "source_interfaces": [iface] if iface else [],
            "destination_interfaces": [],
            "action": "accept" if r.get("permit", True) else "deny",
            "enabled": r.get("active", True),
            "logging_enabled": r.get("logInterval", 0) > 0 or r.get("logLevel") not in (None, "default"),
            "nat_enabled": False,
            "schedule": "always",
            "comments": "; ".join(r.get("remarks", [])),
            "applications": [],
            "hit_count": hit_counts.get(acl_key, 0),
            "bytes": 0,
            "pkts": 0,
            "active_sessions": 0,
            "first_hit": None,
            "last_hit": None,
        }
        rules.append(rule)

    return {"rules": rules, "objects": obj_map, "warnings": []}


def _asa_addr(addr_obj: dict) -> str:
    kind = addr_obj.get("kind", "")
    val = addr_obj.get("value", {})
    if isinstance(val, dict):
        if kind == "AnyIPAddress":
            return "any"
        elif kind == "IPv4Address":
            return val.get("value", "any")
        elif kind == "IPv4Network":
            return f"{val.get('value', '')}/{val.get('prefix', '32')}"
        elif kind in ("objectRef#NetworkObject", "objectRef#NetworkObjectGroup"):
            return val.get("name", "any")
    if isinstance(val, str):
        return val or "any"
    return "any"


def _asa_svc_name(svc_obj: dict) -> str:
    kind = svc_obj.get("kind", "")
    val = svc_obj.get("value", {})
    if kind == "NetworkProtocol" and isinstance(val, dict):
        proto = val.get("name", "ip").upper()
        return proto
    if isinstance(val, dict) and "name" in val:
        return val["name"]
    return ""


def _parse_port(port_str: str) -> tuple[int, int]:
    s = port_str.strip()
    if "-" in s:
        parts = s.split("-")
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            pass
    try:
        p = int(s)
        return p, p
    except ValueError:
        return 0, 65535
