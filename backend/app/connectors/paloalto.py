"""
Palo Alto PAN-OS connector — supports both standalone firewalls and Panorama.

Authentication:
  API key passed as X-PAN-KEY header (REST API) or &key= param (XML API).
  Generate key:  GET /api/?type=keygen&user=<u>&password=<p>
  Response: <response><result><key>APIKEY</key></result></response>

REST API endpoints (PAN-OS 9.0+):
  GET /restapi/v{ver}/Policies/SecurityRules?location=vsys&vsys=vsys1
  GET /restapi/v{ver}/Objects/Addresses?location=vsys&vsys=vsys1
  GET /restapi/v{ver}/Objects/AddressGroups?location=vsys&vsys=vsys1
  GET /restapi/v{ver}/Objects/Services?location=vsys&vsys=vsys1
  GET /restapi/v{ver}/Objects/ServiceGroups?location=vsys&vsys=vsys1
  GET /restapi/v{ver}/Objects/Applications?location=vsys&vsys=vsys1

XML API (operational commands — for hit counts):
  GET /api/?type=op&key=KEY&cmd=<show><rule-hit-count>...</rule-hit-count></show>
  Fields returned per rule: hit-count, last-hit-timestamp, first-hit-timestamp,
                             rule-creation-timestamp, rule-modification-timestamp

Docs: https://pan.dev/panos/docs/restapi/
      https://pan.dev/panos/docs/tutorials/rule-hit-counts/
"""
import logging
import urllib3
import xml.etree.ElementTree as ET
from typing import Optional
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

# Default REST API version — device may support higher versions
DEFAULT_API_VER = "v10.2"


class PaloAltoConnector:
    """Read-only PAN-OS REST + XML API client."""

    def __init__(
        self,
        host: str,
        *,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        vsys: str = "vsys1",
        api_version: str = DEFAULT_API_VER,
        timeout: int = 30,
    ):
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}"
        self.api_key = api_key
        self.username = username
        self.password = password
        self.vsys = vsys
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl

    # ── Auth ─────────────────────────────────────────────────────────────────

    def connect(self) -> dict:
        """Authenticate and return device info."""
        if not self.api_key:
            self.api_key = self._generate_key()

        self._session.headers.update({"X-PAN-KEY": self.api_key})

        # Get system info via XML API
        info = self._xml_op("<show><system><info/></system></show>")
        sys_info = info.find(".//system") or ET.Element("system")
        return {
            "hostname": self._text(sys_info, "hostname"),
            "ip_address": self._text(sys_info, "ip-address"),
            "model": self._text(sys_info, "model"),
            "sw_version": self._text(sys_info, "sw-version"),
            "vsys": self.vsys,
            "api_version": self.api_version,
        }

    def _generate_key(self) -> str:
        url = f"{self.base_url}/api/?type=keygen&user={self.username}&password={self.password}"
        resp = self._session.get(url, timeout=self.timeout, verify=self.verify_ssl)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        key = root.findtext(".//key")
        if not key:
            raise ConnectionError("PAN-OS key generation failed — check credentials")
        return key

    # ── REST API helpers ─────────────────────────────────────────────────────

    def _rest_get(self, resource: str) -> list:
        """GET /restapi/{ver}/{resource}?location=vsys&vsys=vsys1 — returns entry list."""
        url = f"{self.base_url}/restapi/{self.api_version}/{resource}"
        params = {"location": "vsys", "vsys": self.vsys}
        resp = self._session.get(url, params=params, timeout=self.timeout, verify=self.verify_ssl)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result", {})
        if result is None:
            return []
        entries = result.get("entry", [])
        return entries if isinstance(entries, list) else [entries]

    # ── XML API helper ────────────────────────────────────────────────────────

    def _xml_op(self, cmd: str) -> ET.Element:
        """Run an operational command via XML API, return parsed root element."""
        url = f"{self.base_url}/api/"
        params = {"type": "op", "key": self.api_key, "cmd": cmd}
        resp = self._session.get(url, params=params, timeout=self.timeout, verify=self.verify_ssl)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.get("status") == "error":
            msg = root.findtext(".//msg") or "Unknown error"
            raise RuntimeError(f"PAN-OS XML API error: {msg}")
        return root

    @staticmethod
    def _text(el: ET.Element, tag: str) -> str:
        sub = el.find(tag)
        return sub.text or "" if sub is not None else ""

    # ── Data fetchers ─────────────────────────────────────────────────────────

    def get_security_rules(self) -> list[dict]:
        return self._rest_get("Policies/SecurityRules")

    def get_addresses(self) -> list[dict]:
        return self._rest_get("Objects/Addresses")

    def get_address_groups(self) -> list[dict]:
        return self._rest_get("Objects/AddressGroups")

    def get_services(self) -> list[dict]:
        return self._rest_get("Objects/Services")

    def get_service_groups(self) -> list[dict]:
        return self._rest_get("Objects/ServiceGroups")

    def get_applications(self) -> list[dict]:
        return self._rest_get("Objects/Applications")

    def get_hit_counts(self) -> dict[str, dict]:
        """
        Fetch hit counts for all security rules via XML API.
        Returns dict keyed by rule name.
        """
        cmd = (
            f"<show><rule-hit-count><vsys><vsys-name>"
            f"<entry name='{self.vsys}'>"
            f"<rule-base><entry name='security'><rules><all/></rules></entry></rule-base>"
            f"</entry></vsys-name></vsys></rule-hit-count></show>"
        )
        try:
            root = self._xml_op(cmd)
        except Exception as e:
            logger.warning("Could not fetch PA hit counts: %s", e)
            return {}

        hit_map: dict[str, dict] = {}
        for entry in root.findall(".//rules/entry"):
            name = entry.get("name", "")
            if not name:
                continue
            hit_map[name] = {
                "hit_count": int(self._text(entry, "hit-count") or 0),
                "last_hit_ts": int(self._text(entry, "last-hit-timestamp") or 0),
                "first_hit_ts": int(self._text(entry, "first-hit-timestamp") or 0),
                "last_reset_ts": int(self._text(entry, "last-reset-timestamp") or 0),
            }
        return hit_map

    def get_all(self) -> dict:
        hit_counts = {}
        try:
            hit_counts = self.get_hit_counts()
        except Exception as e:
            logger.warning("PA hit count fetch failed: %s", e)

        return {
            "rules": self.get_security_rules(),
            "addresses": self.get_addresses(),
            "address_groups": self.get_address_groups(),
            "services": self.get_services(),
            "service_groups": self.get_service_groups(),
            "applications": self.get_applications(),
            "hit_counts": hit_counts,
        }


# ── Translation helper (used by live_sync.py) ─────────────────────────────────

def translate(raw: dict) -> dict:
    """Convert PAN-OS REST API output to normalised format."""
    from datetime import datetime

    rules_raw = raw.get("rules", [])
    addrs = {a.get("@name", ""): a for a in raw.get("addresses", [])}
    addr_grps = {g.get("@name", ""): g for g in raw.get("address_groups", [])}
    svcs = {s.get("@name", ""): s for s in raw.get("services", [])}
    svc_grps = {g.get("@name", ""): g for g in raw.get("service_groups", [])}
    hit_counts = raw.get("hit_counts", {})  # keyed by rule name

    obj_map: dict[str, dict] = {}

    for name, a in addrs.items():
        obj_map[name] = _pa_addr(name, a)

    for name, g in addr_grps.items():
        members = _members(g.get("static", {}).get("member", []))
        obj_map[name] = {"type": "group", "value": None, "members": members, "comment": g.get("description", "")}

    for name, s in svcs.items():
        obj_map[name] = _pa_svc(name, s)

    for name, g in svc_grps.items():
        members = _members(g.get("members", {}).get("member", []))
        obj_map[name] = {"type": "service-group", "value": None, "members": members, "comment": g.get("description", "")}

    rules: list[dict] = []
    for seq, r in enumerate(rules_raw):
        rname = r.get("@name", f"rule_{seq+1}")
        stats = hit_counts.get(rname, {})

        # Convert unix timestamps to ISO
        def _ts(val):
            if not val:
                return None
            try:
                return datetime.utcfromtimestamp(int(val)).isoformat() if int(val) > 0 else None
            except Exception:
                return None

        rule = {
            "rule_id": rname,
            "rule_name": rname,
            "section": r.get("group-tag", ""),
            "sources": _members(r.get("source", {}).get("member", [])),
            "destinations": _members(r.get("destination", {}).get("member", [])),
            "services": _members(r.get("service", {}).get("member", [])),
            "source_interfaces": _members(r.get("from", {}).get("member", [])),
            "destination_interfaces": _members(r.get("to", {}).get("member", [])),
            "action": r.get("action", "allow").replace("allow", "accept"),
            "enabled": r.get("disabled", "no") != "yes",
            "logging_enabled": r.get("log-end", "yes") == "yes",
            "nat_enabled": False,
            "schedule": r.get("schedule", "any"),
            "comments": r.get("description", ""),
            "applications": _members(r.get("application", {}).get("member", [])),
            "hit_count": stats.get("hit_count", 0),
            "bytes": 0,
            "pkts": 0,
            "active_sessions": 0,
            "first_hit": _ts(stats.get("first_hit_ts")),
            "last_hit": _ts(stats.get("last_hit_ts")),
        }
        rules.append(rule)

    return {"rules": rules, "objects": obj_map, "warnings": []}


def _members(val) -> list[str]:
    if not val:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _pa_addr(name: str, a: dict) -> dict:
    if "ip-netmask" in a:
        return {"type": "network", "value": a["ip-netmask"], "members": [], "comment": a.get("description", "")}
    elif "ip-range" in a:
        return {"type": "range", "value": a["ip-range"], "members": [], "comment": a.get("description", "")}
    elif "fqdn" in a:
        return {"type": "fqdn", "value": a["fqdn"], "members": [], "comment": a.get("description", "")}
    return {"type": "host", "value": "", "members": [], "comment": a.get("description", "")}


def _pa_svc(name: str, s: dict) -> dict:
    proto_block = s.get("protocol", {})
    if "tcp" in proto_block:
        proto, port_str = "TCP", str(proto_block["tcp"].get("port", "0"))
    elif "udp" in proto_block:
        proto, port_str = "UDP", str(proto_block["udp"].get("port", "0"))
    else:
        return {"type": "service", "protocol": "TCP", "port_start": 0, "port_end": 65535, "members": [], "comment": s.get("description", "")}

    lo, hi = 0, 65535
    if "-" in port_str:
        parts = port_str.split("-")
        try:
            lo, hi = int(parts[0]), int(parts[1])
        except ValueError:
            pass
    else:
        try:
            lo = hi = int(port_str)
        except ValueError:
            pass

    return {"type": "service", "protocol": proto, "port_start": lo, "port_end": hi, "members": [], "comment": s.get("description", "")}
