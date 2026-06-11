"""
Huawei USG Firewall Connector
==============================
Supports Huawei USG2000/5000/6000/6000E/6000F/9000 series via HTTPS REST API.

Authentication
--------------
  POST /api/v1/auth/sessions
  Body: {"userName": "<user>", "password": "<pass>"}
  Returns: {"data": {"token": "<token>", ...}}

  Some firmware versions use:
    POST /web/xLogin  (form-based, returns cookie + token in response body)
    POST /api/v2/auth/token
    POST /webapi/v1/auth/sessions
    POST /rest/v1/auth/sessions

  All subsequent requests use:
    Header: X-Auth-Token: <token>

Endpoints used
--------------
  POST <base>/auth/sessions              → authenticate, get token
  GET  <base>/device/overview            → device info (version, model, serial)
  GET  <base>/sys/info                   → alternative device info endpoint
  GET  <base>/sec-policy/ipv4            → IPv4 security policy rules
  GET  <base>/sec-policy/ipv6            → IPv6 security policy rules
  GET  <base>/policy/security/rules      → alternative security policy endpoint
  GET  <base>/object/address             → address objects
  GET  <base>/object/address-group       → address group objects
  GET  <base>/object/service             → service objects
  GET  <base>/object/service-group       → service group objects
  GET  <base>/object/region              → zone/interface objects
  GET  <base>/zone                       → alternative zone endpoint
  GET  <base>/monitor/statistic          → traffic / hit count statistics
  DELETE <base>/auth/sessions/<token>    → logout

API base path probing order (newest → oldest firmware):
  /api/v2      (USG6000E/F V600+)
  /api/v1      (USG6000 V500R001C60+)
  /webapi/v2
  /webapi/v1   (USG6000 V500R001C30)
  /rest/v2
  /rest/v1     (USG2000/5000 older)
  /api         (some management platform variants)

Port probing order: user-specified, then 8443 (USG6000E/F common), then 443.
HTTP fallback is attempted if HTTPS fails (for lab/management network scenarios).

SAFETY: Read-only — no write or delete calls are made to policy objects.
        Only DELETE on the session token (logout) which is a cleanup op.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 443
_TIMEOUT = 15
_PAGE_SIZE = 1000  # max records per page (Huawei allows up to 1000)

# All known API base paths, newest/most-common firmware first
_API_BASES = [
    "/api/v2",
    "/api/v1",
    "/webapi/v2",
    "/webapi/v1",
    "/rest/v2",
    "/rest/v1",
    "/api",
    "/webapi",
]

# Auth endpoint suffixes to try under each base
_AUTH_PATHS = [
    "/auth/sessions",
    "/auth/token",
    "/auth/login",
]


class HuaweiUSGConnector:
    """REST API connector for Huawei USG firewall series."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = _DEFAULT_PORT,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        vsys: Optional[str] = None,  # reserved — USG uses virtual systems differently
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._session_id: Optional[str] = None
        self._base_url: Optional[str] = None  # e.g. "https://host:443/api/v1"
        self._api_base: Optional[str] = None  # e.g. "/api/v1"

    # ── internal helpers ─────────────────────────────────────────────────────

    def _get_client(self):
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required: pip install httpx")
        return httpx.Client(verify=self.verify_ssl, timeout=_TIMEOUT)

    def _url(self, path: str) -> str:
        scheme = "https" if self.use_ssl else "http"
        base = self._base_url or f"{scheme}://{self.host}:{self.port}"
        return f"{base}{path}"

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token:
            h["X-Auth-Token"] = self._token
        return h

    def _get_paged(self, client, path: str) -> List[dict]:
        """Fetch all pages from a paginated endpoint."""
        results = []
        offset = 0
        while True:
            sep = "&" if "?" in path else "?"
            url = self._url(f"{path}{sep}offset={offset}&count={_PAGE_SIZE}")
            resp = client.get(url, headers=self._headers())
            if resp.status_code != 200:
                logger.warning("GET %s returned %d", path, resp.status_code)
                break
            data = resp.json()
            items = data.get("data", data) if isinstance(data, dict) else data
            if isinstance(items, dict):
                items = items.get("rules", items.get("items", items.get("data", [])))
            if not isinstance(items, list) or len(items) == 0:
                break
            results.extend(items)
            if len(items) < _PAGE_SIZE:
                break
            offset += _PAGE_SIZE
        return results

    # ── internal: connection probing ──────────────────────────────────────────

    def _candidate_origins(self) -> List[str]:
        """
        Build ordered list of (scheme, host, port) origin strings to try.
        Order: user-specified scheme+port first, then HTTPS/8443, HTTPS/443,
        HTTP/8080, HTTP/80 as fallbacks.
        """
        seen = set()
        origins = []

        def _add(scheme: str, port: int):
            key = (scheme, port)
            if key not in seen:
                seen.add(key)
                origins.append(f"{scheme}://{self.host}:{port}")

        # User-configured combination first
        scheme0 = "https" if self.use_ssl else "http"
        _add(scheme0, self.port)

        # Common Huawei management ports
        _add("https", 8443)
        _add("https", 443)
        _add("https", 4433)
        _add("http",  8080)
        _add("http",  80)
        _add("http",  8888)

        return origins

    def _try_auth(self, client, origin: str, api_base: str) -> Optional[Tuple[str, str]]:
        """
        Attempt authentication at origin+api_base. Returns (token, session_id)
        or None if this combination doesn't work.
        Raises PermissionError immediately on 401 (wrong credentials).
        """
        payload = {"userName": self.username, "password": self.password}
        # Some firmware variants use "user" instead of "userName"
        payloads_to_try = [
            {"userName": self.username, "password": self.password},
            {"user": self.username, "password": self.password},
            {"username": self.username, "password": self.password},
        ]

        for auth_path in _AUTH_PATHS:
            url = f"{origin}{api_base}{auth_path}"
            for payload in payloads_to_try:
                try:
                    resp = client.post(
                        url,
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                        content=json.dumps(payload),
                        timeout=_TIMEOUT,
                    )
                    if resp.status_code == 401:
                        raise PermissionError(
                            f"Authentication failed (401) at {url} — check username/password"
                        )
                    if resp.status_code in (200, 201):
                        try:
                            body = resp.json()
                        except Exception:
                            continue
                        token = (
                            (body.get("data") or {}).get("token")
                            or (body.get("data") or {}).get("authToken")
                            or body.get("token")
                            or body.get("authToken")
                            or body.get("X-Auth-Token")
                            or resp.headers.get("X-Auth-Token")
                            or resp.headers.get("x-auth-token")
                        )
                        if token:
                            session_id = (
                                (body.get("data") or {}).get("sessionId")
                                or (body.get("data") or {}).get("session_id")
                                or body.get("sessionId")
                                or token
                            )
                            logger.info(
                                "Huawei USG authenticated at %s%s%s",
                                origin, api_base, auth_path,
                            )
                            return token, session_id
                except PermissionError:
                    raise
                except Exception as e:
                    logger.debug("Auth probe %s failed: %s", url, e)
                    break  # connection error — skip remaining payloads for this path
        return None

    # ── public interface ──────────────────────────────────────────────────────

    def connect(self) -> dict:
        """
        Authenticate and probe the device.
        Tries all known API base paths across all candidate origins.
        Returns info dict:
          {version, model, serial, rule_count, object_count, zone_count}
        Raises on failure.
        """
        client = self._get_client()

        found = False
        origins_tried: List[str] = []

        for origin in self._candidate_origins():
            origins_tried.append(origin)
            for api_base in _API_BASES:
                try:
                    result = self._try_auth(client, origin, api_base)
                except PermissionError:
                    raise  # wrong password — don't keep probing
                if result:
                    self._token, self._session_id = result
                    self._base_url = origin
                    self._api_base = api_base
                    found = True
                    break
            if found:
                break

        if not found:
            tried_summary = ", ".join(
                f"{o}{b}" for o in origins_tried[:3] for b in _API_BASES[:3]
            )
            raise ConnectionError(
                f"Could not connect to Huawei USG at {self.host} — "
                f"no supported API base found. "
                f"Tried origins: {', '.join(origins_tried)}. "
                f"Example paths tried: {tried_summary}... "
                f"Verify the device is reachable, the port is correct, "
                f"and the web API service is enabled on the device."
            )

        # Probe device info using discovered base
        info: Dict[str, Any] = {}
        info_endpoints = [
            f"{self._api_base}/device/overview",
            f"{self._api_base}/sys/info",
            f"{self._api_base}/device/info",
            f"{self._api_base}/system/info",
        ]
        for ep in info_endpoints:
            try:
                r = client.get(self._url(ep), headers=self._headers())
                if r.status_code == 200:
                    d = r.json()
                    d = d.get("data", d) if isinstance(d, dict) else d
                    if isinstance(d, dict):
                        info["version"] = (
                            d.get("softwareVersion") or d.get("vrpVersion")
                            or d.get("version") or d.get("sysVersion") or ""
                        )
                        info["model"] = (
                            d.get("deviceName") or d.get("productModel")
                            or d.get("model") or d.get("sysName") or ""
                        )
                        info["serial"] = (
                            d.get("esn") or d.get("serialNumber")
                            or d.get("serial") or d.get("sn") or ""
                        )
                        if info.get("version") or info.get("model"):
                            break
            except Exception as e:
                logger.debug("Device info from %s failed: %s", ep, e)

        # Count rules
        try:
            rules = self._get_paged(client, f"{self._api_base}/sec-policy/ipv4")
            info["rule_count"] = len(rules)
        except Exception:
            try:
                rules = self._get_paged(client, f"{self._api_base}/policy/security/rules")
                info["rule_count"] = len(rules)
            except Exception:
                info["rule_count"] = 0

        # Count address objects
        try:
            addrs = self._get_paged(client, f"{self._api_base}/object/address")
            info["object_count"] = len(addrs)
        except Exception:
            info["object_count"] = 0

        # Count zones
        for zone_ep in [f"{self._api_base}/object/region", f"{self._api_base}/zone"]:
            try:
                zones_resp = client.get(self._url(zone_ep), headers=self._headers())
                if zones_resp.status_code == 200:
                    zd = zones_resp.json().get("data", zones_resp.json())
                    info["zone_count"] = len(zd) if isinstance(zd, list) else 0
                    break
            except Exception:
                pass
        else:
            info["zone_count"] = 0

        return info

    def get_all(self) -> dict:
        """
        Fetch all policy rules and objects.
        Returns:
          {
            rules: [...],
            addresses: [...],
            address_groups: [...],
            services: [...],
            service_groups: [...],
            zones: [...],
          }
        """
        if not self._token:
            self.connect()

        client = self._get_client()
        b = self._api_base or "/api/v1"
        result: Dict[str, List] = {
            "rules": [], "addresses": [], "address_groups": [],
            "services": [], "service_groups": [], "zones": [],
        }

        # Rules (IPv4 + IPv6) — try multiple endpoint variants
        for ipv4_ep in [f"{b}/sec-policy/ipv4", f"{b}/policy/security/rules"]:
            try:
                ipv4 = self._get_paged(client, ipv4_ep)
                if ipv4:
                    result["rules"].extend(self._normalize_rules(ipv4))
                    break
            except Exception as e:
                logger.debug("IPv4 rules from %s: %s", ipv4_ep, e)

        try:
            ipv6 = self._get_paged(client, f"{b}/sec-policy/ipv6")
            result["rules"].extend(self._normalize_rules(ipv6, family="ipv6"))
        except Exception as e:
            logger.debug("IPv6 rules: %s", e)

        # Hit count statistics — try statistics endpoints and merge into rules by name
        # Some VRP REST APIs expose per-rule stats separately from the policy listing.
        stat_map: Dict[str, dict] = {}
        for stat_ep in [
            f"{b}/sec-policy/statistics",
            f"{b}/sec-policy/ipv4/statistics",
            f"{b}/monitor/statistic",
            f"{b}/security-policy/statistics",
        ]:
            try:
                stats = self._get_paged(client, stat_ep)
                if stats:
                    for s in stats:
                        name = (s.get("ruleName") or s.get("name") or s.get("id") or "").strip()
                        if name:
                            stat_map[name] = s
                    logger.info("Huawei REST: got %d stats entries from %s", len(stat_map), stat_ep)
                    break
            except Exception as e:
                logger.debug("Stats from %s: %s", stat_ep, e)

        if stat_map:
            for r in result["rules"]:
                name = r.get("rule_name", "")
                if name in stat_map:
                    s = stat_map[name]
                    hc = (s.get("hitCount") or s.get("matchCount") or s.get("forwardMatchCount")
                          or s.get("matchTimes") or 0)
                    if hc and not r.get("hit_count"):
                        r["hit_count"] = hc
                    if not r.get("last_hit"):
                        r["last_hit"] = (s.get("lastMatchTime") or s.get("lastHitTime")
                                         or s.get("forwardLastMatchTime"))
                    if not r.get("first_hit"):
                        r["first_hit"] = (s.get("firstMatchTime") or s.get("firstHitTime")
                                          or s.get("forwardFirstMatchTime"))

        # Address objects
        for addr_ep in [f"{b}/object/address", f"{b}/object/addresses"]:
            try:
                result["addresses"] = self._get_paged(client, addr_ep)
                if result["addresses"]:
                    break
            except Exception as e:
                logger.debug("Address objects from %s: %s", addr_ep, e)

        for ag_ep in [f"{b}/object/address-group", f"{b}/object/addressgroup"]:
            try:
                result["address_groups"] = self._get_paged(client, ag_ep)
                if result["address_groups"]:
                    break
            except Exception as e:
                logger.debug("Address groups from %s: %s", ag_ep, e)

        # Service objects
        for svc_ep in [f"{b}/object/service", f"{b}/object/services"]:
            try:
                result["services"] = self._get_paged(client, svc_ep)
                if result["services"]:
                    break
            except Exception as e:
                logger.debug("Service objects from %s: %s", svc_ep, e)

        for sg_ep in [f"{b}/object/service-group", f"{b}/object/servicegroup"]:
            try:
                result["service_groups"] = self._get_paged(client, sg_ep)
                if result["service_groups"]:
                    break
            except Exception as e:
                logger.debug("Service groups from %s: %s", sg_ep, e)

        # Zones
        for zone_ep in [f"{b}/object/region", f"{b}/zone", f"{b}/object/zone"]:
            try:
                resp = client.get(self._url(zone_ep), headers=self._headers())
                if resp.status_code == 200:
                    d = resp.json()
                    d = d.get("data", d) if isinstance(d, dict) else d
                    result["zones"] = d if isinstance(d, list) else []
                    if result["zones"]:
                        break
            except Exception as e:
                logger.debug("Zones from %s: %s", zone_ep, e)

        return result

    def disconnect(self):
        """Logout / revoke session token."""
        if not self._token:
            return
        b = self._api_base or "/api/v1"
        try:
            client = self._get_client()
            client.delete(
                self._url(f"{b}/auth/sessions/{self._session_id or self._token}"),
                headers=self._headers(),
            )
        except Exception as e:
            logger.debug("Logout failed (non-fatal): %s", e)
        finally:
            self._token = None
            self._session_id = None
            self._api_base = None

    # ── normalisation ─────────────────────────────────────────────────────────

    @staticmethod
    def _names(lst) -> List[str]:
        """Convert a list of name-references (strings or dicts) to a list of strings."""
        if not lst:
            return []
        if isinstance(lst, str):
            return [lst] if lst not in ("any", "") else []
        if not isinstance(lst, list):
            return []
        out: List[str] = []
        for item in lst:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("id") or item.get("refName") or str(item)
                out.append(name)
        return out

    @staticmethod
    def _normalize_rules(rules: List[dict], family: str = "ipv4") -> List[dict]:
        """Normalise Huawei USG rule dicts to the common PolicyInsight schema."""
        action_map = {
            "permit": "accept", "allow": "accept", "accept": "accept",
            "deny": "deny", "drop": "deny", "discard": "deny", "reject": "deny",
        }

        def _names(lst) -> List[str]:
            return HuaweiUSGConnector._names(lst)

        out = []
        for idx, r in enumerate(rules):
            # Source/dest addresses — multiple field name variants across firmware
            srcs = (
                r.get("sourceAddress") or r.get("srcAddress") or r.get("src")
                or r.get("source", {}).get("address") or []
            )
            dsts = (
                r.get("destinationAddress") or r.get("dstAddress") or r.get("dst")
                or r.get("destination", {}).get("address") or []
            )
            svcs = (
                r.get("service") or r.get("services")
                or r.get("serviceGroup") or []
            )
            apps = (
                r.get("application") or r.get("applications")
                or r.get("app") or []
            )
            # Source/dest zones
            src_zones = (
                r.get("sourceZone") or r.get("srcZone") or r.get("srcInterface")
                or r.get("source", {}).get("zone") or []
            )
            dst_zones = (
                r.get("destinationZone") or r.get("dstZone") or r.get("dstInterface")
                or r.get("destination", {}).get("zone") or []
            )
            # Users
            users = r.get("user") or r.get("users") or r.get("sourceUser") or []

            action_raw = str(r.get("action", "permit")).lower()

            # enabled: various representations
            status = r.get("enable") or r.get("status") or r.get("enabled") or r.get("state")
            enabled = status in (True, "enable", "enabled", "active", 1) if status is not None else True

            out.append({
                "rule_id":               r.get("ruleId") or r.get("id") or str(idx),
                "rule_uid":              r.get("ruleId") or r.get("id") or str(idx),
                "rule_number":           r.get("ruleOrder") or r.get("seqNum") or r.get("order") or idx + 1,
                "rule_name":             r.get("ruleName") or r.get("name") or f"Rule-{idx+1}",
                "section":               r.get("policyName") or r.get("section") or family,
                # Addresses
                "sources":               _names(srcs) or ["any"],
                "destinations":          _names(dsts) or ["any"],
                # Services & applications
                "services":              _names(svcs) or ["any"],
                "applications":          _names(apps),
                # Users
                "users":                 _names(users),
                # VPN / install-on (not typically exposed via REST)
                "vpn":                   [],
                "install_on":            [],
                # Zones (mapped to interface columns in ORM)
                "source_interfaces":     _names(src_zones),
                "destination_interfaces": _names(dst_zones),
                # Action
                "action":                action_map.get(action_raw, action_raw),
                "enabled":               enabled,
                "logging_enabled":       r.get("log", r.get("logging", True)) in (True, "enable", "enabled", 1),
                "nat_enabled":           False,
                # Hit statistics
                "hit_count":             r.get("hitCount") or r.get("hitTimes") or r.get("matchTimes") or 0,
                "last_hit":              r.get("lastHitTime") or r.get("lastMatchTime") or r.get("lastHit"),
                "first_hit":             r.get("firstHitTime") or r.get("firstMatchTime") or r.get("firstHit"),
                # Schedule / time-range
                "schedule":              r.get("timeRange") or r.get("schedule") or r.get("time") or "",
                # Comment/description
                "comments":              r.get("description") or r.get("comment") or r.get("remark") or "",
                # Raw data for audit trail
                "raw_data":              r,
            })
        return out
