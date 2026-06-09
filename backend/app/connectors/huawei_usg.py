"""
Huawei USG Firewall Connector
==============================
Supports Huawei USG2000/5000/6000/9000 series via HTTPS REST API.

Authentication
--------------
  POST /api/v1/auth/sessions
  Body: {"userName": "<user>", "password": "<pass>"}
  Returns: {"data": {"token": "<token>", ...}}

  All subsequent requests use:
    Header: X-Auth-Token: <token>

Endpoints used
--------------
  POST /api/v1/auth/sessions             → authenticate, get token
  GET  /api/v1/device/overview           → device info (version, model, serial)
  GET  /api/v1/sec-policy/ipv4           → IPv4 security policy rules
  GET  /api/v1/sec-policy/ipv6           → IPv6 security policy rules
  GET  /api/v1/object/address            → address objects
  GET  /api/v1/object/address-group      → address group objects
  GET  /api/v1/object/service            → service objects
  GET  /api/v1/object/service-group      → service group objects
  GET  /api/v1/object/region             → zone/interface objects
  GET  /api/v1/monitor/statistic         → traffic / hit count statistics
  DELETE /api/v1/auth/sessions/<token>   → logout

Note: Older USG firmwares (V500R001) may use a different base path
(/webapi/v1/ or /rest/v1/). We try /api/v1/ first and fall back.

SAFETY: Read-only — no write or delete calls are made to policy objects.
        Only DELETE on the session token (logout) which is a cleanup op.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 443
_TIMEOUT = 15
_PAGE_SIZE = 1000  # max records per page (Huawei allows up to 1000)


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
        self._base_url: Optional[str] = None

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

    # ── public interface ──────────────────────────────────────────────────────

    def connect(self) -> dict:
        """
        Authenticate and probe the device.
        Returns info dict:
          {version, model, serial, rule_count, object_count, zone_count}
        Raises on failure.
        """
        client = self._get_client()
        scheme = "https" if self.use_ssl else "http"

        # Try API base paths (newer firmware first)
        for api_base in (
            f"{scheme}://{self.host}:{self.port}/api/v1",
            f"{scheme}://{self.host}:{self.port}/webapi/v1",
            f"{scheme}://{self.host}:{self.port}/rest/v1",
        ):
            self._base_url = api_base
            try:
                payload = {"userName": self.username, "password": self.password}
                resp = client.post(
                    f"{api_base}/auth/sessions",
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    content=json.dumps(payload),
                )
                if resp.status_code in (200, 201):
                    body = resp.json()
                    token = (
                        body.get("data", {}).get("token")
                        or body.get("token")
                        or body.get("X-Auth-Token")
                        or resp.headers.get("X-Auth-Token")
                    )
                    if token:
                        self._token = token
                        self._session_id = body.get("data", {}).get("sessionId") or token
                        break
                elif resp.status_code == 401:
                    raise PermissionError(f"Authentication failed (401) — check username/password")
            except (PermissionError, RuntimeError):
                raise
            except Exception:
                continue
        else:
            raise ConnectionError(f"Could not connect to Huawei USG at {self.host}:{self.port} — no supported API base found")

        # Probe device info
        info: Dict[str, Any] = {}
        try:
            r = client.get(self._url("/api/v1/device/overview"), headers=self._headers())
            if r.status_code == 200:
                d = r.json().get("data", r.json())
                info["version"] = d.get("softwareVersion") or d.get("version") or d.get("vrpVersion", "")
                info["model"]   = d.get("deviceName") or d.get("model") or d.get("productModel", "")
                info["serial"]  = d.get("esn") or d.get("serialNumber") or d.get("serial", "")
        except Exception as e:
            logger.debug("Device overview failed: %s", e)

        # Count rules
        try:
            rules = self._get_paged(client, "/api/v1/sec-policy/ipv4")
            info["rule_count"] = len(rules)
        except Exception:
            info["rule_count"] = 0

        # Count address objects
        try:
            addrs = self._get_paged(client, "/api/v1/object/address")
            info["object_count"] = len(addrs)
        except Exception:
            info["object_count"] = 0

        # Count zones
        try:
            zones_resp = client.get(self._url("/api/v1/object/region"), headers=self._headers())
            if zones_resp.status_code == 200:
                zd = zones_resp.json().get("data", [])
                info["zone_count"] = len(zd) if isinstance(zd, list) else 0
            else:
                info["zone_count"] = 0
        except Exception:
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
        result: Dict[str, List] = {
            "rules": [], "addresses": [], "address_groups": [],
            "services": [], "service_groups": [], "zones": [],
        }

        # Rules (IPv4 + IPv6)
        try:
            ipv4 = self._get_paged(client, "/api/v1/sec-policy/ipv4")
            result["rules"].extend(self._normalize_rules(ipv4))
        except Exception as e:
            logger.warning("Failed to fetch IPv4 rules: %s", e)

        try:
            ipv6 = self._get_paged(client, "/api/v1/sec-policy/ipv6")
            result["rules"].extend(self._normalize_rules(ipv6, family="ipv6"))
        except Exception as e:
            logger.debug("IPv6 rules: %s", e)

        # Address objects
        try:
            result["addresses"] = self._get_paged(client, "/api/v1/object/address")
        except Exception as e:
            logger.warning("Address objects: %s", e)

        try:
            result["address_groups"] = self._get_paged(client, "/api/v1/object/address-group")
        except Exception as e:
            logger.warning("Address groups: %s", e)

        # Service objects
        try:
            result["services"] = self._get_paged(client, "/api/v1/object/service")
        except Exception as e:
            logger.warning("Service objects: %s", e)

        try:
            result["service_groups"] = self._get_paged(client, "/api/v1/object/service-group")
        except Exception as e:
            logger.warning("Service groups: %s", e)

        # Zones
        try:
            resp = client.get(self._url("/api/v1/object/region"), headers=self._headers())
            if resp.status_code == 200:
                d = resp.json().get("data", [])
                result["zones"] = d if isinstance(d, list) else []
        except Exception as e:
            logger.warning("Zones: %s", e)

        return result

    def disconnect(self):
        """Logout / revoke session token."""
        if not self._token:
            return
        try:
            client = self._get_client()
            client.delete(
                self._url(f"/api/v1/auth/sessions/{self._session_id or self._token}"),
                headers=self._headers(),
            )
        except Exception as e:
            logger.debug("Logout failed (non-fatal): %s", e)
        finally:
            self._token = None
            self._session_id = None

    # ── normalisation ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_rules(rules: List[dict], family: str = "ipv4") -> List[dict]:
        """Normalise Huawei USG rule dicts to the common schema."""
        out = []
        for idx, r in enumerate(rules):
            # Resolve source/dest — Huawei uses "sourceAddress" / "destinationAddress"
            srcs  = r.get("sourceAddress", r.get("src", r.get("srcAddress", [])))
            dsts  = r.get("destinationAddress", r.get("dst", r.get("dstAddress", [])))
            svcs  = r.get("service", r.get("services", []))

            # Convert name-reference lists (list of dicts with "name" key, or plain strings)
            def _names(lst) -> List[str]:
                if not isinstance(lst, list):
                    return []
                out_names = []
                for item in lst:
                    if isinstance(item, str):
                        out_names.append(item)
                    elif isinstance(item, dict):
                        out_names.append(item.get("name") or item.get("id") or str(item))
                return out_names

            action_raw = r.get("action", "permit").lower()
            action_map = {
                "permit": "accept", "allow": "accept", "accept": "accept",
                "deny": "deny", "drop": "deny", "discard": "deny",
            }

            out.append({
                "rule_id":      r.get("ruleId") or r.get("id") or str(idx),
                "rule_number":  r.get("ruleOrder") or r.get("seqNum") or idx + 1,
                "rule_name":    r.get("ruleName") or r.get("name") or f"Rule-{idx+1}",
                "section":      r.get("policyName") or r.get("zone") or family,
                "sources":      _names(srcs) or ["any"],
                "destinations": _names(dsts) or ["any"],
                "services":     _names(svcs) or ["any"],
                "applications": _names(r.get("application", [])),
                "action":       action_map.get(action_raw, action_raw),
                "enabled":      r.get("enable", r.get("status", "enable")) in (True, "enable", "enabled", 1),
                "logging_enabled": r.get("log", True) in (True, "enable", "enabled", 1),
                "hit_count":    r.get("hitCount") or r.get("hitTimes") or 0,
                "last_hit":     r.get("lastHitTime") or r.get("lastHit"),
                "comments":     r.get("description") or r.get("comment") or "",
            })
        return out
