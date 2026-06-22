"""
Check Point Management API connector — R80.10 / R80.20 / R80.40 / R81 / R81.10 / R81.20 / R82.

Architecture (mirrors how Tufin SecureTrack works)
===================================================
This connector targets the Check Point MANAGEMENT SERVER — not individual gateways.
The management server is the single source of truth for:
  - Policy packages and access layers
  - Network and service objects
  - NAT rules
  - VPN communities
  - Gateway/cluster definitions and topology
  - Policy revision history

Supported management platforms:
  SmartCenter        — single-domain, all-in-one management
  MDS (Multi-Domain) — multiple CMA domains; connect at MDS level or per-CMA
  Smart-1 Cloud      — SaaS management (same API, port 443)

Authentication
--------------
  POST /web_api/login
    {"user": "...", "password": "...", "domain": "..."(optional for MDS)}
    → {"sid": "<session-token>", "uid": "...", "api-server-version": "..."}

  All subsequent calls: header  X-chkp-sid: <sid>

  Required permissions (read-only profile is sufficient):
    SmartCenter   → SmartCenter Manager / Read Only All
    MDS           → Multi-Domain Super User (or per-domain CMA admin)
    API access must be enabled on the management server

  Best practice: create a dedicated read-only API user (e.g. "monitoring-readonly")
  with "Read Only All" permission profile and trusted host restricted to this server.

Commands used (POST /web_api/<command>)
---------------------------------------
  login / logout
  show-api-versions               → server version info
  show-domains                    → MDS domain list (domains/CMAs)
  show-packages                   → policy packages with access-layers
  show-access-rulebase            → rules (paginated, with inline hit counts)
  show-nat-rulebase               → NAT rules
  show-hosts                      → host objects
  show-networks                   → network objects
  show-address-ranges             → IP range objects
  show-wildcards                  → wildcard address objects
  show-groups                     → address group objects
  show-services-tcp               → TCP service objects
  show-services-udp               → UDP service objects
  show-services-icmp              → ICMP service objects
  show-services-other             → protocol-number service objects
  show-service-groups             → service group objects
  show-times                      → time objects
  show-time-groups                → time group objects
  show-application-site-categories → application category objects (R80.10+)
  show-application-site-groups    → application group objects
  show-vpn-communities-star       → star VPN community definitions
  show-vpn-communities-meshed     → meshed VPN community definitions
  show-gateways-and-servers       → gateway + cluster objects with topology
  show-session                    → current session / last-install info

Pagination: offset + limit, max 500 per call.

Hit counts
----------
Requested inline per rule:  "show-hits": true
"hits-settings": {"from-date": "YYYY-MM-DD", "to-date": "YYYY-MM-DD", "target": "<gw>"}
Per rule: rule["hits"]["value"], rule["hits"]["first-date"], rule["hits"]["last-date"]

Layered policies (R80+)
-----------------------
A package has one or more "access-layers". Each is fetched with show-access-rulebase.
Inline layers (sub-policies) appear as access-rule rows with action type "inline-layer".
We fetch those sub-layers recursively and merge into the flat rule list.

Ref:
  https://sc1.checkpoint.com/documents/latest/APIs/
  https://github.com/CheckPointSW/cp_mgmt_api_python_sdk
"""

import logging
import urllib3
from datetime import datetime, timedelta
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

PAGE_SIZE     = 500
HITS_DAYS_BACK = 365   # 1 year of hit count history


class CheckPointConnector:
    """
    Read-only Check Point Management API client.

    Designed to connect to the MANAGEMENT SERVER (SmartCenter / MDS / Smart-1 Cloud),
    mirroring the architecture used by Tufin SecureTrack.

    SAFETY: All operations are read-only.  This connector never installs a policy,
    modifies an object, or pushes any configuration change.
    """

    def __init__(
        self,
        host: str,
        *,
        username: str = "",
        password: str = "",
        api_key: Optional[str] = None,         # Smart-1 Cloud / API-key auth (R81.10+)
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        domain: Optional[str] = None,          # CMA name / domain for MDS, None for SmartCenter
        policy_package: Optional[str] = None,  # pre-selected package; discovered if None
        management_type: str = "SmartCenter",  # "SmartCenter" | "MDS" | "Smart-1Cloud"
        timeout: int = 60,
    ):
        scheme = "https" if use_ssl else "http"

        # Smart-1 Cloud: base URL includes the domain UID in the path
        # Pattern: https://<cloudinfra-host>/<domain-uid>/web_api
        # If host already contains a path component (Smart-1 Cloud tenant URL), use it directly
        if management_type == "Smart-1Cloud" and domain and "/" not in host:
            self.base_url = f"{scheme}://{host}/{domain}/web_api"
        else:
            self.base_url = f"{scheme}://{host}:{port}/web_api"

        self.username = username
        self.password = password
        self.api_key  = api_key              # Takes priority over username/password
        self.domain = domain
        self.policy_package = policy_package
        self.management_type = management_type
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self._sid: Optional[str] = None
        self._api_version: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "SSL certificate verification DISABLED for Check Point %s — "
                "set verify_ssl=True or provide a trusted CA bundle in production.",
                host,
            )
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

    # ── Authentication ──────────────────────────────────────────────────────

    def connect(self) -> dict:
        """
        Authenticate to the management server and return server info.

        Smart-1 Cloud / API-key auth (R81.10+):
          POST /web_api/login  {"api-key": "<key>"}
          This is preferred over username/password for Smart-1 Cloud.

        MDS: session scoped to specified domain/CMA.
        SmartCenter: domain is ignored.
        """
        if self.api_key:
            # API-key authentication (Smart-1 Cloud and on-prem R81.10+)
            payload: dict = {
                "api-key":   self.api_key,
                "read-only": True,
            }
            if self.domain and self.management_type != "Smart-1Cloud":
                # For Smart-1 Cloud the domain is part of the URL; for MDS include in payload
                payload["domain"] = self.domain
        else:
            # Username/password authentication (all versions)
            payload = {
                "user":      self.username,
                "password":  self.password,
                "read-only": True,   # request read-only session (supported R81+, harmless on older)
            }
            if self.domain:
                payload["domain"] = self.domain

        resp = self._post_raw("login", payload)
        self._sid         = resp["sid"]
        self._api_version = resp.get("api-server-version", "unknown")
        self._session.headers["X-chkp-sid"] = self._sid

        logger.info(
            "CP management connected: %s  type=%s  domain=%s  api=%s  auth=%s",
            self.base_url, self.management_type, self.domain or "(root)", self._api_version,
            "api-key" if self.api_key else "password",
        )
        return {
            "api_server_version": self._api_version,
            "uid":                resp.get("uid"),
            "session_uid":        resp.get("session-uid"),
            "management_type":    self.management_type,
            "domain":             self.domain,
        }

    def disconnect(self):
        """Terminate the API session."""
        if self._sid:
            try:
                self._post_raw("logout", {})
            except Exception as e:
                logger.debug("CP logout error (ignored): %s", e)
            self._sid = None

    # ── Low-level HTTP ──────────────────────────────────────────────────────

    def _post_raw(self, command: str, payload: dict) -> dict:
        url = f"{self.base_url}/{command}"
        resp = self._session.post(
            url, json=payload,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        resp.raise_for_status()
        data = resp.json()
        # Check Point returns HTTP 200 even for errors
        code = data.get("code")
        if code and code != "ok" and "sid" not in data:
            raise RuntimeError(
                f"CP API error [{command}]: {data.get('message', '')} (code={code})"
            )
        return data

    def _post_paged(self, command: str, base_payload: dict, list_key: str = None,
                    max_pages: int = 100) -> list:
        """
        Paginate through all results.
        Flattens access-section wrappers and tags rules with section name.
        max_pages guards against unexpectedly huge result sets (e.g. app-site-categories).
        """
        results: list = []
        offset = 0
        page = 0
        while True:
            payload = {**base_payload, "offset": offset, "limit": PAGE_SIZE}
            data = self._post_raw(command, payload)
            page += 1

            # Auto-detect the list key
            batch: list = []
            keys_to_try = [list_key] if list_key else [
                "rulebase", "objects", "packages", "gateways",
                "times", "time-groups", "applications", "application-site-categories",
                "vpn-communities",
            ]
            for k in keys_to_try:
                if k and k in data:
                    batch = data[k]
                    break

            # Flatten access-section wrappers
            for item in batch:
                if isinstance(item, dict) and item.get("type") == "access-section":
                    section_name = item.get("name", "")
                    for rule in item.get("rulebase", []):
                        if isinstance(rule, dict):
                            rule.setdefault("_section", section_name)
                        results.append(rule)
                else:
                    results.append(item)

            total = data.get("total", offset + PAGE_SIZE)
            offset += PAGE_SIZE
            if offset >= total or page >= max_pages:
                if page >= max_pages:
                    logger.warning(
                        "CP paged fetch '%s' hit max_pages=%d limit at offset=%d (total=%d) — truncating",
                        command, max_pages, offset, total,
                    )
                break
        return results

    # ── Server / session info ────────────────────────────────────────────────

    def get_api_version(self) -> dict:
        """Return supported API versions dict."""
        try:
            return self._post_raw("show-api-versions", {})
        except Exception:
            return {"current-version": self._api_version or "unknown"}

    def get_session_info(self) -> dict:
        """Return current session metadata (login time, last-login-from, etc.)."""
        try:
            return self._post_raw("show-session", {"uid": "current"})
        except Exception:
            return {}

    # ── MDS domain discovery ─────────────────────────────────────────────────

    def get_domains(self) -> list[dict]:
        """
        List all domains/CMAs on an MDS.
        Returns empty list if this is a SmartCenter (no domains).
        Each domain: {"name": "...", "uid": "...", "type": "domain", "servers": [...]}
        """
        try:
            data = self._post_raw("show-domains", {"details-level": "standard", "limit": 200})
            return data.get("objects", [])
        except Exception as e:
            logger.debug("show-domains returned error (expected on SmartCenter): %s", e)
            return []

    # ── Policy packages & layers ─────────────────────────────────────────────

    def get_packages(self) -> list[dict]:
        """
        List all policy packages with full detail to get access-layers list.
        """
        try:
            data = self._post_raw(
                "show-packages",
                {"details-level": "full", "limit": 200},
            )
            return data.get("packages", [])
        except Exception as e:
            logger.error("Could not list packages: %s", e)
            return []

    def get_access_layers(self) -> list[dict]:
        """
        List all access layers on the management server.
        Fallback used when show-packages doesn't populate access-layers.
        """
        try:
            data = self._post_raw(
                "show-access-layers",
                {"details-level": "standard", "limit": 200},
            )
            return data.get("access-layers", [])
        except Exception as e:
            logger.debug("show-access-layers not available: %s", e)
            return []

    def get_access_layers_for_package(self, package_name: str) -> list[str]:
        """
        Return ordered access-layer names for a given policy package.

        Strategy:
          1. Try show-packages (details-level=full) → access-layers field
          2. Fall back to show-access-layers and filter by package reference
          3. Final fallback: [package_name] for pre-R80 compatibility
        """
        packages = self.get_packages()
        for pkg in packages:
            if pkg.get("name") == package_name:
                raw_layers = pkg.get("access-layers", [])
                if raw_layers:
                    names = [
                        (layer["name"] if isinstance(layer, dict) else layer)
                        for layer in raw_layers
                        if layer  # skip empty entries
                    ]
                    if names:
                        logger.info("CP: layers for '%s' from show-packages: %s", package_name, names)
                        return names

        # Fallback: discover layers from show-access-layers
        logger.info("CP: no layers in show-packages for '%s', trying show-access-layers", package_name)
        all_layers = self.get_access_layers()
        if all_layers:
            # Match layers whose domain/package reference matches, or pick all non-inline layers
            matched = [
                l["name"] for l in all_layers
                if isinstance(l, dict) and l.get("name")
                and not l.get("implicit", False)
                and l.get("type", "") != "access-layer-inline"
            ]
            if matched:
                logger.info("CP: layers from show-access-layers (filtered): %s", matched)
                return matched

        logger.warning(
            "CP: could not discover access layers for '%s' — falling back to package name as layer",
            package_name,
        )
        return [package_name]

    # ── Gateways ─────────────────────────────────────────────────────────────

    def get_gateways(self) -> list[dict]:
        """
        List all gateways, clusters, and servers from the management DB.
        Returns full topology info — interfaces, cluster members, version, etc.
        """
        try:
            data = self._post_raw(
                "show-gateways-and-servers",
                # "full" returns per-gateway topology: interfaces (with IPs/masks),
                # hardware, version, and cluster membership — needed to populate the
                # device inventory (Network Interfaces panel) and OS version for CVEs.
                {"details-level": "full", "limit": 200},
            )
            return data.get("objects", [])
        except Exception as e:
            logger.warning("Could not list gateways: %s", e)
            return []

    def pick_gateway_target(self, gateways: list[dict]) -> Optional[str]:
        """Select the best gateway name to use as hit-count target."""
        priority_types = [
            "CpmiGatewayCluster", "CpmiVsCluster",
            "simple-cluster", "simple-gateway", "CpmiHostCkp",
        ]
        for ptype in priority_types:
            for gw in gateways:
                if gw.get("type", "").lower() == ptype.lower():
                    return gw.get("name")
        return gateways[0].get("name") if gateways else None

    # ── Rulebase fetching ────────────────────────────────────────────────────

    def _get_rulebase_page(self, layer_name: str, offset: int, payload_extra: dict) -> dict:
        """Fetch a single page of the rulebase and return the raw response."""
        payload = {
            "name":                  layer_name,
            "details-level":         "full",
            "use-object-dictionary": True,
            "offset":                offset,
            "limit":                 PAGE_SIZE,
            **payload_extra,
        }
        return self._post_raw("show-access-rulebase", payload)

    def get_access_rulebase(
        self,
        layer_name: str,
        gateway_target: Optional[str] = None,
        include_hits: bool = True,
        fetch_inline_layers: bool = True,
    ) -> tuple[list[dict], list[dict]]:
        """
        Fetch all rules in a named access-layer with optional hit counts.

        Returns: (rules_list, inline_objects_list)
          rules_list        — flat list of rule dicts, sections expanded, layer tagged
          inline_objects_list — objects embedded in the rulebase objects-dictionary
        """
        today     = datetime.utcnow().date().isoformat()
        from_date = (datetime.utcnow() - timedelta(days=HITS_DAYS_BACK)).date().isoformat()

        payload_extra: dict = {}
        if include_hits:
            payload_extra["show-hits"] = True
            hits_settings: dict = {"from-date": from_date, "to-date": today}
            if gateway_target:
                hits_settings["target"] = gateway_target
            payload_extra["hits-settings"] = hits_settings

        # Collect inline object dictionary from the first page
        inline_objects: list[dict] = []
        all_rules: list[dict] = []
        inline_layer_names: set[str] = set()

        offset = 0
        while True:
            data = self._get_rulebase_page(layer_name, offset, payload_extra)

            # Collect inline object dictionary (present on every page — just use first)
            if not inline_objects:
                inline_objects = data.get("objects-dictionary", [])

            # Flatten batch
            batch = data.get("rulebase", [])
            for item in batch:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "access-section":
                    section_name = item.get("name", "")
                    for rule in item.get("rulebase", []):
                        if isinstance(rule, dict):
                            rule.setdefault("_section", section_name)
                            rule.setdefault("_layer",   layer_name)
                        all_rules.append(rule)
                else:
                    item.setdefault("_layer",   layer_name)
                    item.setdefault("_section", "")
                    # Detect inline-layer references (sub-policies)
                    action_name = ""
                    act = item.get("action", {})
                    if isinstance(act, dict):
                        action_name = act.get("name", "").lower()
                    if action_name == "inline-layer" and fetch_inline_layers:
                        # The inline layer name is in action.inline-layer
                        il_ref = item.get("inline-layer", item.get("action", {}).get("inline-layer"))
                        il_name = il_ref.get("name") if isinstance(il_ref, dict) else il_ref
                        if il_name and il_name not in inline_layer_names:
                            inline_layer_names.add(il_name)
                    all_rules.append(item)

            total = data.get("total", offset + PAGE_SIZE)
            offset += PAGE_SIZE
            if offset >= total:
                break

        # Recursively fetch inline layers
        if fetch_inline_layers and inline_layer_names:
            for il_name in inline_layer_names:
                logger.info("Fetching inline layer: %s", il_name)
                try:
                    il_rules, il_objects = self.get_access_rulebase(
                        il_name,
                        gateway_target=gateway_target,
                        include_hits=include_hits,
                        fetch_inline_layers=False,  # don't recurse infinitely
                    )
                    all_rules.extend(il_rules)
                    inline_objects.extend(il_objects)
                except Exception as e:
                    logger.warning("Could not fetch inline layer '%s': %s", il_name, e)

        logger.info("Layer '%s': %d rules, %d inline objects", layer_name, len(all_rules), len(inline_objects))
        return all_rules, inline_objects

    def get_nat_rulebase(self, package_name: str) -> list[dict]:
        """
        Fetch the NAT rulebase for a policy package.
        NAT rules are critical for understanding how traffic is translated
        and for identifying permissive inbound access.
        """
        try:
            return self._post_paged(
                "show-nat-rulebase",
                {"package": package_name, "details-level": "full"},
                list_key="rulebase",
            )
        except Exception as e:
            logger.warning("Could not fetch NAT rulebase for '%s': %s", package_name, e)
            return []

    # ── Network object fetchers ──────────────────────────────────────────────

    def _fetch_typed(self, command: str, extra: dict = None) -> list[dict]:
        """Generic paginated fetch for any object-list command."""
        payload = {"details-level": "full", **(extra or {})}
        try:
            return self._post_paged(command, payload, list_key="objects")
        except Exception as e:
            logger.debug("'%s' fetch failed (non-fatal): %s", command, e)
            return []

    def get_network_objects(self) -> list[dict]:
        """
        Fetch all network and service objects using dedicated per-type commands.
        This approach is more reliable than show-objects on large management DBs
        (show-objects can time out; per-type calls are bounded).
        """
        objects: list[dict] = []
        # Network address objects
        objects += self._fetch_typed("show-hosts")
        objects += self._fetch_typed("show-networks")
        objects += self._fetch_typed("show-address-ranges")
        objects += self._fetch_typed("show-wildcards")
        objects += self._fetch_typed("show-groups")
        # Service objects
        objects += self._fetch_typed("show-services-tcp")
        objects += self._fetch_typed("show-services-udp")
        objects += self._fetch_typed("show-services-icmp")
        objects += self._fetch_typed("show-services-other")
        objects += self._fetch_typed("show-service-groups")
        return objects

    # ── Time objects ─────────────────────────────────────────────────────────

    def get_time_objects(self) -> list[dict]:
        """
        Fetch time and time-group objects.
        Rules with non-'Any' time objects are time-restricted; this affects
        zero-hit analysis (a rule may hit 0 because it's time-restricted).
        """
        times: list[dict] = []
        times += self._fetch_typed("show-times")
        times += self._fetch_typed("show-time-groups")
        return times

    # ── Application / URL objects ────────────────────────────────────────────

    def get_application_objects(self) -> list[dict]:
        """
        Fetch application-site-groups only (R80.10+).
        NOTE: show-application-site-categories is intentionally skipped —
        it returns thousands of built-in CP app signatures that are not needed
        for access-policy analysis and would make sync take 30+ minutes.
        """
        apps: list[dict] = []
        # Skip show-application-site-categories (too many built-in objects)
        apps += self._fetch_typed("show-application-site-groups")
        return apps

    # ── VPN communities ──────────────────────────────────────────────────────

    def get_vpn_communities(self) -> list[dict]:
        """
        Fetch star and meshed VPN community definitions.
        VPN communities define encryption domains and affect traffic routing;
        rules in the access policy reference community objects as services.
        """
        communities: list[dict] = []
        communities += self._fetch_typed("show-vpn-communities-star",   {"details-level": "full"})
        communities += self._fetch_typed("show-vpn-communities-meshed", {"details-level": "full"})
        return communities

    # ── Policy change detection ──────────────────────────────────────────────

    def get_last_policy_modified(self, package_name: str) -> Optional[str]:
        """
        Return an ISO timestamp of the last modification to a policy package.
        Used to detect whether a sync is needed without pulling all rules.

        Looks at the package's 'last-modify-time' field from show-packages.
        Returns None if not determinable.
        """
        try:
            packages = self.get_packages()
            for pkg in packages:
                if pkg.get("name") == package_name:
                    meta = pkg.get("last-modify-time", {})
                    if isinstance(meta, dict):
                        return meta.get("iso-8601") or meta.get("posix")
                    if isinstance(meta, str):
                        return meta
        except Exception as e:
            logger.debug("Could not check last-modify-time: %s", e)
        return None

    # ── Main fetch ───────────────────────────────────────────────────────────

    def get_all(self, gateway_target: Optional[str] = None) -> dict:
        """
        Fetch everything needed for full policy analysis — mirrors what
        Tufin SecureTrack pulls from the Check Point Management Server.

        Data retrieved:
          - Policy packages + access layers
          - Access control rules (all layers, with hit counts)
          - NAT rules
          - Network objects (hosts, networks, ranges, wildcards, groups)
          - Service objects (TCP/UDP/ICMP/other, service groups)
          - Time objects
          - Application / URL objects
          - VPN community definitions
          - Gateway and cluster objects with topology
          - MDS domains (if MDS)

        Returns dict with keys: rules, nat_rules, objects, inline_objects,
          packages, gateways, vpn_communities, time_objects, application_objects,
          domains, policy_package, gateway_target, layers
        """
        # ── Packages ──────────────────────────────────────────────────────
        packages  = self.get_packages()
        pkg_name  = self.policy_package or (packages[0]["name"] if packages else "Network")
        logger.info("CP: using policy package '%s'", pkg_name)

        # ── Gateways ──────────────────────────────────────────────────────
        gateways = self.get_gateways()
        if not gateway_target:
            gateway_target = self.pick_gateway_target(gateways)
        logger.info(
            "CP: %d gateways found, hit-count target='%s'",
            len(gateways), gateway_target or "none",
        )

        # ── Access layers ──────────────────────────────────────────────────
        layers = self.get_access_layers_for_package(pkg_name)
        logger.info("CP: access layers for '%s': %s", pkg_name, layers)

        # ── Rules (all layers) — fetch WITHOUT hits first for speed ───────────
        # Requesting show-hits requires the management server to contact gateways;
        # if a gateway is unreachable this hangs indefinitely. We fetch rules fast
        # first, then try to enrich with hit counts as a non-fatal second pass.
        all_rules:          list[dict] = []
        all_inline_objects: list[dict] = []
        for layer in layers:
            try:
                logger.info("CP: fetching rulebase for layer '%s'", layer)
                rules, inline_objs = self.get_access_rulebase(
                    layer,
                    gateway_target=gateway_target,
                    include_hits=False,   # no hits on first pass — avoids gateway hangs
                    fetch_inline_layers=True,
                )
                logger.info("CP: layer '%s' → %d rules", layer, len(rules))
                all_rules.extend(rules)
                all_inline_objects.extend(inline_objs)
            except Exception as e:
                logger.error("CP: Failed to fetch layer '%s': %s", layer, e)

        # ── Hit count enrichment (second pass, non-fatal) ──────────────────
        # Try to get hit counts per rule. This may fail/be slow if gateways are
        # unreachable — we catch all errors and continue with zero hit counts.
        if all_rules and gateway_target:
            try:
                logger.info("CP: attempting hit count enrichment via gateway '%s'", gateway_target)
                hit_rules_map: dict[str, dict] = {}
                for layer in layers:
                    try:
                        hit_rules, _ = self.get_access_rulebase(
                            layer,
                            gateway_target=gateway_target,
                            include_hits=True,
                            fetch_inline_layers=False,
                        )
                        for r in hit_rules:
                            uid = r.get("uid", r.get("rule-number", ""))
                            if uid:
                                hit_rules_map[str(uid)] = r.get("hits", {})
                    except Exception as layer_err:
                        logger.warning("Hit enrichment failed for layer '%s': %s", layer, layer_err)
                        break  # if one layer fails, skip hit enrichment entirely

                # Apply hit counts to already-fetched rules
                enriched = 0
                for r in all_rules:
                    uid = r.get("uid", r.get("rule-number", ""))
                    if str(uid) in hit_rules_map:
                        r["hits"] = hit_rules_map[str(uid)]
                        enriched += 1
                logger.info("CP: hit counts enriched for %d/%d rules", enriched, len(all_rules))
            except Exception as e:
                logger.warning("CP: hit count enrichment skipped (non-fatal): %s", e)

        # ── NAT rules ─────────────────────────────────────────────────────
        nat_rules: list[dict] = self.get_nat_rulebase(pkg_name)
        logger.info("CP: %d NAT rules", len(nat_rules))

        # ── Object database ────────────────────────────────────────────────
        objects = self.get_network_objects()
        logger.info("CP: %d network/service objects", len(objects))

        # ── Time objects ───────────────────────────────────────────────────
        time_objects = self.get_time_objects()
        logger.info("CP: %d time objects", len(time_objects))

        # ── Application objects ────────────────────────────────────────────
        application_objects = self.get_application_objects()
        logger.info("CP: %d application objects", len(application_objects))

        # ── VPN communities ────────────────────────────────────────────────
        vpn_communities = self.get_vpn_communities()
        logger.info("CP: %d VPN communities", len(vpn_communities))

        # ── MDS domains ───────────────────────────────────────────────────
        domains: list[dict] = []
        if self.management_type == "MDS":
            domains = self.get_domains()
            logger.info("CP MDS: %d domains", len(domains))

        return {
            "rules":               all_rules,
            "nat_rules":           nat_rules,
            "objects":             objects,
            "inline_objects":      all_inline_objects,
            "packages":            packages,
            "gateways":            gateways,
            "vpn_communities":     vpn_communities,
            "time_objects":        time_objects,
            "application_objects": application_objects,
            "domains":             domains,
            "policy_package":      pkg_name,
            "gateway_target":      gateway_target,
            "layers":              layers,
        }
