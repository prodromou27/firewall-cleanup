"""
Cisco ASA Config Parser  —  File-Based Import
=============================================
Parses Cisco ASA / PIX configuration exports, i.e. the output of:

  show running-config
  show running-config access-list
  show access-list            (includes inline hit counts)

Supported constructs
--------------------
  name <ip> <alias>                         (legacy name aliases)
  object network <name> / host|subnet|range / fqdn
  object service <name> / service ...
  object-group network <name> / network-object / group-object
  object-group service <name> [proto] / service-object / port-object
  object-group protocol <name>
  access-list <name> [line N] extended {permit|deny} ...
  access-list <name> remark <text>
  access-group <acl> {in|out} interface <if>

Hit counts are read from "show access-list" inline "(hitcnt=N)" tokens.

Output schema mirrors app.parsers.base / FirewallRule + FirewallObject.
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple, Any, Optional
from app.parsers.base import BaseParser


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except Exception:
        return 32


# Common ASA port-name → number aliases (best-effort; unknowns kept as-is).
_PORT_ALIASES = {
    "www": "80", "http": "80", "https": "443", "ssh": "22", "telnet": "23",
    "ftp": "21", "ftp-data": "20", "smtp": "25", "domain": "53", "dns": "53",
    "ntp": "123", "snmp": "161", "syslog": "514", "ldap": "389", "ldaps": "636",
    "rdp": "3389", "sqlnet": "1521", "imap4": "143", "pop3": "110",
    "tftp": "69", "bgp": "179", "h323": "1720", "sip": "5060",
    "netbios-ssn": "139", "microsoft-ds": "445", "nfs": "2049",
}


def _norm_port(p: str) -> str:
    return _PORT_ALIASES.get(p.lower(), p)


class CiscoASAParser(BaseParser):
    """Tolerant parser for Cisco ASA running-config text exports."""

    VENDOR = "CiscoASA"

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        warnings: List[str] = []
        lines = content.splitlines()

        markers = ("access-list", "object network", "object-group", "access-group",
                   "ASA Version", ": Saved", "names")
        if not any(m in content for m in markers):
            warnings.append(
                "File does not appear to be a Cisco ASA export. Expected output "
                "from 'show running-config' or 'show access-list'."
            )

        name_aliases = self._parse_name_aliases(lines)
        net_objects, svc_objects = self._parse_objects(lines, warnings)
        groups = self._parse_object_groups(lines, warnings)
        acl_groups = self._parse_access_groups(lines)       # acl_name -> interface/direction
        rules = self._parse_access_lists(lines, acl_groups, warnings)

        if not rules:
            warnings.append(
                "No access-list rules found. Ensure the export includes "
                "'access-list' lines (extended ACLs)."
            )

        objects: List[dict] = []
        objects.extend(net_objects)
        objects.extend(svc_objects)
        objects.extend(groups)
        # Surface legacy name aliases as host objects for traceability.
        for ip, alias in name_aliases.items():
            objects.append({
                "object_uid": alias, "object_name": alias, "object_type": "host",
                "value": ip, "members": [], "comment": "name alias",
                "protocol": None, "port_start": None, "port_end": None,
                "raw_data": {"raw": f"name {ip} {alias}"},
            })

        return rules, objects, warnings

    # ── name aliases ──────────────────────────────────────────────────────────
    def _parse_name_aliases(self, lines: List[str]) -> Dict[str, str]:
        aliases: Dict[str, str] = {}
        for ln in lines:
            m = re.match(r'^name\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', ln.strip())
            if m:
                aliases[m.group(1)] = m.group(2)
        return aliases

    # ── object / object-group blocks ──────────────────────────────────────────
    def _block_lines(self, lines: List[str], start: int) -> Tuple[List[str], int]:
        """Collect indented child lines following a top-level definition."""
        body: List[str] = []
        j = start
        while j < len(lines):
            ln = lines[j]
            if ln.strip() == "":
                j += 1
                continue
            if ln.startswith(" ") or ln.startswith("\t"):
                body.append(ln.strip())
                j += 1
            else:
                break
        return body, j

    def _parse_objects(self, lines: List[str], warnings: List[str]):
        net_objects: List[dict] = []
        svc_objects: List[dict] = []
        i = 0
        while i < len(lines):
            ln = lines[i].strip()
            mn = re.match(r'^object network\s+(\S+)', ln)
            ms = re.match(r'^object service\s+(\S+)', ln)
            if mn:
                body, nxt = self._block_lines(lines, i + 1)
                value, otype = "", "host"
                for b in body:
                    h = re.match(r'^host\s+(\S+)', b)
                    s = re.match(r'^subnet\s+(\S+)\s+(\S+)', b)
                    r = re.match(r'^range\s+(\S+)\s+(\S+)', b)
                    f = re.match(r'^fqdn(?:\s+v4)?\s+(\S+)', b)
                    if h:
                        value, otype = h.group(1), "host"
                    elif s:
                        value, otype = f"{s.group(1)}/{_mask_to_prefix(s.group(2))}", "network"
                    elif r:
                        value, otype = f"{r.group(1)}-{r.group(2)}", "range"
                    elif f:
                        value, otype = f.group(1), "fqdn"
                net_objects.append({
                    "object_uid": mn.group(1), "object_name": mn.group(1),
                    "object_type": otype, "value": value, "members": [],
                    "comment": "", "protocol": None, "port_start": None,
                    "port_end": None, "raw_data": {"raw_lines": [ln] + body},
                })
                i = nxt
                continue
            if ms:
                body, nxt = self._block_lines(lines, i + 1)
                proto, ps, pe, value = None, None, None, ""
                for b in body:
                    sm = re.match(r'^service\s+(\S+)(?:\s+destination\s+(eq|range)\s+(\S+)(?:\s+(\S+))?)?', b)
                    if sm:
                        proto = sm.group(1)
                        if sm.group(2) == "eq" and sm.group(3):
                            ps = pe = _norm_port(sm.group(3))
                        elif sm.group(2) == "range" and sm.group(3):
                            ps, pe = _norm_port(sm.group(3)), _norm_port(sm.group(4) or sm.group(3))
                        value = f"{proto}/{ps}" if ps else proto
                try:
                    ps_i = int(ps) if ps and str(ps).isdigit() else None
                    pe_i = int(pe) if pe and str(pe).isdigit() else None
                except ValueError:
                    ps_i = pe_i = None
                svc_objects.append({
                    "object_uid": ms.group(1), "object_name": ms.group(1),
                    "object_type": "service", "value": value, "members": [],
                    "comment": "", "protocol": proto, "port_start": ps_i,
                    "port_end": pe_i, "raw_data": {"raw_lines": [ln] + body},
                })
                i = nxt
                continue
            i += 1
        return net_objects, svc_objects

    def _parse_object_groups(self, lines: List[str], warnings: List[str]) -> List[dict]:
        groups: List[dict] = []
        i = 0
        while i < len(lines):
            ln = lines[i].strip()
            m = re.match(r'^object-group\s+(network|service|protocol|icmp-type)\s+(\S+)(?:\s+(\S+))?', ln)
            if not m:
                i += 1
                continue
            kind, name, proto_hint = m.group(1), m.group(2), m.group(3)
            body, nxt = self._block_lines(lines, i + 1)
            members: List[str] = []
            value_bits: List[str] = []
            for b in body:
                nm = re.match(r'^network-object\s+(.*)$', b)
                gm = re.match(r'^group-object\s+(\S+)', b)
                so = re.match(r'^service-object\s+(.*)$', b)
                po = re.match(r'^port-object\s+(eq|range)\s+(\S+)(?:\s+(\S+))?', b)
                desc = re.match(r'^description\s+(.*)$', b)
                if nm:
                    spec = nm.group(1).strip()
                    h = re.match(r'^host\s+(\S+)', spec)
                    o = re.match(r'^object\s+(\S+)', spec)
                    sn = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', spec)
                    if h:
                        members.append(h.group(1))
                    elif o:
                        members.append(o.group(1))
                    elif sn:
                        members.append(f"{sn.group(1)}/{_mask_to_prefix(sn.group(2))}")
                    else:
                        members.append(spec)
                elif gm:
                    members.append(gm.group(1))
                elif so:
                    members.append(so.group(1).strip())
                    value_bits.append(so.group(1).strip())
                elif po:
                    if po.group(1) == "eq":
                        members.append(_norm_port(po.group(2)))
                    else:
                        members.append(f"{_norm_port(po.group(2))}-{_norm_port(po.group(3) or po.group(2))}")
                elif desc:
                    pass
            otype = {
                "network": "address_group", "service": "service-group",
                "protocol": "protocol-group", "icmp-type": "icmp-group",
            }.get(kind, "group")
            groups.append({
                "object_uid": name, "object_name": name, "object_type": otype,
                "value": (proto_hint or (value_bits[0] if value_bits else "")),
                "members": members, "comment": "",
                "protocol": proto_hint, "port_start": None, "port_end": None,
                "raw_data": {"raw_lines": [ln] + body},
            })
            i = nxt
        return groups

    # ── access-group bindings ──────────────────────────────────────────────────
    def _parse_access_groups(self, lines: List[str]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        for ln in lines:
            m = re.match(r'^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)', ln.strip())
            if m:
                out[m.group(1)] = {"direction": m.group(2), "interface": m.group(3)}
        return out

    # ── access-list rules ──────────────────────────────────────────────────────
    def _consume_address(self, toks: List[str], k: int) -> Tuple[str, int]:
        """Consume an ASA address spec starting at toks[k]; return (value, new_k)."""
        if k >= len(toks):
            return "any", k
        t = toks[k]
        if t in ("any", "any4", "any6"):
            return "any", k + 1
        if t == "host" and k + 1 < len(toks):
            return toks[k + 1], k + 2
        if t in ("object", "object-group") and k + 1 < len(toks):
            return toks[k + 1], k + 2
        if t == "interface" and k + 1 < len(toks):
            return f"interface:{toks[k + 1]}", k + 2
        # A.B.C.D M.M.M.M
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', t) and k + 1 < len(toks) and re.match(r'^\d+\.\d+\.\d+\.\d+$', toks[k + 1]):
            return f"{t}/{_mask_to_prefix(toks[k + 1])}", k + 2
        return t, k + 1

    def _consume_port(self, toks: List[str], k: int) -> Tuple[Optional[str], int]:
        """Consume an optional port operator; return (service_str_or_None, new_k)."""
        if k >= len(toks):
            return None, k
        t = toks[k]
        if t == "eq" and k + 1 < len(toks):
            return _norm_port(toks[k + 1]), k + 2
        if t in ("gt", "lt", "neq") and k + 1 < len(toks):
            return f"{t} {_norm_port(toks[k + 1])}", k + 2
        if t == "range" and k + 2 < len(toks):
            return f"{_norm_port(toks[k + 1])}-{_norm_port(toks[k + 2])}", k + 3
        if t == "object-group" and k + 1 < len(toks):
            return toks[k + 1], k + 2
        return None, k

    def _parse_access_lists(self, lines: List[str], acl_groups: Dict[str, dict],
                            warnings: List[str]) -> List[dict]:
        rules: List[dict] = []
        remarks: Dict[str, str] = {}     # acl_name -> last remark (applies to next ACE)
        counters: Dict[str, int] = {}
        for ln in lines:
            s = ln.strip()
            mr = re.match(r'^access-list\s+(\S+)\s+remark\s+(.*)$', s)
            if mr:
                remarks[mr.group(1)] = mr.group(2)
                continue
            m = re.match(r'^access-list\s+(\S+)\s+(?:line\s+\d+\s+)?extended\s+(permit|deny)\s+(.*)$', s)
            if not m:
                continue
            acl_name, action_raw, rest = m.group(1), m.group(2), m.group(3)

            # Extract inline hit count from "show access-list" output, then strip noise.
            hit_count = None
            hm = re.search(r'\(hitcnt=(\d+)\)', rest)
            if hm:
                hit_count = int(hm.group(1))
            log_enabled = bool(re.search(r'(?<!\S)log\b', rest))
            inactive = bool(re.search(r'(?<!\S)inactive\b', rest))
            tr = re.search(r'time-range\s+(\S+)', rest)
            time_range = tr.group(1) if tr else ""
            # Drop trailing metadata before tokenizing addresses.
            rest_clean = re.sub(r'\(hitcnt=\d+\).*$', '', rest)
            rest_clean = re.sub(r'\b(log(\s+\w+)?|inactive|time-range\s+\S+|0x[0-9a-fA-F]+)\b', ' ', rest_clean)
            toks = rest_clean.split()
            if not toks:
                continue

            k = 0
            svc_from_group = None
            if toks[0] == "object-group":
                svc_from_group = toks[1] if len(toks) > 1 else None
                proto = svc_from_group or "ip"
                k = 2
            else:
                proto = toks[0]
                k = 1

            src, k = self._consume_address(toks, k)
            src_port = None
            if proto in ("tcp", "udp"):
                src_port, k = self._consume_port(toks, k)
            dst, k = self._consume_address(toks, k)
            dst_port = None
            if proto in ("tcp", "udp"):
                dst_port, k = self._consume_port(toks, k)

            if svc_from_group:
                services = [svc_from_group]
            elif dst_port:
                services = [f"{proto}/{dst_port}"]
            elif proto == "ip":
                services = ["any"]
            else:
                services = [proto]

            counters[acl_name] = counters.get(acl_name, 0) + 1
            idx = counters[acl_name]
            binding = acl_groups.get(acl_name, {})
            rule_uid = f"{acl_name}#{idx}"
            rules.append({
                "rule_id": rule_uid,
                "rule_uid": rule_uid,
                "rule_number": len(rules) + 1,
                "rule_name": f"{acl_name} line {idx}",
                "section": acl_name,
                "sources": [src],
                "destinations": [dst],
                "services": services,
                "applications": [],
                "users": [],
                "vpn": [],
                "install_on": [],
                "source_interfaces": ([binding["interface"]] if binding.get("direction") == "in" else []),
                "destination_interfaces": ([binding["interface"]] if binding.get("direction") == "out" else []),
                "action": "accept" if action_raw == "permit" else "deny",
                "enabled": not inactive,
                "logging_enabled": log_enabled,
                "nat_enabled": False,
                "hit_count": hit_count,
                "last_hit": None,
                "first_hit": None,
                "schedule": time_range,
                "comments": remarks.pop(acl_name, ""),
                "raw_data": {"acl": acl_name, "src_port": src_port, "raw": s},
            })
        return rules
