"""
Huawei USG / VRP SSH Connector
================================
Retrieves firewall configuration and policy data via SSH (TCP/22) using
the Huawei VRP CLI.  All commands are read-only display commands — nothing
modifies the device.

Supported platforms
-------------------
  Huawei USG2000 / USG5000 / USG6000 / USG6000E / USG6000F / USG9000
  Huawei NE / AR / CE series (routing tables, VRRP, BGP)
  eSight / iMaster NCE managed firewalls (SSH into the firewall itself)

Connection flow
---------------
  1. SSH to host:22 (or user-specified port)
  2. Detect prompt — may be VRP user-view or initial banner
  3. Disable paging:  screen-length 0 temporary
  4. Run display commands one by one with a per-command timeout
  5. Concatenate all output → feed to HuaweiUSGParser (the file-upload parser)
  6. Return the same data shape as HuaweiUSGConnector.get_all()

Virtual systems (vsys)
----------------------
  If the device has virtual systems the connector iterates them via:
    switch vsys <name>
  and re-runs the policy display commands in each vsys context.

SAFETY: Read-only.  No configuration commands are issued.
"""
from __future__ import annotations

import io
import logging
import re
import time
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Default SSH port
_SSH_PORT = 22
# Seconds to wait for each command's output to complete
_CMD_TIMEOUT = 60
# Seconds for the overall connection handshake
_CONNECT_TIMEOUT = 30
# Bytes to read in each recv() chunk
_CHUNK = 65536


# ── VRP prompt patterns ───────────────────────────────────────────────────────

_PROMPT_RE = re.compile(
    r"<[A-Za-z0-9][A-Za-z0-9_\-\.]*>\s*$"          # user-view:   <USG6300>
    r"|\[[A-Za-z0-9][A-Za-z0-9_\-\.\-]*[^\n]*\]\s*$"  # system-view: [USG6300] or sub-modes
, re.MULTILINE)

_MORE_RE = re.compile(r"---- More ----", re.IGNORECASE)


# ── Command lists ─────────────────────────────────────────────────────────────

# Commands run in user-view (no system-view needed)
_USERMODE_CMDS: List[str] = [
    "display version",
    "display current-configuration all",
    "display current-configuration",           # fallback if "all" is unsupported
    "display security-policy all",
    "display security-policy rule all",
    "display ip interface brief",
    "display ipv6 interface brief",
    "display zone",
    "display zone all",
    "display ip address-set all",
    "display service-set all",
    "display nat-policy all",
    "display nat-policy",
    # Hit count / statistics — try all known VRP variants:
    #   V500R001C30/C60:  "display security-policy rule all statistics"
    #   V600R007+:        "display security-policy statistics"
    # Both are run; parser deduplicates overlapping data.
    "display security-policy rule all statistics",
    "display security-policy statistics",
    "display traffic policy statistics",    # QoS/network traffic policy stats (completeness)
    "display predefined-service",
    "display application pre-defined",
    "display application user-defined",
    "display application-group all",
    "display ipsec sa",
    "display ipsec policy",
    "display ip routing-table verbose",
    "display ip routing-table",
    "display ipv6 routing-table",
    "display vrrp brief",
    "display vrrp",
    "display ip vpn-instance",
    "display ip vpn-instance verbose",
    "display bgp vpnv4 all routing-table",
    "display bgp vpnv4 all peer",
    "display mpls lsp",
    "display vxlan tunnel",
    "display vxlan vni",
    "display domain-set all",
]

# Commands that require system-view first (some older firmware)
_SYSVIEW_CMDS: List[str] = []  # none currently; kept for future use

# Per-vsys commands (run after "switch vsys <name>")
_VSYS_CMDS: List[str] = [
    "display security-policy all",
    "display security-policy rule all statistics",
    "display security-policy statistics",
    "display ip address-set all",
    "display service-set all",
    "display nat-policy all",
    "display zone",
    "display domain-set all",
]


# ─────────────────────────────────────────────────────────────────────────────

class HuaweiSSHConnector:
    """
    SSH connector for Huawei VRP firewalls.

    Usage:
        conn = HuaweiSSHConnector(host="192.168.1.1", username="admin", password="secret")
        info = conn.connect()     # authenticates, returns {version, model, serial}
        data = conn.get_all()     # runs all display commands, returns parsed data
        conn.disconnect()
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = _SSH_PORT,
        timeout: int = _CONNECT_TIMEOUT,
        cmd_timeout: int = _CMD_TIMEOUT,
        look_for_keys: bool = False,
        allow_agent: bool = False,
        vsys: Optional[str] = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.cmd_timeout = cmd_timeout
        self.look_for_keys = look_for_keys
        self.allow_agent = allow_agent
        self.vsys = vsys  # specific vsys to collect; None = all

        self._client = None          # paramiko.SSHClient
        self._shell = None           # paramiko interactive shell channel
        self._prompt: str = ""       # detected prompt suffix (e.g. "<USG6300>")
        self._collected: List[str] = []  # all raw CLI output accumulated
        self._version_info: Dict[str, str] = {}

    # ── SSH helpers ───────────────────────────────────────────────────────────

    def _get_paramiko(self):
        try:
            import paramiko
            return paramiko
        except ImportError:
            raise RuntimeError(
                "paramiko is required for SSH connectivity: pip install paramiko"
            )

    def _read_until_prompt(self, timeout: Optional[int] = None) -> str:
        """
        Read from the shell channel until the VRP prompt appears or timeout.
        Sends a space to dismiss '---- More ----' paging prompts.
        Falls back to idle-timeout detection when the prompt pattern doesn't
        match (some firmware versions use non-standard prompt characters).
        """
        if timeout is None:
            timeout = self.cmd_timeout
        buf = ""
        deadline = time.monotonic() + timeout
        last_recv = time.monotonic()
        # Idle gap after which we assume the command is done even if prompt
        # wasn't detected (handles unusual prompts)
        _IDLE_GAP = 3.0

        while time.monotonic() < deadline:
            if self._shell.recv_ready():
                chunk = self._shell.recv(_CHUNK).decode("utf-8", errors="replace")
                buf += chunk
                last_recv = time.monotonic()
                # Dismiss '---- More ----' paging
                while _MORE_RE.search(buf):
                    self._shell.send(" ")
                    time.sleep(0.1)
                    # Read the continuation
                    if self._shell.recv_ready():
                        extra = self._shell.recv(_CHUNK).decode("utf-8", errors="replace")
                        buf += extra
                    # Remove the More marker from the buffer
                    buf = _MORE_RE.sub("", buf)
                # Prompt detected → done
                if _PROMPT_RE.search(buf):
                    break
            else:
                # No data — check idle gap
                if (time.monotonic() - last_recv) >= _IDLE_GAP and buf.strip():
                    # Data came in but no new data for _IDLE_GAP seconds
                    # and buffer is non-empty — treat as complete
                    break
                time.sleep(0.1)
        return buf

    def _send_cmd(self, cmd: str, timeout: Optional[int] = None) -> str:
        """Send a command and return its output (stripped of the prompt line)."""
        self._shell.send(cmd + "\n")
        output = self._read_until_prompt(timeout=timeout or self.cmd_timeout)
        return output

    def _detect_prompt(self) -> str:
        """Read the initial prompt from the device after login."""
        output = self._read_until_prompt(timeout=self.timeout)
        # Extract the prompt — last non-empty line
        for line in reversed(output.splitlines()):
            line = line.strip()
            if line and ("<" in line or "[" in line):
                self._prompt = line
                logger.debug("Detected VRP prompt: %r", self._prompt)
                return self._prompt
        self._prompt = output.strip().splitlines()[-1] if output.strip() else ""
        return self._prompt

    def _disable_paging(self):
        """
        Disable screen paging so output is not truncated at 24 lines.
        VRP supports both 'screen-length 0 temporary' (session-only, preferred)
        and 'screen-length 0' (persistent, older firmware).
        Also sets terminal width to 512 to avoid mid-line wraps.
        """
        # Try temporary first (session-only, non-persistent — safest)
        out = self._send_cmd("screen-length 0 temporary", timeout=10)
        if "Error" in out or "Unrecognized" in out or "%" in out:
            # Older firmware: persistent setting (still read-only — affects only display)
            self._send_cmd("screen-length 0", timeout=10)
        # Wide terminal to avoid mid-line wrapping in long output
        self._send_cmd("screen-width 512", timeout=5)

    # ── Connection lifecycle ───────────────────────────────────────────────────

    def connect(self) -> Dict[str, Any]:
        """
        Open SSH connection, authenticate, disable paging, detect device info.
        Returns: {version, model, serial, sysname}
        """
        paramiko = self._get_paramiko()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.info("SSH connect → %s:%d as %s", self.host, self.port, self.username)
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                look_for_keys=self.look_for_keys,
                allow_agent=self.allow_agent,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except Exception as e:
            raise ConnectionError(
                f"SSH connection to {self.host}:{self.port} failed: {e}"
            ) from e

        self._client = client
        self._shell = client.invoke_shell(width=512, height=10000)
        time.sleep(1)

        self._detect_prompt()
        self._disable_paging()

        # Get version info
        ver_out = self._send_cmd("display version", timeout=20)
        self._collected.append(ver_out)
        self._version_info = _parse_version_output(ver_out)

        return {
            "version": self._version_info.get("version", ""),
            "model":   self._version_info.get("model", ""),
            "serial":  self._version_info.get("serial", ""),
            "sysname": self._version_info.get("sysname", self.host),
        }

    def disconnect(self):
        """Close the SSH session."""
        try:
            if self._shell:
                try:
                    self._shell.send("quit\n")
                    time.sleep(0.3)
                except Exception:
                    pass
                self._shell.close()
        except Exception:
            pass
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass
        self._shell = None
        self._client = None

    # ── Data collection ────────────────────────────────────────────────────────

    def _run_cmd_safe(self, cmd: str) -> str:
        """Run a command, return output; log but don't raise on errors."""
        try:
            out = self._send_cmd(cmd)
            logger.debug("CMD [%s] → %d chars", cmd, len(out))
            return out
        except Exception as e:
            logger.warning("Command %r failed: %s", cmd, e)
            return ""

    def _run_display_cmds(self, cmds: List[str]) -> str:
        """Run a list of display commands, return concatenated output."""
        parts = []
        for cmd in cmds:
            out = self._run_cmd_safe(cmd)
            if out.strip():
                parts.append(f"\n# --- {cmd} ---\n{out}")
        return "\n".join(parts)

    def _discover_vsys_names(self) -> List[str]:
        """
        Attempt to enumerate virtual system names from CLI output.
        Returns list of vsys names (empty if not supported or not multi-vsys).
        """
        out = self._run_cmd_safe("display vsys")
        if not out or "Error" in out or "Unrecognized" in out:
            return []
        names = []
        for line in out.splitlines():
            # Typical output: "  public    Running   ..."
            m = re.match(r"^\s+(\S+)\s+(?:Running|Stop|Init)", line)
            if m and m.group(1).lower() not in ("vsys", "name"):
                names.append(m.group(1))
        return names

    def _collect_vpn_vrf(self) -> str:
        """Collect per-VRF routing tables for any VPN instances found."""
        parts = []
        # Discover VPN instance names
        vrf_out = self._run_cmd_safe("display ip vpn-instance")
        parts.append(f"\n# --- display ip vpn-instance ---\n{vrf_out}")

        vrf_names = []
        for line in vrf_out.splitlines():
            # VPN instance name is first column (skip header lines)
            m = re.match(r"^\s+(\S+)\s+\d+\s+", line)
            if m and m.group(1).lower() not in ("vpn-instance", "name", "total"):
                vrf_names.append(m.group(1))

        for vrf in vrf_names[:20]:  # cap at 20 to avoid runaway
            out = self._run_cmd_safe(f"display ip vpn-instance {vrf} interface")
            if out and "Error" not in out:
                parts.append(f"\n# --- display ip vpn-instance {vrf} interface ---\n{out}")
            out = self._run_cmd_safe(
                f"display ip routing-table vpn-instance {vrf} verbose"
            )
            if out and "Error" not in out:
                parts.append(
                    f"\n# --- display ip routing-table vpn-instance {vrf} verbose ---\n{out}"
                )

        return "\n".join(parts)

    def get_all(self) -> Dict[str, Any]:
        """
        Run all read-only display commands and return the parsed policy data.

        Returns the same dict shape as HuaweiUSGConnector.get_all():
          {rules, addresses, address_groups, services, service_groups, zones,
           raw_output, warnings}
        """
        if not self._client:
            self.connect()

        # ── Global display commands ──────────────────────────────────────────
        logger.info("Huawei SSH: collecting global display commands")
        global_output = self._run_display_cmds(_USERMODE_CMDS)
        self._collected.append(global_output)

        # ── Per-VPN instance routing data ────────────────────────────────────
        try:
            vpn_output = self._collect_vpn_vrf()
            self._collected.append(vpn_output)
        except Exception as e:
            logger.debug("VPN instance collection failed: %s", e)

        # ── BGP / MPLS peer detail ────────────────────────────────────────────
        for cmd in [
            "display bgp vpnv4 all routing-table label",
            "display bgp vpnv4 all routing-table peer",
        ]:
            out = self._run_cmd_safe(cmd)
            if out and "Error" not in out:
                self._collected.append(f"\n# --- {cmd} ---\n{out}")

        # ── Virtual systems ───────────────────────────────────────────────────
        if self.vsys:
            vsys_names = [self.vsys]
        else:
            vsys_names = self._discover_vsys_names()

        for vsys_name in vsys_names:
            logger.info("Huawei SSH: switching to vsys %r", vsys_name)
            switch_out = self._run_cmd_safe(f"switch vsys {vsys_name}")
            self._collected.append(f"\n# --- switch vsys {vsys_name} ---\n{switch_out}")
            vsys_out = self._run_display_cmds(_VSYS_CMDS)
            self._collected.append(vsys_out)
            # Return to public vsys
            self._run_cmd_safe("switch vsys public")

        # ── Application names for discovered user-defined apps ────────────────
        app_out = "\n".join(self._collected)
        for app_name in _extract_app_names(app_out):
            out = self._run_cmd_safe(f"display application name {app_name}")
            if out and "Error" not in out:
                self._collected.append(f"\n# --- display application name {app_name} ---\n{out}")

        # ── Parse all collected output ────────────────────────────────────────
        full_output = "\n".join(self._collected)
        return _parse_ssh_output(full_output, self._version_info)

    # ── Context manager support ────────────────────────────────────────────────

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()


# ── Output parsing helpers ────────────────────────────────────────────────────

def _parse_version_output(text: str) -> Dict[str, str]:
    """
    Extract version, model, serial and sysname from 'display version' output.

    Examples:
      Huawei Versatile Routing Platform Software
      VRP (R) software, Version 5.170 (USG6300 V500R001C30SPC200)
      Copyright (C) 2000-2016 Huawei Technologies Co., Ltd.
      USG6300 uptime is 0 week(s), 2 day(s), 4 hour(s), 35 minute(s)
    """
    info: Dict[str, str] = {}

    # Version line: "Version 5.170 (USG6300 V500R001C30SPC200)"
    m = re.search(
        r"Version\s+([\d\.]+)\s*\(([A-Za-z0-9\-_]+)\s+(V[\w]+)\)",
        text, re.IGNORECASE,
    )
    if m:
        info["vrp_version"] = m.group(1)
        info["model"]       = m.group(2)
        info["version"]     = m.group(3)

    # Alternative: "VRP (R) software, Version 8.220 (CE6870EI V200R002C50SPC800)"
    if not info.get("version"):
        m = re.search(r"Version\s+([\w\.]+)", text, re.IGNORECASE)
        if m:
            info["version"] = m.group(1)

    # Sysname from prompt or "sysname" config line
    m = re.search(r"sysname\s+(\S+)", text, re.IGNORECASE)
    if m:
        info["sysname"] = m.group(1)

    # Serial / ESN
    m = re.search(r"(?:ESN|Serial|Board Serial)\s*[:\s]+([A-Z0-9]{8,})", text, re.IGNORECASE)
    if m:
        info["serial"] = m.group(1)

    # Model from "uptime" line if not already found: "USG6300 uptime is ..."
    if not info.get("model"):
        m = re.search(r"^([A-Z0-9\-]+)\s+uptime\s+is", text, re.MULTILINE | re.IGNORECASE)
        if m:
            info["model"] = m.group(1)

    return info


def _extract_app_names(text: str) -> List[str]:
    """
    Extract user-defined application names referenced in security policy rules
    so we can call 'display application name <name>' for each.
    """
    names: List[str] = []
    # Matches "application <name>" inside security policy rule blocks
    for m in re.finditer(r"^\s+application\s+(\S+)", text, re.MULTILINE):
        name = m.group(1)
        if name not in ("pre-defined", "user-defined", "all", "any") and name not in names:
            names.append(name)
    return names[:50]  # cap


def _parse_ssh_output(text: str, version_info: Dict[str, str]) -> Dict[str, Any]:
    """
    Feed the accumulated CLI output through the HuaweiUSGParser and return
    a dict in the same shape as HuaweiUSGConnector.get_all().

    HuaweiUSGParser.parse() returns:
        (rules: List[dict], objects: List[dict], warnings: List[str])

    where objects is a flat list of normalised object dicts, each with an
    'object_type' key ('zone', 'network', 'host', 'service', 'service_group',
    'address_group', 'application_group', 'time_range', 'nat-*', etc.)
    """
    try:
        from app.parsers.huawei_usg import HuaweiUSGParser
        parser = HuaweiUSGParser()

        # parse() returns a 3-tuple: (rules, objects, warnings)
        parse_result = parser.parse(text)

        if isinstance(parse_result, tuple) and len(parse_result) == 3:
            rules, objects_list, warnings = parse_result
        else:
            # Unexpected shape — log and return empty
            logger.error(
                "HuaweiUSGParser.parse() returned unexpected type %s; "
                "expected 3-tuple (rules, objects, warnings)",
                type(parse_result).__name__,
            )
            return {
                "rules": [], "addresses": [], "address_groups": [],
                "services": [], "service_groups": [], "zones": [],
                "raw_output": text[:50000],
                "warnings": ["Parser returned unexpected result shape"],
                "version_info": version_info,
            }

        # objects_list is List[dict] from HuaweiUSGParser._normalise_object().
        # Each dict has 'object_name', 'object_type', 'value', 'members', 'comment'.
        # We split into the buckets that _huawei_translate() expects:
        #   addresses      → {name, type, value, members, comment}
        #   address_groups → {name, members, comment}
        #   services       → {name, protocol, port_start, port_end, members, comment}
        #   service_groups → {name, members, comment}
        #   zones          → {name, priority, interfaces}
        addresses:      List[dict] = []
        address_groups: List[dict] = []
        services:       List[dict] = []
        service_groups: List[dict] = []
        zones:          List[dict] = []

        for obj in (objects_list or []):
            if not isinstance(obj, dict):
                continue
            # Parser uses 'object_type' and 'object_name'
            obj_type = (obj.get("object_type") or obj.get("type") or "host").lower()
            name     = obj.get("object_name")  or obj.get("name") or ""
            members  = obj.get("members", [])
            value    = obj.get("value", "")
            comment  = obj.get("comment", "")

            if obj_type == "zone":
                zones.append({
                    "name":       name,
                    "priority":   obj.get("priority"),
                    "interfaces": members,
                })

            elif obj_type in ("service-group", "service_group"):
                service_groups.append({
                    "name":    name,
                    "members": members,
                    "comment": comment,
                })

            elif obj_type == "service":
                # Parser stores protocol/port in 'value' as "TCP/443"
                proto, _, port_range = value.partition("/")
                port_lo, _, port_hi = port_range.partition("-")
                try:
                    ps = int(port_lo.strip()) if port_lo.strip().isdigit() else 0
                    pe = int(port_hi.strip()) if port_hi.strip().isdigit() else ps
                except ValueError:
                    ps, pe = 0, 65535
                services.append({
                    "name":       name,
                    "protocol":   proto or "TCP",
                    "port_start": ps,
                    "port_end":   pe,
                    "members":    members,
                    "comment":    comment,
                })

            elif obj_type in ("address_group", "address-group", "group"):
                address_groups.append({
                    "name":    name,
                    "members": members,
                    "comment": comment,
                })

            elif obj_type.startswith("nat") or obj_type in ("application_group", "time-range", "time_range"):
                # Skip — not part of address/service buckets
                pass

            else:
                # network / host / range / fqdn / wildcard / geo → address object
                addresses.append({
                    "name":    name,
                    "type":    obj_type,
                    "value":   value,
                    "members": members,
                    "comment": comment,
                })

        logger.info(
            "Huawei SSH parse complete: %d rules, %d addresses, %d addr-groups, "
            "%d services, %d zones, %d warnings",
            len(rules), len(addresses), len(address_groups),
            len(services), len(zones), len(warnings),
        )

        return {
            "rules":          rules,
            "addresses":      addresses,
            "address_groups": address_groups,
            "services":       services,
            "service_groups": service_groups,
            "zones":          zones,
            "raw_output":     text[:50000],   # truncate for storage
            "warnings":       warnings,
            "version_info":   version_info,
        }

    except Exception as e:
        logger.error("Failed to parse Huawei SSH output: %s", e, exc_info=True)
        return {
            "rules": [], "addresses": [], "address_groups": [],
            "services": [], "service_groups": [], "zones": [],
            "raw_output": text[:50000],
            "warnings": [f"Parse error: {e}"],
            "version_info": version_info,
        }
