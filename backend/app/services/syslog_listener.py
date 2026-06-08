"""
Syslog Listener Service
========================
Listens for UDP (and optionally TCP) syslog messages from managed firewall
devices.  When a message arrives that indicates a policy change (rule added,
modified, deleted, committed) the listener queues an immediate re-sync of that
device — mirroring Tufin SecureTrack's "real-time monitoring" mode.

Behaviour
---------
* Binds to 0.0.0.0:<port> (default 5140 — unprivileged alternative to 514).
  Port 514 requires root/admin; 5140 works without elevated privileges.
  Forward device syslogs to this port via a syslog relay or direct device config.

* Maintains a per-device cooldown (COOLDOWN_SECONDS) so that a burst of log
  messages from a rapid config change only triggers one sync.

* Falls back gracefully: if no device matches the source IP the message is
  logged at DEBUG level and ignored.

* Runs as a daemon thread started during FastAPI lifespan — does not block
  startup or shutdown.

SAFETY: Read-only trigger.  Receiving a syslog message causes a live-sync
(which is itself read-only API polling).  No firewall configuration is modified.
"""
from __future__ import annotations

import logging
import re
import socketserver
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger("syslog_listener")

# ── Tunables ──────────────────────────────────────────────────────────────────

DEFAULT_PORT     = 5140          # use 514 if running as root / with cap_net_bind_service
COOLDOWN_SECONDS = 60            # min seconds between auto-syncs triggered by syslog
MAX_MSG_BYTES    = 4096

# Keywords in syslog messages that indicate a policy / configuration change.
# Covers FortiGate, CheckPoint, PaloAlto (PAN-OS), Cisco ASA.
_CHANGE_PATTERNS: list[re.Pattern] = [
    # FortiGate: configuration edit events
    re.compile(r"\bconfig\b.*\bedit\b|\badd\b.*\bpolicy\b|\bset\b.*\bpolicy\b", re.I),
    re.compile(r"policy-change|cfg_change|log_id=0100032\d\d", re.I),
    # CheckPoint: policy install / fetch
    re.compile(r"policy.*install|install.*policy|fetchpolicy|smartconsole", re.I),
    re.compile(r"fw_load|fwd_load|cpd_load", re.I),
    # PaloAlto PAN-OS: commit events
    re.compile(r"\bcommit\b.*\bcompleted\b|\bconfiguration.*committed\b", re.I),
    re.compile(r"SYSTEM.*subtype=\"config\".*type=\"commit\"", re.I),
    # Cisco ASA: access-list or rule change
    re.compile(r"access-list.*added|access-list.*removed|access-list.*modified", re.I),
    re.compile(r"ASA-5-\d{6}.*access-list", re.I),
    # Generic keywords
    re.compile(r"\b(rule|policy|acl|access.list)\b.{0,30}\b(added|deleted|modified|changed|committed|installed)\b", re.I),
]


def _is_policy_change(message: str) -> bool:
    return any(p.search(message) for p in _CHANGE_PATTERNS)


# ── Per-device sync cooldown tracker ─────────────────────────────────────────

_last_triggered: Dict[str, datetime] = {}
_cooldown_lock  = threading.Lock()


def _can_trigger(device_id: str) -> bool:
    """Return True if the device has not been triggered within the cooldown window."""
    with _cooldown_lock:
        last = _last_triggered.get(device_id)
        if last and (datetime.utcnow() - last) < timedelta(seconds=COOLDOWN_SECONDS):
            return False
        _last_triggered[device_id] = datetime.utcnow()
        return True


def _trigger_sync(device_id: str, device_name: str, source_ip: str) -> None:
    """Fire a background sync thread for the device — same path as auto-sync."""
    from app.database import SessionLocal
    from app.models.device import FirewallDevice
    from app.connectors.live_sync import sync_device

    logger.info(
        "Syslog-triggered sync for device %s (%s) — source IP %s",
        device_id, device_name, source_ip,
    )
    db = SessionLocal()
    try:
        device = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
        if device:
            device.sync_status = "running"
            db.commit()
            sync_device(device, db)
    except Exception as exc:
        logger.error("Syslog-triggered sync failed for %s: %s", device_id, exc)
    finally:
        db.close()


# ── IP → device lookup ────────────────────────────────────────────────────────

def _find_device_by_ip(host_ip: str):
    """Return (device_id, device_name) for the first device matching host_ip, or None."""
    from app.database import SessionLocal
    from app.models.device import FirewallDevice

    db = SessionLocal()
    try:
        device = db.query(FirewallDevice).filter(FirewallDevice.host == host_ip).first()
        if device:
            return device.id, device.name
        return None
    except Exception:
        return None
    finally:
        db.close()


# ── UDP handler ───────────────────────────────────────────────────────────────

class _SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, _ = self.request
        try:
            message = data[:MAX_MSG_BYTES].decode("utf-8", errors="replace").strip()
        except Exception:
            return

        source_ip = self.client_address[0]
        logger.debug("Syslog from %s: %s", source_ip, message[:120])

        if not _is_policy_change(message):
            return

        result = _find_device_by_ip(source_ip)
        if not result:
            logger.debug("Syslog policy-change event from unknown IP %s — ignored", source_ip)
            return

        device_id, device_name = result
        if not _can_trigger(device_id):
            logger.debug("Syslog sync for %s skipped — within cooldown window", device_name)
            return

        threading.Thread(
            target=_trigger_sync,
            args=(device_id, device_name, source_ip),
            daemon=True,
            name=f"syslog-sync-{device_id[:8]}",
        ).start()


# ── TCP handler ───────────────────────────────────────────────────────────────

class _SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            data = self.rfile.read(MAX_MSG_BYTES)
            message = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        source_ip = self.client_address[0]
        logger.debug("Syslog/TCP from %s: %s", source_ip, message[:120])

        if not _is_policy_change(message):
            return

        result = _find_device_by_ip(source_ip)
        if not result:
            return

        device_id, device_name = result
        if not _can_trigger(device_id):
            return

        threading.Thread(
            target=_trigger_sync,
            args=(device_id, device_name, source_ip),
            daemon=True,
            name=f"syslog-tcp-sync-{device_id[:8]}",
        ).start()


# ── Public start function ─────────────────────────────────────────────────────

def start_syslog_listener(port: int = DEFAULT_PORT) -> Optional[threading.Thread]:
    """
    Start UDP syslog listener in a daemon thread.
    Returns the thread, or None if binding fails (e.g. port already in use).
    """
    try:
        server = socketserver.UDPServer(("0.0.0.0", port), _SyslogUDPHandler)
        server.socket.settimeout(1.0)   # allow clean shutdown
    except OSError as exc:
        logger.warning(
            "Syslog listener could not bind to UDP port %d: %s  "
            "(Try port 514 with elevated privileges, or forward syslogs to port %d.)",
            port, exc, port,
        )
        return None

    def _serve():
        logger.info("Syslog listener started on UDP 0.0.0.0:%d", port)
        try:
            server.serve_forever()
        finally:
            server.server_close()

    t = threading.Thread(target=_serve, daemon=True, name=f"syslog-udp-{port}")
    t.start()
    return t


def get_listener_status(port: int = DEFAULT_PORT) -> dict:
    """Return a status dict for the API."""
    import socket
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test.bind(("0.0.0.0", port))
        test.close()
        # If we could bind, the listener is NOT running
        return {"active": False, "port": port, "reason": "port not bound — listener inactive"}
    except OSError:
        # Port is in use — our listener is running
        return {"active": True, "port": port, "protocol": "UDP", "cooldown_seconds": COOLDOWN_SECONDS}
