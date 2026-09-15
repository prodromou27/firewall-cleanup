"""Exact FortiGate destination[:source] port terms, without widening gaps."""
import re


def port_bounds(text: str) -> tuple[int, int]:
    if not re.fullmatch(r"\d+(?:-\d+)?", text):
        raise ValueError("Invalid port range")
    parts = text.split("-")
    start, end = int(parts[0]), int(parts[-1])
    if not 0 <= start <= end <= 65535:
        raise ValueError("Invalid port bounds")
    return start, end


def fortigate_service_terms(raw: dict, name: str) -> list[dict] | None:
    """None means no raw port fields; malformed terms yield an unknown marker."""
    if not any(raw.get(f"{proto}-portrange") for proto in ("tcp", "udp", "sctp")):
        return None
    terms = []
    try:
        if raw.get("sctp-portrange"):
            raise ValueError("SCTP is not modeled")
        for proto in ("tcp", "udp"):
            for token in str(raw.get(f"{proto}-portrange") or "").split():
                parts = token.split(":")
                if len(parts) > 2:
                    raise ValueError("Invalid source port syntax")
                start, end = port_bounds(parts[0])
                source_start, source_end = port_bounds(parts[1]) if len(parts) == 2 else (0, 65535)
                terms.append({"protocol": proto, "port_start": start, "port_end": end,
                              "source_port_start": source_start, "source_port_end": source_end,
                              "name": name})
    except ValueError:
        return [{"protocol": "unknown", "port_start": None, "port_end": None,
                 "unknown": True, "name": name, "reason": "unsupported_service_ports"}]
    return terms
