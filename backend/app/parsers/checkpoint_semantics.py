"""Check Point semantics shared by file import and live synchronization."""


def reference_name(value):
    if isinstance(value, dict):
        return str(value.get("name") or value.get("uid") or "")
    return str(value or "")


def normalize_action(value):
    name = reference_name(value).strip().lower()
    if name in ("accept", "allow"):
        return "accept"
    if name in ("drop", "deny", "reject", "block"):
        return "deny"
    return name or "unknown"


def negated_fields(rule):
    return [field for field in ("source", "destination", "service")
            if rule.get(f"{field}-negate") is True
            or str(rule.get(f"{field}-negate", "")).lower() == "true"]
