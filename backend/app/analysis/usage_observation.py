"""Validate provenance for rule hit-count based analysis."""
from datetime import UTC, datetime


def verified_observation(rule: dict, minimum_days: int, now: datetime) -> dict | None:
    if isinstance(rule, dict):
        observation = rule.get("usage_observation")
        if observation is None:
            observation = (rule.get("raw_data") or {}).get("usage_observation")
    else:
        observation = (getattr(rule, "raw_data", None) or {}).get("usage_observation")
    if not isinstance(observation, dict) or observation.get("complete") is not True \
            or observation.get("counter_reset") is not False or not observation.get("source"):
        return None
    try:
        start = datetime.fromisoformat(str(observation["start"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(observation["end"]).replace("Z", "+00:00"))
        if start.tzinfo is not None:
            start = start.astimezone(UTC).replace(tzinfo=None)
        if end.tzinfo is not None:
            end = end.astimezone(UTC).replace(tzinfo=None)
    except (KeyError, TypeError, ValueError):
        return None
    if (end - start).days < minimum_days or end > now or (now - end).days > 7:
        return None
    return observation
