"""Base parser interface."""
from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, Any


class BaseParser(ABC):
    """Base class for firewall config parsers."""

    @abstractmethod
    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        """
        Parse firewall config content.
        Returns: (rules, objects, warnings)
        """
        raise NotImplementedError

    def parse_file(self, file_path: str) -> Tuple[List[dict], List[dict], List[str]]:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return self.parse(content)

    def finalize_parse_result(
        self,
        rules: Any,
        objects: Any,
        warnings: Any,
        vendor: str,
    ) -> Tuple[List[dict], List[dict], List[str]]:
        """Normalize parser output and add warnings for unsafe object graphs."""
        normalized_warnings = self._as_warning_list(warnings)
        normalized_rules = self._normalize_records(rules, "rule", normalized_warnings)
        normalized_objects = self._normalize_records(objects, "object", normalized_warnings)

        for rule in normalized_rules:
            rule.setdefault("vendor", vendor)
            rule.setdefault("raw_data", {})
            for field in (
                "sources", "destinations", "services", "applications", "users", "vpn",
                "install_on", "source_interfaces", "destination_interfaces",
            ):
                rule[field] = self._as_string_list(rule.get(field))

        for obj in normalized_objects:
            obj.setdefault("vendor", vendor)
            obj.setdefault("raw_data", {})
            obj["members"] = self._as_string_list(obj.get("members"))

        self._warn_on_group_cycles(normalized_objects, normalized_warnings, vendor)
        return normalized_rules, normalized_objects, normalized_warnings

    @staticmethod
    def _as_warning_list(warnings: Any) -> List[str]:
        if warnings is None:
            return []
        if isinstance(warnings, list):
            return [str(w) for w in warnings if w is not None]
        return [str(warnings)]

    @staticmethod
    def _as_string_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            result = []
            for item in value:
                if item is None:
                    continue
                if isinstance(item, dict):
                    name = item.get("name") or item.get("object_name") or item.get("uid")
                    if name:
                        result.append(str(name))
                else:
                    result.append(str(item))
            return result
        if isinstance(value, tuple) or isinstance(value, set):
            return [str(item) for item in value if item is not None]
        if isinstance(value, dict):
            name = value.get("name") or value.get("object_name") or value.get("uid")
            return [str(name)] if name else []
        return [str(value)]

    @staticmethod
    def _normalize_records(records: Any, label: str, warnings: List[str]) -> List[dict]:
        if records is None:
            return []
        if not isinstance(records, list):
            warnings.append(f"Parser returned non-list {label} collection; ignored malformed collection.")
            return []
        normalized: List[dict] = []
        for idx, record in enumerate(records):
            if isinstance(record, dict):
                normalized.append(record)
            else:
                warnings.append(f"Ignored malformed {label} at index {idx}: expected object, got {type(record).__name__}.")
        return normalized

    @staticmethod
    def _is_group_object(obj: dict) -> bool:
        return "group" in (obj.get("object_type") or "").lower().replace("-", "_")

    def _warn_on_group_cycles(self, objects: List[dict], warnings: List[str], vendor: str) -> None:
        names = {o.get("object_name") for o in objects if o.get("object_name")}
        graph = {
            o.get("object_name"): [m for m in o.get("members", []) if m in names]
            for o in objects
            if o.get("object_name") and self._is_group_object(o)
        }
        visited = set()
        visiting = set()

        def visit(name: str, path: List[str]) -> None:
            if name in visiting:
                cycle = path[path.index(name):] + [name] if name in path else path + [name]
                warnings.append(f"{vendor} parser warning: circular group reference detected: {' -> '.join(cycle)}.")
                return
            if name in visited:
                return
            visiting.add(name)
            for child in graph.get(name, []):
                visit(child, path + [child])
            visiting.remove(name)
            visited.add(name)

        for name in list(graph):
            visit(name, [name])


class SafeParser:
    """Factory wrapper that keeps vendor parser failures non-fatal."""

    def __init__(self, parser: BaseParser, vendor: str):
        self.parser = parser
        self.vendor = vendor

    def parse(self, content: str) -> Tuple[List[dict], List[dict], List[str]]:
        try:
            rules, objects, warnings = self.parser.parse(content or "")
        except Exception as exc:
            return [], [], [f"{self.vendor} parser error: {exc.__class__.__name__}: {exc}"]
        return self.parser.finalize_parse_result(rules, objects, warnings, self.vendor)

    def parse_file(self, file_path: str) -> Tuple[List[dict], List[dict], List[str]]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            return [], [], [f"{self.vendor} parser error: unable to read file: {exc}"]
        return self.parse(content)
