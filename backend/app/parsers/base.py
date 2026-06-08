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
