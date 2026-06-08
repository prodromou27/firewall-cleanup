from app.parsers.fortigate import FortiGateParser
from app.parsers.checkpoint import CheckPointParser


def get_parser(vendor: str):
    vendor = vendor.lower().replace(" ", "").replace("-", "")
    if vendor in ("fortigate", "forti"):
        return FortiGateParser()
    if vendor in ("checkpoint", "check_point", "cp"):
        return CheckPointParser()
    raise ValueError(f"Unsupported vendor: {vendor}")
