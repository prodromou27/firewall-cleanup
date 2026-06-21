from app.parsers.fortigate import FortiGateParser
from app.parsers.checkpoint import CheckPointParser
from app.parsers.huawei_usg import HuaweiUSGParser
from app.parsers.cisco_asa import CiscoASAParser
from app.parsers.paloalto import PaloAltoParser
from app.parsers.base import SafeParser


def get_parser(vendor: str):
    normalized = vendor.lower().replace(" ", "").replace("-", "").replace("_", "")
    if normalized in ("fortigate", "forti"):
        return SafeParser(FortiGateParser(), "FortiGate")
    if normalized in ("checkpoint", "cp"):
        return SafeParser(CheckPointParser(), "CheckPoint")
    if normalized in ("huaweiusg", "huawei"):
        return SafeParser(HuaweiUSGParser(), "HuaweiUSG")
    if normalized in ("ciscoasa", "cisco", "asa", "pix"):
        return SafeParser(CiscoASAParser(), "CiscoASA")
    if normalized in ("paloalto", "panos", "panorama", "palo"):
        return SafeParser(PaloAltoParser(), "PaloAlto")
    raise ValueError(f"Unsupported vendor: {vendor}")
