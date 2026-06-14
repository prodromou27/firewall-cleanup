from app.parsers.fortigate import FortiGateParser
from app.parsers.checkpoint import CheckPointParser
from app.parsers.huawei_usg import HuaweiUSGParser
from app.parsers.cisco_asa import CiscoASAParser
from app.parsers.paloalto import PaloAltoParser


def get_parser(vendor: str):
    vendor = vendor.lower().replace(" ", "").replace("-", "").replace("_", "")
    if vendor in ("fortigate", "forti"):
        return FortiGateParser()
    if vendor in ("checkpoint", "cp"):
        return CheckPointParser()
    if vendor in ("huaweiusg", "huawei"):
        return HuaweiUSGParser()
    if vendor in ("ciscoasa", "cisco", "asa", "pix"):
        return CiscoASAParser()
    if vendor in ("paloalto", "panos", "panorama", "palo"):
        return PaloAltoParser()
    raise ValueError(f"Unsupported vendor: {vendor}")
