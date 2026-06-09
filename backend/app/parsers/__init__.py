from app.parsers.fortigate import FortiGateParser
from app.parsers.checkpoint import CheckPointParser
from app.parsers.huawei_usg import HuaweiUSGParser


def get_parser(vendor: str):
    vendor = vendor.lower().replace(" ", "").replace("-", "")
    if vendor in ("fortigate", "forti"):
        return FortiGateParser()
    if vendor in ("checkpoint", "check_point", "cp"):
        return CheckPointParser()
    if vendor in ("huaweiusg", "huawei_usg", "huawei"):
        return HuaweiUSGParser()
    raise ValueError(f"Unsupported vendor: {vendor}")
