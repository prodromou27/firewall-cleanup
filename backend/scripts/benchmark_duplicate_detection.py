"""Synthetic duplicate-detector benchmark; not an end-to-end performance claim.

From backend/: python scripts/benchmark_duplicate_detection.py --sizes 600 6000
"""
import argparse
import json
import sys
from pathlib import Path
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.analysis.duplicate_detector import detect_duplicates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[600, 6000])
    args = parser.parse_args()
    for size in args.sizes:
        if not 1 <= size <= 65536:
            parser.error("sizes must be between 1 and 65536")
        rules = [dict(id=str(i), rule_number=i, enabled=True, action="accept",
                      sources=[f"10.{i // 256}.{i % 256}.1"],
                      destinations=["192.168.1.1"], services=["https"])
                 for i in range(size)]
        start = perf_counter()
        findings = detect_duplicates(rules, {})
        print(json.dumps({"rules": size, "findings": len(findings),
                          "seconds": round(perf_counter() - start, 4)}))


if __name__ == "__main__":
    main()
