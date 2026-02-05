"""Command-line interface for the keylogger detector."""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import DEFAULT_SAMPLE_INTERVAL
from .scanner import report_to_json, run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive keylogger detector (process + network scan)."
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=DEFAULT_SAMPLE_INTERVAL,
        help="Seconds between CPU samples (default: %(default)s).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the JSON report to a file instead of stdout.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report = run_scan(sample_interval=args.sample_interval)
    payload = report_to_json(report)

    if args.output:
        args.output.write_text(payload, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
