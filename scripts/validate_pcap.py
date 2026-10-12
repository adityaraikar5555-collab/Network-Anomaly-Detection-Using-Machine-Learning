#!/usr/bin/env python
"""Command-line PCAP -> 78-feature -> model validation.

Runs the full live inference pipeline on a *saved* capture file and reports
extracted flow counts, schema validation, prediction labels, confidence scores,
skipped packets and any errors.

Usage::

    python scripts/validate_pcap.py --pcap capture.pcap
    python scripts/validate_pcap.py --pcap capture.pcap --model models/cicids_anomaly_model.pkl

Exit codes:

* ``0`` - capture processed (even if it contained zero usable flows).
* ``2`` - the capture could not be read, or Scapy is not installed.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import json
import platform
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.pcap_reader import (  # noqa: E402
    CaptureReadError,
    ScapyUnavailableError,
    render_markdown_report,
    validate_capture,
)


def _environment_metadata() -> "dict[str, str]":
    """Best-effort capture of the runtime environment for the report."""

    def version(distribution: str) -> str:
        try:
            return importlib.metadata.version(distribution)
        except Exception:
            return "not installed"

    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "scapy": version("scapy"),
        "scikit-learn": version("scikit-learn"),
        "numpy": version("numpy"),
        "pandas": version("pandas"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract CICIDS-2017 flow features from a PCAP/PCAPNG capture and "
            "classify each flow with the existing trained Random Forest model. "
            "Reads saved capture files only (not a live interface)."
        )
    )
    parser.add_argument("--pcap", required=True,
                        help="Path to a .pcap/.pcapng capture file.")
    parser.add_argument("--model", default=None,
                        help="Trained model .pkl (default: models/cicids_anomaly_model.pkl).")
    parser.add_argument("--encoder", default=None,
                        help="Label encoder .pkl (default: models/cicids_label_encoder.pkl).")
    parser.add_argument("--max-packets", type=int, default=None,
                        help="Stop after this many usable packets (default: no limit).")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="Write the full JSON report to this path.")
    parser.add_argument("--markdown", dest="markdown_path", default=None,
                        help="Write a human-readable Markdown report to this path. "
                             "Rendered from the same result object as --json.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        report = validate_capture(
            args.pcap,
            model_path=args.model,
            encoder_path=args.encoder,
            max_packets=args.max_packets,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except (ScapyUnavailableError, CaptureReadError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    # Provenance for the report files. These are added once, before either
    # format is rendered, so JSON and Markdown carry identical metadata.
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    report["command"] = " ".join(
        ["python", "scripts/validate_pcap.py", *argv_list]
    )
    report["generated_at"] = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    )
    report["environment"] = _environment_metadata()

    print("=" * 64)
    print("PCAP -> CICIDS-2017 inference validation")
    print("=" * 64)
    print(f"Capture            : {report['pcap']}")
    print(f"Usable packets     : {report['packet_count']}")
    print(f"Skipped (unsupported): {report['skipped_unsupported']}")
    print(f"Skipped (malformed)  : {report['skipped_malformed']}")
    print(f"Extracted flows    : {report['flow_count']}")
    print(f"Feature schema OK  : {report['schema_ok']}")
    print(f"Labels             : {report['label_counts']}")

    if report["schema_errors"]:
        print("\nSchema errors:")
        for err in report["schema_errors"]:
            print(f"  - {err}")

    if report["flows"]:
        print("\nPer-flow predictions:")
        for flow in report["flows"]:
            print(
                f"  [{flow['flow_index']:>3}] "
                f"{flow['src']:>21} -> {flow['dst']:<21} "
                f"proto={flow['protocol']:<3} "
                f"pkts={flow['packets']:<4} "
                f"{flow['prediction']:<6} "
                f"conf={flow['confidence']:.4f}"
            )

    if report["errors"]:
        print("\nNon-fatal errors:")
        for err in report["errors"]:
            print(f"  - {err}")

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(f"\nJSON report written to: {args.json_path}")

    if args.markdown_path:
        Path(args.markdown_path).write_text(
            render_markdown_report(report), encoding="utf-8"
        )
        print(f"Markdown report written to: {args.markdown_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
