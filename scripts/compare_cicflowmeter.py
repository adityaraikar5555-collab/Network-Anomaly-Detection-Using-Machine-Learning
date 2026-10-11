#!/usr/bin/env python
"""Compare our 78-feature extractor against the ``cicflowmeter`` reference port.

This is a *diagnostic* tool. It runs both feature extractors on the same capture
and reports per-feature differences, so deviations from CICFlowMeter semantics
are visible instead of assumed.

The reference port (``pip install cicflowmeter``) is a Python re-implementation
of the original Java CICFlowMeter. It is **not** byte-for-byte identical to the
original, and it emits time features in **seconds** while the CICIDS-2017
dataset uses **microseconds**. This script rescales the reference's time
features before comparing.

Usage::

    python scripts/compare_cicflowmeter.py --pcap samples/sample.pcap

Exit codes:

* ``0`` - comparison ran (differences are reported, not treated as failure).
* ``2`` - a required dependency or input file was missing.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.cicids_features import CICIDS_FEATURE_NAMES  # noqa: E402

# CICIDS feature name -> (cicflowmeter column, multiplier).
# Time features are rescaled seconds -> microseconds (x1e6).
_SECOND_TO_MICRO = 1_000_000.0
REFERENCE_MAP: "dict[str, tuple[str, float]]" = {
    "Destination Port": ("dst_port", 1.0),
    "Flow Duration": ("flow_duration", _SECOND_TO_MICRO),
    "Total Fwd Packets": ("tot_fwd_pkts", 1.0),
    "Total Backward Packets": ("tot_bwd_pkts", 1.0),
    "Total Length of Fwd Packets": ("totlen_fwd_pkts", 1.0),
    "Total Length of Bwd Packets": ("totlen_bwd_pkts", 1.0),
    "Fwd Packet Length Max": ("fwd_pkt_len_max", 1.0),
    "Fwd Packet Length Min": ("fwd_pkt_len_min", 1.0),
    "Fwd Packet Length Mean": ("fwd_pkt_len_mean", 1.0),
    "Fwd Packet Length Std": ("fwd_pkt_len_std", 1.0),
    "Bwd Packet Length Max": ("bwd_pkt_len_max", 1.0),
    "Bwd Packet Length Min": ("bwd_pkt_len_min", 1.0),
    "Bwd Packet Length Mean": ("bwd_pkt_len_mean", 1.0),
    "Bwd Packet Length Std": ("bwd_pkt_len_std", 1.0),
    "Flow Bytes/s": ("flow_byts_s", 1.0),
    "Flow Packets/s": ("flow_pkts_s", 1.0),
    "Flow IAT Mean": ("flow_iat_mean", _SECOND_TO_MICRO),
    "Flow IAT Std": ("flow_iat_std", _SECOND_TO_MICRO),
    "Flow IAT Max": ("flow_iat_max", _SECOND_TO_MICRO),
    "Flow IAT Min": ("flow_iat_min", _SECOND_TO_MICRO),
    "Fwd IAT Total": ("fwd_iat_tot", _SECOND_TO_MICRO),
    "Fwd IAT Mean": ("fwd_iat_mean", _SECOND_TO_MICRO),
    "Fwd IAT Std": ("fwd_iat_std", _SECOND_TO_MICRO),
    "Fwd IAT Max": ("fwd_iat_max", _SECOND_TO_MICRO),
    "Fwd IAT Min": ("fwd_iat_min", _SECOND_TO_MICRO),
    "Bwd IAT Total": ("bwd_iat_tot", _SECOND_TO_MICRO),
    "Bwd IAT Mean": ("bwd_iat_mean", _SECOND_TO_MICRO),
    "Bwd IAT Std": ("bwd_iat_std", _SECOND_TO_MICRO),
    "Bwd IAT Max": ("bwd_iat_max", _SECOND_TO_MICRO),
    "Bwd IAT Min": ("bwd_iat_min", _SECOND_TO_MICRO),
    "Fwd PSH Flags": ("fwd_psh_flags", 1.0),
    "Bwd PSH Flags": ("bwd_psh_flags", 1.0),
    "Fwd URG Flags": ("fwd_urg_flags", 1.0),
    "Bwd URG Flags": ("bwd_urg_flags", 1.0),
    "Fwd Header Length": ("fwd_header_len", 1.0),
    "Bwd Header Length": ("bwd_header_len", 1.0),
    "Fwd Packets/s": ("fwd_pkts_s", 1.0),
    "Bwd Packets/s": ("bwd_pkts_s", 1.0),
    "Min Packet Length": ("pkt_len_min", 1.0),
    "Max Packet Length": ("pkt_len_max", 1.0),
    "Packet Length Mean": ("pkt_len_mean", 1.0),
    "Packet Length Std": ("pkt_len_std", 1.0),
    "Packet Length Variance": ("pkt_len_var", 1.0),
    "FIN Flag Count": ("fin_flag_cnt", 1.0),
    "SYN Flag Count": ("syn_flag_cnt", 1.0),
    "RST Flag Count": ("rst_flag_cnt", 1.0),
    "PSH Flag Count": ("psh_flag_cnt", 1.0),
    "ACK Flag Count": ("ack_flag_cnt", 1.0),
    "URG Flag Count": ("urg_flag_cnt", 1.0),
    # The reference port aliases CWE -> URG (a known bug); compare anyway.
    "CWE Flag Count": ("cwr_flag_count", 1.0),
    "ECE Flag Count": ("ece_flag_cnt", 1.0),
    "Down/Up Ratio": ("down_up_ratio", 1.0),
    "Average Packet Size": ("pkt_size_avg", 1.0),
    "Avg Fwd Segment Size": ("fwd_seg_size_avg", 1.0),
    "Avg Bwd Segment Size": ("bwd_seg_size_avg", 1.0),
    "Fwd Header Length.1": ("fwd_header_len", 1.0),
    "Fwd Avg Bytes/Bulk": ("fwd_byts_b_avg", 1.0),
    "Fwd Avg Packets/Bulk": ("fwd_pkts_b_avg", 1.0),
    "Fwd Avg Bulk Rate": ("fwd_blk_rate_avg", 1.0),
    "Bwd Avg Bytes/Bulk": ("bwd_byts_b_avg", 1.0),
    "Bwd Avg Packets/Bulk": ("bwd_pkts_b_avg", 1.0),
    "Bwd Avg Bulk Rate": ("bwd_blk_rate_avg", 1.0),
    "Subflow Fwd Packets": ("subflow_fwd_pkts", 1.0),
    "Subflow Fwd Bytes": ("subflow_fwd_byts", 1.0),
    "Subflow Bwd Packets": ("subflow_bwd_pkts", 1.0),
    "Subflow Bwd Bytes": ("subflow_bwd_byts", 1.0),
    "Init_Win_bytes_forward": ("init_fwd_win_byts", 1.0),
    "Init_Win_bytes_backward": ("init_bwd_win_byts", 1.0),
    "act_data_pkt_fwd": ("fwd_act_data_pkts", 1.0),
    "min_seg_size_forward": ("fwd_seg_size_min", 1.0),
    "Active Mean": ("active_mean", _SECOND_TO_MICRO),
    "Active Std": ("active_std", _SECOND_TO_MICRO),
    "Active Max": ("active_max", _SECOND_TO_MICRO),
    "Active Min": ("active_min", _SECOND_TO_MICRO),
    "Idle Mean": ("idle_mean", _SECOND_TO_MICRO),
    "Idle Std": ("idle_std", _SECOND_TO_MICRO),
    "Idle Max": ("idle_max", _SECOND_TO_MICRO),
    "Idle Min": ("idle_min", _SECOND_TO_MICRO),
}


def _reference_rows(pcap_path: str) -> "list[dict]":
    """Run the ``cicflowmeter`` reference port offline and return its rows."""

    try:
        from scapy.utils import PcapReader
        from cicflowmeter.flow_session import FlowSession
    except Exception as exc:
        raise RuntimeError(
            "The 'cicflowmeter' and 'scapy' packages are required for the "
            "reference comparison (pip install cicflowmeter scapy)."
        ) from exc

    class _MemoryWriter:
        def __init__(self) -> None:
            self.rows: "list[dict]" = []

        def write(self, data: dict) -> None:
            self.rows.append(dict(data))

    # The factory insists on opening a CSV file; discard it immediately and
    # collect rows in memory instead (avoids Windows file-locking issues).
    handle = tempfile.NamedTemporaryFile(suffix=".csv", prefix="cflow_", delete=False)
    handle.close()
    tmp_csv = Path(handle.name)
    session = FlowSession(output_mode="csv", output=str(tmp_csv))
    session.output_writer.file.close()
    writer = _MemoryWriter()
    session.output_writer = writer
    try:
        with PcapReader(pcap_path) as reader:
            for packet in reader:
                session.process(packet)
        session.flush_flows()
    finally:
        session.output_writer = None
        tmp_csv.unlink(missing_ok=True)

    return writer.rows


def _our_rows(pcap_path: str) -> "list[dict]":
    from src.pcap_reader import load_flows

    extractor = load_flows(pcap_path)
    rows = []
    for flow in extractor.get_flows():
        first = flow.forward_packets[0] if flow.forward_packets else flow.packets[0]
        row = {
            "src_ip": first.src_ip,
            "dst_ip": first.dst_ip,
            "src_port": first.src_port,
            "dst_port": first.dst_port,
            "protocol": first.protocol,
        }
        row.update(flow.extract_features())
        rows.append(row)
    return rows


def _key(row: dict):
    def as_int(value):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return value

    return (
        row.get("src_ip"),
        as_int(row.get("src_port")),
        row.get("dst_ip"),
        as_int(row.get("dst_port")),
        as_int(row.get("protocol")),
    )


def compare(pcap_path: str, tolerance: float = 1e-6) -> dict:
    reference = {_key(r): r for r in _reference_rows(pcap_path)}
    ours = {_key(r): r for r in _our_rows(pcap_path)}

    matched_keys = sorted(set(reference) & set(ours), key=str)
    flow_reports = []
    for key in matched_keys:
        ref, mine = reference[key], ours[key]
        diffs = []
        for name in CICIDS_FEATURE_NAMES:
            column, scale = REFERENCE_MAP[name]
            raw = ref.get(column)
            if raw in (None, "", "NaN"):
                continue
            try:
                ref_value = float(raw) * scale
            except (TypeError, ValueError):
                continue
            try:
                our_value = float(mine.get(name, 0.0))
            except (TypeError, ValueError):
                our_value = float("nan")

            if ref_value == 0.0 and our_value == 0.0:
                continue
            denom = max(abs(ref_value), abs(our_value), 1e-12)
            rel = abs(ref_value - our_value) / denom
            if rel > tolerance:
                diffs.append(
                    {
                        "feature": name,
                        "ours": our_value,
                        "reference_scaled": ref_value,
                        "rel_diff": rel,
                    }
                )
        flow_reports.append(
            {
                "flow": {
                    "src": f"{key[0]}:{key[1]}",
                    "dst": f"{key[2]}:{key[3]}",
                    "protocol": key[4],
                },
                "mismatched_features": sorted(diffs, key=lambda d: -d["rel_diff"]),
            }
        )

    return {
        "pcap": str(pcap_path),
        "reference_flow_count": len(reference),
        "our_flow_count": len(ours),
        "matched_flow_count": len(matched_keys),
        "unmatched_reference": [str(k) for k in set(reference) - set(ours)],
        "unmatched_ours": [str(k) for k in set(ours) - set(reference)],
        "flows": flow_reports,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pcap", required=True, help="Capture file to analyse.")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=1e-4,
        help="Relative difference above which a feature is reported (default 1e-4).",
    )
    parser.add_argument("--max-report", type=int, default=15,
                        help="Max mismatched features to print per flow.")
    parser.add_argument("--json", dest="json_path", default=None)
    args = parser.parse_args(argv)

    try:
        report = compare(args.pcap, tolerance=args.tolerance)
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("=" * 64)
    print("Extractor parity vs cicflowmeter reference")
    print("=" * 64)
    print(f"Reference flows : {report['reference_flow_count']}")
    print(f"Our flows       : {report['our_flow_count']}")
    print(f"Matched flows   : {report['matched_flow_count']}")
    if report["unmatched_reference"]:
        print(f"Unmatched (ref) : {report['unmatched_reference']}")
    if report["unmatched_ours"]:
        print(f"Unmatched (ours): {report['unmatched_ours']}")

    for flow in report["flows"]:
        diffs = flow["mismatched_features"]
        label = f"{flow['flow']['src']} -> {flow['flow']['dst']}"
        print(f"\n{label}")
        if not diffs:
            print("  all 78 features within tolerance")
            continue
        print(f"  {len(diffs)} feature(s) beyond tolerance:")
        for diff in diffs[: args.max_report]:
            print(
                f"    {diff['feature']:<28} "
                f"ours={diff['ours']:.6g} "
                f"ref={diff['reference_scaled']:.6g} "
                f"rel={diff['rel_diff']:.2e}"
            )
        if len(diffs) > args.max_report:
            print(f"    ... and {len(diffs) - args.max_report} more")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.json_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
