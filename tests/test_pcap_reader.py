"""Tests for the PCAP ingestion / live-inference pipeline.

Scapy-dependent tests are skipped automatically when Scapy is not installed.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from src.pcap_reader import (
    CaptureReadError,
    load_flows,
    read_packets,
    validate_capture,
)
from src.cicids_features import CICIDS_FEATURE_NAMES

try:
    import scapy  # noqa: F401

    _HAVE_SCAPY = True
except Exception:  # pragma: no cover
    _HAVE_SCAPY = False


class TestCaptureFileErrors(unittest.TestCase):
    """Error handling that does not require Scapy."""

    def test_nonexistent_file(self):
        with self.assertRaises(FileNotFoundError):
            list(read_packets("definitely-not-a-real-file.pcap"))

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.pcap"
            empty.write_bytes(b"")
            with self.assertRaises(CaptureReadError):
                list(read_packets(empty))


@unittest.skipUnless(_HAVE_SCAPY, "scapy is not installed")
class TestPcapReader(unittest.TestCase):
    """End-to-end parsing of the synthetic sample capture."""

    @classmethod
    def setUpClass(cls):
        from src.sample_capture import build_sample_capture

        cls._tmp = tempfile.mkdtemp(prefix="nadsm_pcap_")
        cls.pcap = Path(cls._tmp) / "sample.pcap"
        build_sample_capture(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    # ---- packet-level parsing -----------------------------------------

    def test_packet_count_and_icmp_skipped(self):
        records = list(read_packets(self.pcap))
        # 12 TCP + 5 UDP = 17 usable; the single ICMP packet is skipped.
        self.assertEqual(len(records), 17)
        self.assertNotIn(1, {r.protocol for r in records})

    def test_first_packet_fields(self):
        first = next(iter(read_packets(self.pcap)))
        self.assertEqual(first.protocol, 6)
        self.assertEqual(first.src_ip, "10.0.0.1")
        self.assertEqual(first.dst_ip, "10.0.0.2")
        self.assertEqual(first.src_port, 40000)
        self.assertEqual(first.dst_port, 80)
        # Ethernet (14) + IP (20) + TCP (20), no options.
        self.assertEqual(first.length, 54)
        self.assertEqual(first.ip_header_length, 20)
        self.assertEqual(first.tcp_header_length, 20)
        self.assertTrue(first.syn)
        self.assertFalse(first.ack)

    def test_tcp_flags(self):
        records = [r for r in read_packets(self.pcap) if r.protocol == 6]
        self.assertTrue(records[0].syn and not records[0].ack)
        self.assertTrue(records[1].syn and records[1].ack)
        self.assertTrue(any(r.psh for r in records))
        self.assertTrue(any(r.fin for r in records))
        self.assertTrue(any(r.rst for r in records))

    def test_udp_packet_fields(self):
        udp = [r for r in read_packets(self.pcap) if r.protocol == 17]
        self.assertEqual(len(udp), 5)
        self.assertEqual(udp[0].tcp_header_length, 8)
        self.assertEqual(udp[0].tcp_window_size, 0)
        self.assertFalse(udp[0].syn)

    def test_max_packets_cap(self):
        records = list(read_packets(self.pcap, max_packets=5))
        self.assertEqual(len(records), 5)

    # ---- flow-level grouping ------------------------------------------

    def test_bidirectional_flow_grouping(self):
        extractor = load_flows(self.pcap)
        flows = extractor.get_flows()
        self.assertEqual(len(flows), 2)

        tcp = [f for f in flows if f.destination_port == 80]
        self.assertEqual(len(tcp), 1)
        tcp_flow = tcp[0]
        self.assertEqual(len(tcp_flow.packets), 12)
        self.assertEqual(tcp_flow.total_fwd_packets, 9)   # handshake + 6 data + FIN
        self.assertEqual(tcp_flow.total_backward_packets, 3)  # SYN-ACK + ACK + RST

        udp = [f for f in flows if f.destination_port == 53]
        self.assertEqual(len(udp), 1)
        self.assertEqual(len(udp[0].packets), 5)

    def test_flow_feature_schema(self):
        extractor = load_flows(self.pcap)
        for idx, flow in enumerate(extractor.get_flows()):
            features = flow.extract_features()
            self.assertEqual(
                list(features.keys()),
                list(CICIDS_FEATURE_NAMES),
                msg=f"flow {idx} feature schema mismatch",
            )

    # ---- full pipeline -------------------------------------------------

    def test_validate_capture_report(self):
        report = validate_capture(self.pcap)
        self.assertEqual(report["packet_count"], 17)
        self.assertEqual(report["flow_count"], 2)
        self.assertTrue(report["schema_ok"])
        self.assertEqual(report["schema_errors"], [])
        self.assertEqual(report["errors"], [])

        total = report["label_counts"]["BENIGN"] + report["label_counts"]["ATTACK"]
        self.assertEqual(total, 2)

        self.assertEqual(len(report["flows"]), 2)
        for flow in report["flows"]:
            self.assertIn(flow["prediction"], ("BENIGN", "ATTACK"))
            self.assertTrue(0.0 <= flow["confidence"] <= 1.0)
            self.assertEqual(flow["model"], "cicids_random_forest")

    def test_validate_capture_is_json_serialisable(self):
        report = validate_capture(self.pcap)
        # Should not raise.
        json.dumps(report)

    def test_validate_capture_flow_endpoints(self):
        report = validate_capture(self.pcap)
        endpoints = {(f["src"], f["dst"]) for f in report["flows"]}
        self.assertIn(("10.0.0.1:40000", "10.0.0.2:80"), endpoints)
        self.assertIn(("10.0.0.3:5000", "8.8.8.8:53"), endpoints)

    # ---- malformed captures -------------------------------------------

    def test_garbage_capture_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "garbage.pcap"
            bad.write_bytes(b"not a pcap file at all")
            with self.assertRaises(CaptureReadError):
                list(read_packets(bad))


@unittest.skipUnless(_HAVE_SCAPY, "scapy is not installed")
class TestSampleCaptureGenerator(unittest.TestCase):
    """The generator used as a fixture must be deterministic and writable."""

    def test_generator_writes_readable_capture(self):
        from src.sample_capture import build_sample_capture

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "gen.pcap"
            written = build_sample_capture(out)
            self.assertEqual(str(written), str(out))
            self.assertTrue(out.exists())
            self.assertGreater(out.stat().st_size, 0)
            self.assertEqual(len(list(read_packets(out))), 17)


if __name__ == "__main__":
    unittest.main()
