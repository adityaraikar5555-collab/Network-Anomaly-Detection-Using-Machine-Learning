"""Tests for the PCAP/PCAPNG ingestion adapter (src/pcap_reader.py)."""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.flow_extractor import FlowExtractor, PacketRecord
from src.pcap_reader import (
    CaptureReadError,
    ScapyUnavailableError,
    load_flows,
    packet_to_record,
    read_packets,
    render_markdown_report,
    validate_capture,
)

try:
    with contextlib.redirect_stderr(io.StringIO()):
        from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap
    from scapy.utils import PcapNgWriter
    HAVE_SCAPY = True
except Exception:  # pragma: no cover
    HAVE_SCAPY = False


def _write_pcap(path, packets):
    wrpcap(str(path), packets)

@unittest.skipUnless(HAVE_SCAPY, "scapy is required for PCAP reader tests")
class TestPacketToRecord(unittest.TestCase):
    def test_tcp_payload_record(self):
        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=1234, dport=80, flags="PA", window=1024)
            / Raw(load=b"x" * 10)
        )
        pkt.time = 1000.0
        record = packet_to_record(pkt, IP, TCP, UDP)
        self.assertIsInstance(record, PacketRecord)
        self.assertEqual(record.src_ip, "10.0.0.1")
        self.assertEqual(record.dst_ip, "10.0.0.2")
        self.assertEqual(record.src_port, 1234)
        self.assertEqual(record.dst_port, 80)
        self.assertEqual(record.protocol, 6)
        self.assertEqual(record.payload_length, 10)
        self.assertTrue(record.psh)
        self.assertTrue(record.ack)
        self.assertEqual(record.ip_header_length, 20)
        self.assertEqual(record.tcp_header_length, 20)

    def test_udp_record(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=5000) / Raw(load=b"y" * 8)
        pkt.time = 1.0
        record = packet_to_record(pkt, IP, TCP, UDP)
        self.assertEqual(record.protocol, 17)
        self.assertEqual(record.payload_length, 8)
        self.assertEqual(record.tcp_header_length, 8)

    def test_header_only_tcp_has_zero_payload(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, flags="S")
        pkt.time = 1.0
        record = packet_to_record(pkt, IP, TCP, UDP)
        self.assertEqual(record.payload_length, 0)

    def test_non_tcp_udp_returns_none(self):
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
        pkt.time = 1.0
        self.assertIsNone(packet_to_record(pkt, IP, TCP, UDP))

@unittest.skipUnless(HAVE_SCAPY, "scapy is required")
class TestReadPackets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.pcap")
        pkts = []
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="S")
        p.time = 1.0
        pkts.append(p)
        p = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=2, dport=1, flags="SA")
        p.time = 1.1
        pkts.append(p)
        p = Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / ICMP()
        p.time = 1.2
        pkts.append(p)
        _write_pcap(self.path, pkts)

    def tearDown(self):
        self.tmp.cleanup()

    def test_reads_usable_and_counts_unsupported(self):
        stats = {}
        records = list(read_packets(self.path, stats=stats))
        self.assertEqual(len(records), 2)
        self.assertEqual(stats["usable"], 2)
        self.assertEqual(stats["unsupported"], 1)
        self.assertEqual(stats["malformed"], 0)

    def test_max_packets_cap(self):
        records = list(read_packets(self.path, max_packets=1))
        self.assertEqual(len(records), 1)

    def test_load_flows_groups_bidirectional(self):
        extractor = load_flows(self.path)
        self.assertEqual(len(extractor.get_flows()), 1)
        self.assertEqual(extractor.get_flows()[0].total_fwd_packets, 1)
        self.assertEqual(extractor.get_flows()[0].total_backward_packets, 1)

class TestCaptureErrors(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            list(read_packets("does_not_exist_xyz.pcap"))

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.pcap")
            Path(p).write_bytes(b"")
            with self.assertRaises(CaptureReadError):
                list(read_packets(p))

    def test_bad_magic(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.pcap")
            Path(p).write_bytes(b"not a pcap file at all")
            with self.assertRaises(CaptureReadError):
                list(read_packets(p))

    def test_scapy_unavailable_propagates(self):
        with mock.patch("src.pcap_reader._import_scapy", side_effect=ScapyUnavailableError("nope")):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "x.pcap")
                Path(p).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
                with self.assertRaises(ScapyUnavailableError):
                    list(read_packets(p))


@unittest.skipUnless(HAVE_SCAPY, "scapy is required")
class TestValidateCapture(unittest.TestCase):
    def test_end_to_end_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.pcap")
            pkts = []
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="SA")
            pkt.time = 1.0
            pkts.append(pkt)
            pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=2, dport=1, flags="A")
            pkt.time = 1.5
            pkts.append(pkt)
            wrpcap(p, pkts)
            report = validate_capture(p)
        self.assertIn("packet_count", report)
        self.assertTrue(report["schema_ok"])
        self.assertGreaterEqual(report["flow_count"], 1)
        for flow in report["flows"]:
            self.assertIn(flow["prediction"], ["BENIGN", "ATTACK"])
            self.assertTrue(0.0 <= flow["confidence"] <= 1.0)

    def test_report_includes_capture_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.pcap")
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="SA")
            pkt.time = 1.0
            wrpcap(p, [pkt])
            report = validate_capture(p)
        self.assertEqual(report["pcap_filename"], "s.pcap")
        self.assertEqual(len(report["pcap_sha256"]), 64)
        self.assertGreater(report["pcap_size_bytes"], 0)
        self.assertIn("model_path", report)
        self.assertIn("encoder_path", report)

    def test_markdown_report_matches_json_counts(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.pcap")
            pkts = []
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="SA")
            pkt.time = 1.0
            pkts.append(pkt)
            pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=2, dport=1, flags="A")
            pkt.time = 1.5
            pkts.append(pkt)
            wrpcap(p, pkts)
            report = validate_capture(p)
        markdown = render_markdown_report(report)
        self.assertIn(report["pcap_sha256"], markdown)
        for flow in report["flows"]:
            self.assertIn(str(flow["fwd_packets"]), markdown)
            self.assertIn(str(flow["bwd_packets"]), markdown)

    def test_pcapng_supported(self):
        try:
            from scapy.utils import PcapNgWriter
        except Exception:
            self.skipTest('PcapNgWriter not available')
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 's.pcapng')
            w = PcapNgWriter(p)
            pkt = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1, dport=2, flags='S')
            pkt.time = 1.0
            w.write(pkt)
            w.close()
            records = list(read_packets(p))
        self.assertEqual(len(records), 1)


class TestRenderMarkdownReport(unittest.TestCase):
    """The Markdown renderer must be a faithful view of the JSON result object."""

    def _report(self):
        return {
            "pcap": "http.cap",
            "pcap_filename": "http.cap",
            "pcap_sha256": "a" * 64,
            "pcap_size_bytes": 25803,
            "packet_count": 43,
            "flow_count": 1,
            "skipped_unsupported": 0,
            "skipped_malformed": 0,
            "schema_ok": True,
            "schema_errors": [],
            "label_counts": {"BENIGN": 1, "ATTACK": 0},
            "model_path": "models/cicids_anomaly_model.pkl",
            "encoder_path": "models/cicids_label_encoder.pkl",
            "flows": [
                {
                    "flow_index": 0,
                    "src": "145.254.160.237:3372",
                    "dst": "65.208.228.223:80",
                    "protocol": 6,
                    "packets": 34,
                    "fwd_packets": 16,
                    "bwd_packets": 18,
                    "prediction": "BENIGN",
                    "confidence": 0.9011,
                    "model": "cicids_random_forest",
                }
            ],
            "errors": [],
        }

    def test_renders_directional_split_from_result_object(self):
        markdown = render_markdown_report(self._report())
        # The forward/backward split must come from the result object, not a
        # hand-written value: a stale 17/17 would fail this assertion.
        self.assertIn("| 0 | `145.254.160.237:3372` | `65.208.228.223:80` | 6 | 34 | 16 | 18 |", markdown)
        self.assertNotIn("| 17 | 17 |", markdown)

    def test_renders_provenance_and_environment(self):
        report = self._report()
        report["generated_at"] = "2026-10-12T00:00:00+00:00"
        report["command"] = "python scripts/validate_pcap.py --pcap http.cap"
        report["environment"] = {"python": "3.13.5", "scapy": "2.8.0"}
        markdown = render_markdown_report(report)
        self.assertIn("a" * 64, markdown)
        self.assertIn("2026-10-12T00:00:00+00:00", markdown)
        self.assertIn("python scripts/validate_pcap.py --pcap http.cap", markdown)
        self.assertIn("3.13.5", markdown)

    def test_handles_no_flows(self):
        report = self._report()
        report["flows"] = []
        report["flow_count"] = 0
        markdown = render_markdown_report(report)
        self.assertIn("_No flows were extracted._", markdown)

    def test_renders_schema_errors(self):
        report = self._report()
        report["schema_ok"] = False
        report["schema_errors"] = ["flow 0: feature schema mismatch"]
        markdown = render_markdown_report(report)
        self.assertIn("flow 0: feature schema mismatch", markdown)
