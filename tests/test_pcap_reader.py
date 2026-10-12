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
