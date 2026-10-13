"""Unit tests for the live CICIDS-2017 flow feature extractor.

These tests do not depend on any committed PCAP or CICIDS dataset files.
They build small synthetic flows in-memory and verify that the extractor
produces exactly the 78 features required by the trained Random Forest model,
in the exact training order, with no NaN/Inf, and that the model accepts the
resulting vector.
"""

import math
import unittest
from unittest import mock

from src.cicids_features import CICIDS_FEATURE_NAMES
from src.flow_extractor import (
    MICROSECONDS_PER_SECOND,
    FlowExtractor,
    InvalidPacketError,
    NetworkFlow,
    NonFiniteFeatureError,
    PacketRecord,
)
from src.prediction import (
    load_cicids_artifacts,
    predict_cicids,
    predict_flow,
)


def _make_packet(
    timestamp,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    length,
    *,
    protocol=6,
    ip_header_length=20,
    tcp_header_length=20,
    payload_length=0,
    tcp_window_size=0,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    psh=False,
    urg=False,
    cwe=False,
    ece=False,
):
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        ip_header_length=ip_header_length,
        tcp_header_length=tcp_header_length,
        payload_length=payload_length,
        tcp_window_size=tcp_window_size,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
        psh=psh,
        urg=urg,
        cwe=cwe,
        ece=ece,
    )


def build_sample_flow():
    """Build one bidirectional TCP flow with forward and backward packets."""

    extractor = FlowExtractor()

    # Forward direction (client -> server), 3 packets.
    extractor.add_packet(_make_packet(
        1000.000000, "192.168.1.10", "10.0.0.5", 51000, 443, 1466,
        tcp_window_size=65535, syn=True, ack=True, psh=True,
    ))
    extractor.add_packet(_make_packet(
        1000.002000, "192.168.1.10", "10.0.0.5", 51000, 443, 1200,
        tcp_window_size=65535, ack=True, psh=True,
    ))
    extractor.add_packet(_make_packet(
        1000.005000, "192.168.1.10", "10.0.0.5", 51000, 443, 800,
        tcp_window_size=65535, ack=True, urg=True,
    ))

    # Backward direction (server -> client), 2 packets.
    extractor.add_packet(_make_packet(
        1000.001000, "10.0.0.5", "192.168.1.10", 443, 51000, 54,
        tcp_window_size=32768, ack=True, psh=True, cwe=True, ece=True,
    ))
    extractor.add_packet(_make_packet(
        1000.010000, "10.0.0.5", "192.168.1.10", 443, 51000, 60,
        tcp_window_size=32768, ack=True, fin=True, rst=True,
    ))

    return extractor.get_flows()[0]


class TestFlowExtractorSchema(unittest.TestCase):
    """Schema / count / order / finiteness of the extracted feature vector."""

    def setUp(self):
        self.flow = build_sample_flow()

    def test_extract_features_has_exactly_78_features(self):
        features = self.flow.extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(len(CICIDS_FEATURE_NAMES), 78)

    def test_feature_names_match_training_schema_exactly(self):
        features = self.flow.extract_features()
        self.assertEqual(set(features.keys()), set(CICIDS_FEATURE_NAMES))
        self.assertEqual(len(features), len(set(features)))

    def test_feature_order_matches_training_schema(self):
        # Fails loudly if anyone reorders the canonical schema or the extractor.
        features = self.flow.extract_features()
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))

    def test_feature_order_matches_model_artifact(self):
        model, _ = load_cicids_artifacts()
        self.assertEqual(list(CICIDS_FEATURE_NAMES), list(model.feature_names_in_))

    def test_all_feature_values_are_numeric(self):
        for name, value in self.flow.extract_features().items():
            self.assertIsInstance(value, float, f"{name} is not a float")

    def test_no_nan_or_inf(self):
        for name, value in self.flow.extract_features().items():
            self.assertFalse(math.isnan(value), f"{name} is NaN")
            self.assertFalse(math.isinf(value), f"{name} is Inf")

    def test_feature_vector_length_and_order(self):
        vector = self.flow.to_feature_vector()
        features = self.flow.extract_features()
        self.assertEqual(len(vector), 78)
        self.assertEqual(vector, [features[n] for n in CICIDS_FEATURE_NAMES])

    def test_extraction_is_deterministic(self):
        first = self.flow.to_feature_vector()
        second = self.flow.to_feature_vector()
        self.assertEqual(first, second)

    def test_fwd_psh_flags_present_and_correct(self):
        features = self.flow.extract_features()
        self.assertIn("Fwd PSH Flags", features)
        # Two forward packets were flagged PSH in build_sample_flow().
        self.assertEqual(features["Fwd PSH Flags"], 2.0)
        self.assertEqual(features["Bwd PSH Flags"], 1.0)

    def test_flow_duration_is_microseconds(self):
        features = self.flow.extract_features()
        expected_us = self.flow.duration * MICROSECONDS_PER_SECOND
        self.assertAlmostEqual(features["Flow Duration"], expected_us)

    def test_tcp_flag_counts(self):
        features = self.flow.extract_features()
        self.assertEqual(features["SYN Flag Count"], 1.0)
        self.assertEqual(features["FIN Flag Count"], 1.0)
        self.assertEqual(features["RST Flag Count"], 1.0)
        self.assertEqual(features["ACK Flag Count"], 5.0)
        self.assertEqual(features["PSH Flag Count"], 3.0)
        self.assertEqual(features["URG Flag Count"], 1.0)
        self.assertEqual(features["CWE Flag Count"], 1.0)
        self.assertEqual(features["ECE Flag Count"], 1.0)


class TestFlowExtractorEdgeCases(unittest.TestCase):
    """Edge cases must still yield a complete, finite 78-feature schema."""

    def test_single_packet_flow(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(
            500.0, "10.0.0.1", "10.0.0.2", 12345, 80, 100,
            tcp_window_size=8192, syn=True,
        ))
        features = extractor.get_flows()[0].extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))
        for value in features.values():
            self.assertFalse(math.isnan(value))
            self.assertFalse(math.isinf(value))

    def test_empty_flow(self):
        flow = NetworkFlow(key=("a", "b", 6))
        features = flow.extract_features()
        self.assertEqual(len(features), 78)
        self.assertEqual(list(features.keys()), list(CICIDS_FEATURE_NAMES))
        self.assertTrue(all(v == 0.0 for v in features.values()))

    def test_multiple_flows(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(1.0, "10.0.0.1", "10.0.0.2", 1, 80, 100, ack=True))
        extractor.add_packet(_make_packet(2.0, "10.0.0.3", "10.0.0.4", 2, 22, 120, ack=True))
        vectors = extractor.get_feature_vectors()
        self.assertEqual(len(vectors), 2)
        for vector in vectors:
            self.assertEqual(len(vector), 78)
            self.assertTrue(all(isinstance(v, float) for v in vector))


class TestFlowModelInference(unittest.TestCase):
    """End-to-end integration: extractor -> existing model -> label/confidence."""

    def setUp(self):
        self.flow = build_sample_flow()

    def test_model_accepts_extracted_vector(self):
        vector = self.flow.to_feature_vector()
        result = predict_cicids(vector)
        self.assertIsInstance(result, dict)

    def test_prediction_label_and_confidence_ranges(self):
        result = predict_cicids(self.flow.to_feature_vector())
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])
        self.assertIsInstance(result["confidence"], float)
        self.assertTrue(0.0 <= result["confidence"] <= 1.0)
        self.assertEqual(result["model"], "cicids_random_forest")

    def test_model_accepts_extracted_dict(self):
        result = predict_cicids(self.flow.extract_features())
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])

    def test_predict_flow_end_to_end(self):
        result = predict_flow(self.flow)
        self.assertIn(result["prediction"], ["BENIGN", "ATTACK"])
        self.assertTrue(0.0 <= result["confidence"] <= 1.0)

    def test_predict_flow_rejects_non_flow(self):
        with self.assertRaises(TypeError):
            predict_flow({"not": "a flow"})


if __name__ == "__main__":
    unittest.main()

class TestPayloadDrivenFeatures(unittest.TestCase):
    def test_act_data_pkt_fwd_counts_only_payload_packets(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(1.0, 'a','b',1,80,100, payload_length=0, ack=True))
        extractor.add_packet(_make_packet(1.1, 'a','b',1,80,150, payload_length=50, ack=True))
        extractor.add_packet(_make_packet(1.2, 'a','b',1,80,200, payload_length=100, ack=True))
        flow = extractor.get_flows()[0]
        features = flow.extract_features()
        self.assertEqual(features['act_data_pkt_fwd'], 2.0)

    def test_min_seg_size_forward_uses_payload(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(1.0, 'a','b',1,80,74, payload_length=20, ack=True))
        extractor.add_packet(_make_packet(1.1, 'a','b',1,80,104, payload_length=50, ack=True))
        extractor.add_packet(_make_packet(1.2, 'a','b',1,80,154, payload_length=100, ack=True))
        flow = extractor.get_flows()[0]
        features = flow.extract_features()
        self.assertEqual(features['min_seg_size_forward'], 20.0)

    def test_min_seg_size_forward_zero_when_header_only(self):
        extractor = FlowExtractor()
        extractor.add_packet(_make_packet(1.0, 'a','b',1,80,100, payload_length=0, ack=True))
        extractor.add_packet(_make_packet(1.1, 'a','b',1,80,150, payload_length=0, ack=True))
        flow = extractor.get_flows()[0]
        features = flow.extract_features()
        self.assertEqual(features['min_seg_size_forward'], 0.0)
        self.assertEqual(features['act_data_pkt_fwd'], 0.0)

class TestBulkFeatures(unittest.TestCase):
    """Numerical regression tests for bulk transfer calculation.

    Authoritative reference: Java CICFlowMeter (BasicFlow.java lines 388-560).
    Verified behaviors:
    1. Forward bulk only (single direction burst >= 4 packets with payload > 0)
    2. Backward bulk only (backward burst >= 4 packets with payload > 0)
    3. Bidirectional where only forward qualifies (forward >= 4, backward < 4)
    4. Bidirectional where both qualify
    5. Packet count below threshold (count < 4) -> all 6 bulk features 0.0
    6. Packet arrival after timeout (> 1.0s clump gap) -> clump resets, features 0.0
    7. Packets without payload (payload = 0) -> ignored, do not count towards bulk
    8. Interleaving reset (reverse direction payload packet arrives before bound)
    """

    def _burst(self, count=5, payload=100, spacing=0.01, start=1000.0, is_forward=True):
        extractor = FlowExtractor()
        t = start
        src_ip, dst_ip = ("a", "b") if is_forward else ("b", "a")
        src_port, dst_port = (1, 80) if is_forward else (80, 1)
        if not is_forward:
            # Seed the forward direction with a zero-payload handshake packet
            extractor.add_packet(_make_packet(t - 1.0, "a", "b", 1, 80, 54, payload_length=0, syn=True))

        for _ in range(count):
            extractor.add_packet(_make_packet(t, src_ip, dst_ip, src_port, dst_port, payload + 54, payload_length=payload, ack=True))
            t += spacing
        return extractor.get_flows()[0]

    def test_scenario1_forward_bulk_only(self):
        """Scenario 1: Forward bulk only."""
        flow = self._burst(count=5, payload=100, spacing=0.01, is_forward=True)
        f = flow.extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 500.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 5.0)
        self.assertAlmostEqual(f["Fwd Avg Bulk Rate"], 500.0 / 0.04, places=3)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Bulk Rate"], 0.0)

    def test_scenario2_backward_bulk_only(self):
        """Scenario 2: Backward bulk only."""
        flow = self._burst(count=5, payload=100, spacing=0.01, is_forward=False)
        f = flow.extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Bulk Rate"], 0.0)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 500.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 5.0)
        self.assertAlmostEqual(f["Bwd Avg Bulk Rate"], 500.0 / 0.04, places=3)

    def test_scenario3_bidirectional_only_forward_qualifies(self):
        """Scenario 3: Bidirectional flow where only forward qualifies for bulk."""
        extractor = FlowExtractor()
        t = 1000.0
        for _ in range(5):
            extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
            t += 0.01
        t += 2.0
        for _ in range(2):
            extractor.add_packet(_make_packet(t, "b", "a", 80, 1, 154, payload_length=100, ack=True))
            t += 0.01
        f = extractor.get_flows()[0].extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 500.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 5.0)
        self.assertAlmostEqual(f["Fwd Avg Bulk Rate"], 500.0 / 0.04, places=3)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Bulk Rate"], 0.0)

    def test_scenario4_bidirectional_both_qualify(self):
        """Scenario 4: Bidirectional flow where both directions qualify for bulk."""
        extractor = FlowExtractor()
        t = 1000.0
        for _ in range(4):
            extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
            t += 0.01
        t += 2.0
        for _ in range(4):
            extractor.add_packet(_make_packet(t, "b", "a", 80, 1, 154, payload_length=200, ack=True))
            t += 0.02
        f = extractor.get_flows()[0].extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 400.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 4.0)
        self.assertAlmostEqual(f["Fwd Avg Bulk Rate"], 400.0 / 0.03, places=3)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 800.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 4.0)
        self.assertAlmostEqual(f["Bwd Avg Bulk Rate"], 800.0 / 0.06, places=3)

    def test_scenario5_below_threshold_bulk_bound(self):
        """Scenario 5: Flow where packet count is below threshold (3 < BULK_BOUND 4)."""
        flow = self._burst(count=3, payload=100, spacing=0.01)
        f = flow.extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Bulk Rate"], 0.0)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Bulk Rate"], 0.0)

    def test_scenario6_clump_gap_timeout_resets(self):
        """Scenario 6: Flow where packet arrives after timeout (> 1.0s gap)."""
        extractor = FlowExtractor()
        t = 1000.0
        extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        t += 0.01
        extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        t += 2.0
        extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        t += 0.01
        extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        f = extractor.get_flows()[0].extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Bulk Rate"], 0.0)

    def test_scenario7_header_only_packets_ignored(self):
        """Scenario 7: Packets without payload (payload = 0) do not participate in bulk."""
        extractor = FlowExtractor()
        t = 1000.0
        for _ in range(10):
            extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 54, payload_length=0, ack=True))
            t += 0.01
        f = extractor.get_flows()[0].extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Bulk Rate"], 0.0)

    def test_scenario8_interleaving_reverse_direction_resets(self):
        """Scenario 8: Interleaving reset where reverse direction payload packet resets clump."""
        extractor = FlowExtractor()
        for i in range(3):
            extractor.add_packet(_make_packet(1000.0 + i * 0.01, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        extractor.add_packet(_make_packet(1000.03, "b", "a", 80, 1, 154, payload_length=100, ack=True))
        extractor.add_packet(_make_packet(1000.04, "a", "b", 1, 80, 154, payload_length=100, ack=True))
        f = extractor.get_flows()[0].extract_features()
        self.assertEqual(f["Fwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Fwd Avg Bulk Rate"], 0.0)
        self.assertEqual(f["Bwd Avg Bytes/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Packets/Bulk"], 0.0)
        self.assertEqual(f["Bwd Avg Bulk Rate"], 0.0)


class TestActiveIdleFeatures(unittest.TestCase):
    """Numerical regression tests for Active and Idle time calculations.

    Authoritative reference: Java CICFlowMeter (BasicFlow.java / FlowGenerator.java).
    Verified behaviors:
    1. Single-packet flow -> all Active/Idle stats are 0.0.
    2. Multi-packet flow with no idle gaps (> 5.0s) -> all Active/Idle stats are 0.0.
    3. Multi-packet flow with one idle gap -> preceding active period and idle gap recorded;
       trailing active period discarded upon flow termination.
    4. Multi-packet flow with multiple idle gaps -> multiple active and idle periods recorded.
    5. Zero-duration flow -> all Active/Idle stats are 0.0.
    6. Sample standard deviation calculation with Bessel's correction (N - 1) matching
       Apache Commons Math 3 SummaryStatistics.
    7. Microsecond unit scaling verification (1s = 1,000,000 us).
    """

    def _flow(self, timestamps):
        extractor = FlowExtractor()
        for t in timestamps:
            extractor.add_packet(_make_packet(t, "a", "b", 1, 80, 100, ack=True))
        return extractor.get_flows()[0].extract_features()

    def test_single_packet_flow_zero_active_idle(self):
        f = self._flow([1000.0])
        self.assertEqual(f["Active Mean"], 0.0)
        self.assertEqual(f["Active Std"], 0.0)
        self.assertEqual(f["Active Max"], 0.0)
        self.assertEqual(f["Active Min"], 0.0)
        self.assertEqual(f["Idle Mean"], 0.0)
        self.assertEqual(f["Idle Std"], 0.0)
        self.assertEqual(f["Idle Max"], 0.0)
        self.assertEqual(f["Idle Min"], 0.0)

    def test_zero_duration_multi_packet_zero_active_idle(self):
        f = self._flow([1000.0, 1000.0, 1000.0])
        self.assertEqual(f["Active Mean"], 0.0)
        self.assertEqual(f["Active Std"], 0.0)
        self.assertEqual(f["Active Max"], 0.0)
        self.assertEqual(f["Active Min"], 0.0)
        self.assertEqual(f["Idle Mean"], 0.0)
        self.assertEqual(f["Idle Std"], 0.0)
        self.assertEqual(f["Idle Max"], 0.0)
        self.assertEqual(f["Idle Min"], 0.0)

    def test_flow_without_idle_gaps_zero_active_idle(self):
        f = self._flow([1000.0, 1001.0, 1002.0, 1005.0])
        self.assertEqual(f["Active Mean"], 0.0)
        self.assertEqual(f["Active Std"], 0.0)
        self.assertEqual(f["Active Max"], 0.0)
        self.assertEqual(f["Active Min"], 0.0)
        self.assertEqual(f["Idle Mean"], 0.0)
        self.assertEqual(f["Idle Std"], 0.0)
        self.assertEqual(f["Idle Max"], 0.0)
        self.assertEqual(f["Idle Min"], 0.0)

    def test_gap_exactly_threshold_stays_active(self):
        f = self._flow([1000.0, 1005.0])
        self.assertEqual(f["Active Mean"], 0.0)
        self.assertEqual(f["Active Max"], 0.0)
        self.assertEqual(f["Idle Max"], 0.0)

    def test_single_idle_gap_records_preceding_active(self):
        f = self._flow([1000.0, 1002.0, 1010.0])
        self.assertAlmostEqual(f["Active Mean"], 2_000_000.0)
        self.assertAlmostEqual(f["Active Max"], 2_000_000.0)
        self.assertAlmostEqual(f["Active Min"], 2_000_000.0)
        self.assertEqual(f["Active Std"], 0.0)
        self.assertAlmostEqual(f["Idle Mean"], 8_000_000.0)
        self.assertAlmostEqual(f["Idle Max"], 8_000_000.0)
        self.assertAlmostEqual(f["Idle Min"], 8_000_000.0)
        self.assertEqual(f["Idle Std"], 0.0)

    def test_single_idle_gap_with_zero_duration_preceding_active(self):
        f = self._flow([1000.0, 1008.0])
        self.assertEqual(f["Active Mean"], 0.0)
        self.assertEqual(f["Active Max"], 0.0)
        self.assertAlmostEqual(f["Idle Mean"], 8_000_000.0)
        self.assertAlmostEqual(f["Idle Max"], 8_000_000.0)

    def test_multiple_idle_gaps_and_sample_std(self):
        f = self._flow([1000.0, 1002.0, 1010.0, 1014.0, 1024.0])
        self.assertAlmostEqual(f["Active Mean"], 3_000_000.0)
        self.assertAlmostEqual(f["Active Max"], 4_000_000.0)
        self.assertAlmostEqual(f["Active Min"], 2_000_000.0)
        self.assertAlmostEqual(f["Active Std"], (2.0e12) ** 0.5, places=3)

        self.assertAlmostEqual(f["Idle Mean"], 9_000_000.0)
        self.assertAlmostEqual(f["Idle Max"], 10_000_000.0)
        self.assertAlmostEqual(f["Idle Min"], 8_000_000.0)
        self.assertAlmostEqual(f["Idle Std"], (2.0e12) ** 0.5, places=3)

    def test_microsecond_unit_scaling(self):
        f = self._flow([1000.0, 1001.5, 1008.0])
        self.assertAlmostEqual(f["Active Mean"], 1_500_000.0)
        self.assertAlmostEqual(f["Idle Mean"], 6_500_000.0)

class TestFeatureSanitization(unittest.TestCase):

    def test_nonfinite_feature_raises(self):
        flow = build_sample_flow()
        with mock.patch.object(NetworkFlow, 'flow_bytes_per_second', new_callable=mock.PropertyMock) as prop:
            prop.return_value = float('inf')
            with self.assertRaises(NonFiniteFeatureError) as ctx:
                flow.extract_features()
        self.assertIn(('Flow Bytes/s', float('inf')), ctx.exception.diagnostics)

    def test_feature_diagnostics_lists_offenders(self):
        flow = build_sample_flow()
        with mock.patch.object(NetworkFlow, 'flow_bytes_per_second', new_callable=mock.PropertyMock) as prop:
            prop.return_value = float('inf')
            diags = flow.feature_diagnostics()
            self.assertEqual([name for name, _ in diags], ['Flow Bytes/s'])

    def test_feature_diagnostics_empty_when_finite(self):
        flow = build_sample_flow()
        self.assertEqual(flow.feature_diagnostics(), [])

class TestPacketValidation(unittest.TestCase):

    def test_valid_packet_passes(self):
        FlowExtractor.validate_packet(_make_packet(1.0, 'a', 'b', 1, 2, 100))

    def test_nan_timestamp_rejected(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor().add_packet(_make_packet(float('nan'), 'a', 'b', 1, 2, 100))

    def test_infinite_length_rejected(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor.validate_packet(_make_packet(1.0, 'a', 'b', 1, 2, float('inf')))

    def test_negative_length_rejected(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor.validate_packet(_make_packet(1.0, 'a', 'b', 1, 2, -5))

    def test_negative_payload_rejected(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor.validate_packet(_make_packet(1.0, 'a', 'b', 1, 2, 100, payload_length=-1))

    def test_add_packet_rejects_nan_timestamp(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor().add_packet(_make_packet(float('nan'), 'a', 'b', 1, 2, 100))

    def test_validate_packet_rejects_nonfinite_timestamp(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor.validate_packet(_make_packet(float('inf'), 'a', 'b', 1, 2, 100))

    def test_validate_packet_rejects_nonfinite_payload(self):
        with self.assertRaises(InvalidPacketError):
            FlowExtractor.validate_packet(_make_packet(1.0, 'a', 'b', 1, 2, 100, payload_length=float('nan')))
